
import os, sqlite3, secrets, hashlib, hmac, time, mimetypes, json, urllib.request, urllib.error
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, make_response, redirect, session

BASE = Path(__file__).resolve().parent
DB = BASE / "data.sqlite3"
UPLOADS = BASE / "uploads"
PUBLIC = BASE / "public"
UPLOADS.mkdir(exist_ok=True)

app = Flask(__name__, static_folder=str(PUBLIC), static_url_path="")
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE_THIS_SECRET_IN_PRODUCTION")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "CAMBIA_ESTA_CLAVE")
MAX_TICKETS = 999999
PRICE = 10
JSONPE_TOKEN = os.environ.get("JSONPE_TOKEN", "").strip()
DNI_CACHE = {}

def db():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    c=db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS orders(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      document_type TEXT,
      document_number TEXT,
      quantity INTEGER NOT NULL CHECK(quantity BETWEEN 1 AND 50),
      total INTEGER NOT NULL,
      proof_path TEXT,
      status TEXT NOT NULL DEFAULT 'pending',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      reviewed_at TEXT,
      review_note TEXT
    );
    CREATE TABLE IF NOT EXISTS tickets(
      number INTEGER PRIMARY KEY,
      order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
      status TEXT NOT NULL DEFAULT 'reserved',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      UNIQUE(number)
    );
    CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status);
    CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at);
    CREATE TABLE IF NOT EXISTS admin_sessions(
      token TEXT PRIMARY KEY,
      created_at INTEGER NOT NULL
    );
    """)
    columns={row["name"] for row in c.execute("PRAGMA table_info(orders)").fetchall()}
    if "document_type" not in columns: c.execute("ALTER TABLE orders ADD COLUMN document_type TEXT")
    if "document_number" not in columns: c.execute("ALTER TABLE orders ADD COLUMN document_number TEXT")
    c.execute("CREATE INDEX IF NOT EXISTS idx_orders_document ON orders(document_type, document_number)")
    c.commit(); c.close()

def cleanup_expired():
    # Pending reservations older than 30 minutes are released.
    c=db()
    c.execute("""
      UPDATE orders SET status='expired', reviewed_at=datetime('now'), review_note='Reserva vencida'
      WHERE status='pending' AND datetime(created_at) < datetime('now','-30 minutes')
    """)
    c.execute("""
      DELETE FROM tickets WHERE order_id IN (SELECT id FROM orders WHERE status='expired')
    """)
    c.commit(); c.close()

def make_code():
    return "CTS-" + secrets.token_hex(4).upper()

def allocate_numbers(c, quantity):
    nums=[]
    # Random 6-digit tickets, uniqueness enforced by the database.
    while len(nums)<quantity:
        n=secrets.randbelow(900000)+100000
        try:
            c.execute("INSERT INTO tickets(number,order_id,status) VALUES(?,?,?)",(n,-1,'temp'))
            c.execute("DELETE FROM tickets WHERE number=?",(n,))
            nums.append(n)
        except sqlite3.IntegrityError:
            pass
    return nums

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token=request.cookies.get("admin_session")
        if not token: return jsonify(error="No autorizado"),401
        c=db()
        row=c.execute("SELECT token FROM admin_sessions WHERE token=? AND created_at>?",(token,int(time.time())-86400)).fetchone()
        c.close()
        if not row: return jsonify(error="No autorizado"),401
        return fn(*args, **kwargs)
    return wrapper

@app.get("/")
def home():
    return send_from_directory(PUBLIC,"index.html")

@app.post("/api/identity/dni")
def identity_dni():
    """Consulta DNI en JSON.pe sin exponer el token al navegador."""
    dni=(request.json or {}).get("dni", "") if request.is_json else (request.form.get("dni") or "")
    dni=str(dni).strip()
    if not dni.isdigit() or len(dni)!=8:
        return jsonify(error="El DNI debe tener 8 dígitos"),400
    if not JSONPE_TOKEN:
        return jsonify(error="La consulta de DNI no está configurada en el servidor"),503

    cached=DNI_CACHE.get(dni)
    if cached:
        return jsonify(success=True, data=cached, cached=True)

    payload=json.dumps({"dni":dni}).encode("utf-8")
    req=urllib.request.Request(
        "https://api.json.pe/api/dni",
        data=payload,
        headers={
            "Authorization": f"Bearer {JSONPE_TOKEN}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw=resp.read().decode("utf-8")
            result=json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            detail=json.loads(e.read().decode("utf-8"))
            message=detail.get("message") or detail.get("error") or "No se pudo consultar el DNI"
        except Exception:
            message="No se pudo consultar el DNI"
        return jsonify(error=message), e.code if 400 <= e.code < 500 else 502
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return jsonify(error="No se pudo conectar con el servicio de consulta de DNI"),502

    if not result.get("success"):
        return jsonify(error=result.get("message") or "No se encontró información para ese DNI"),404

    data=result.get("data") or {}
    nombres=str(data.get("nombres") or "").strip()
    paterno=str(data.get("apellido_paterno") or "").strip()
    materno=str(data.get("apellido_materno") or "").strip()
    nombre_completo=str(data.get("nombre_completo") or " ".join(x for x in [nombres,paterno,materno] if x)).strip()
    if not nombre_completo:
        return jsonify(error="La consulta no devolvió nombres y apellidos"),404

    clean={
        "numero": dni,
        "nombres": nombres,
        "apellido_paterno": paterno,
        "apellido_materno": materno,
        "nombre_completo": nombre_completo,
        "codigo_verificacion": data.get("codigo_verificacion"),
    }
    DNI_CACHE[dni]=clean
    return jsonify(success=True, data=clean, cached=False)


@app.post("/api/orders")
def create_order():
    cleanup_expired()
    name=(request.form.get("name") or "").strip()
    phone=(request.form.get("phone") or "").strip()
    document_type=(request.form.get("document_type") or "").strip().upper()
    document_number=(request.form.get("document_number") or "").strip()
    try: quantity=int(request.form.get("quantity","1"))
    except: quantity=0
    proof=request.files.get("proof")
    if not name or len(name)>120: return jsonify(error="Nombre inválido"),400
    if not phone or len(phone)>30: return jsonify(error="Celular inválido"),400
    if document_type not in {"DNI","CE"}: return jsonify(error="Tipo de documento inválido"),400
    if not document_number.isdigit(): return jsonify(error="Número de documento inválido"),400
    if document_type=="DNI" and len(document_number)!=8: return jsonify(error="El DNI debe tener 8 dígitos"),400
    if document_type=="CE" and not 6<=len(document_number)<=12: return jsonify(error="El Carnet de Extranjería debe tener entre 6 y 12 dígitos"),400
    if quantity<1 or quantity>50: return jsonify(error="Cantidad inválida"),400
    if not proof: return jsonify(error="Falta el comprobante"),400
    if proof.mimetype not in {"image/jpeg","image/png","image/webp"}: return jsonify(error="Formato no permitido"),400
    raw=proof.read()
    if len(raw)>5*1024*1024: return jsonify(error="Comprobante demasiado grande"),400

    c=db()
    try:
        c.execute("BEGIN IMMEDIATE")
        code=make_code()
        while c.execute("SELECT 1 FROM orders WHERE code=?",(code,)).fetchone(): code=make_code()
        c.execute("INSERT INTO orders(code,name,phone,document_type,document_number,quantity,total) VALUES(?,?,?,?,?,?,?)",
                  (code,name,phone,document_type,document_number,quantity,quantity*PRICE))
        oid=c.execute("SELECT last_insert_rowid()").fetchone()[0]

        nums=[]
        while len(nums)<quantity:
            n=secrets.randbelow(900000)+100000
            try:
                c.execute("INSERT INTO tickets(number,order_id,status) VALUES(?,?,?)",(n,oid,'reserved'))
                nums.append(n)
            except sqlite3.IntegrityError:
                continue

        ext={ "image/jpeg":".jpg","image/png":".png","image/webp":".webp"}[proof.mimetype]
        filename=f"{code}{ext}"
        (UPLOADS/filename).write_bytes(raw)
        c.execute("UPDATE orders SET proof_path=? WHERE id=?",(filename,oid))
        c.commit()
    except Exception:
        c.rollback(); c.close()
        return jsonify(error="No se pudo crear la solicitud"),500
    c.close()
    return jsonify(order_code=code,quantity=quantity,total=quantity*PRICE,tickets=nums,status="pending"),201

@app.get("/api/tickets/<number>")
def ticket(number):
    if not number.isdigit() or len(number)!=6: return jsonify(error="Número inválido"),400
    c=db()
    row=c.execute("""SELECT t.number,o.name,t.status,o.status AS order_status
                    FROM tickets t JOIN orders o ON o.id=t.order_id WHERE t.number=?""",(int(number),)).fetchone()
    c.close()
    if not row: return jsonify(error="No encontrado"),404
    status_map={
      ("reserved","pending"):("RESERVADO · PENDIENTE DE PAGO/VALIDACIÓN"),
      ("reserved","expired"):("RESERVA VENCIDA"),
      ("reserved","rejected"):("RECHAZADO"),
      ("confirmed","approved"):("CONFIRMADO"),
    }
    label=status_map.get((row["status"],row["order_status"]),"EN REVISIÓN")
    return jsonify(number=row["number"],name=row["name"],status_label=label)


@app.get("/api/tickets/by-document")
def tickets_by_document():
    document_type=(request.args.get("document_type") or "").strip().upper()
    document_number=(request.args.get("document_number") or "").strip()
    if document_type not in {"DNI","CE"} or not document_number.isdigit():
        return jsonify(error="Documento inválido"),400
    if document_type=="DNI" and len(document_number)!=8:
        return jsonify(error="El DNI debe tener 8 dígitos"),400
    if document_type=="CE" and not 6<=len(document_number)<=12:
        return jsonify(error="El Carnet de Extranjería debe tener entre 6 y 12 dígitos"),400
    cleanup_expired(); c=db()
    rows=c.execute("""SELECT o.id,o.code,o.name,o.document_type,o.document_number,o.quantity,o.total,
                             o.status AS order_status,o.created_at,t.number,t.status AS ticket_status
                      FROM orders o LEFT JOIN tickets t ON t.order_id=o.id
                      WHERE o.document_type=? AND o.document_number=?
                      ORDER BY o.id DESC,t.number ASC""",(document_type,document_number)).fetchall()
    c.close()
    if not rows: return jsonify(error="No se encontraron tickets para ese documento"),404
    orders={}
    labels={"pending":"PENDIENTE DE VALIDACIÓN","approved":"CONFIRMADO","rejected":"RECHAZADO","expired":"RESERVA VENCIDA"}
    for r in rows:
        orders.setdefault(r["id"],{"order_code":r["code"],"name":r["name"],"document_type":r["document_type"],
          "document_number":r["document_number"],"quantity":r["quantity"],"total":r["total"],
          "status":r["order_status"],"status_label":labels.get(r["order_status"],"EN REVISIÓN"),
          "created_at":r["created_at"],"tickets":[]})
        if r["number"] is not None:
            orders[r["id"]]["tickets"].append({"number":r["number"],"status":r["ticket_status"]})
    result=list(orders.values())
    return jsonify(document_type=document_type,document_number=document_number,total_orders=len(result),
                   total_tickets=sum(len(x["tickets"]) for x in result),orders=result)

@app.post("/admin/login")
def login():
    data=request.form or request.json or {}
    if data.get("username")!=ADMIN_USER or not hmac.compare_digest(str(data.get("password","")),ADMIN_PASSWORD):
        return jsonify(error="Credenciales incorrectas"),401
    token=secrets.token_urlsafe(32)
    c=db(); c.execute("INSERT INTO admin_sessions(token,created_at) VALUES(?,?)",(token,int(time.time()))); c.commit(); c.close()
    r=jsonify(ok=True); r.set_cookie("admin_session",token,httponly=True,samesite="Lax",secure=bool(os.environ.get("COOKIE_SECURE")),max_age=86400)
    return r

@app.post("/admin/logout")
def logout():
    token=request.cookies.get("admin_session")
    if token:
        c=db(); c.execute("DELETE FROM admin_sessions WHERE token=?",(token,)); c.commit(); c.close()
    r=jsonify(ok=True); r.delete_cookie("admin_session"); return r

@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    cleanup_expired()
    status=request.args.get("status","all")
    c=db()
    q="""SELECT id,code,name,phone,quantity,total,status,proof_path,created_at,reviewed_at,review_note
         FROM orders"""
    args=[]
    if status!="all":
        q+=" WHERE status=?"; args.append(status)
    q+=" ORDER BY id DESC LIMIT 200"
    rows=[dict(x) for x in c.execute(q,args).fetchall()]
    for r in rows:
        r["tickets"]=[x["number"] for x in c.execute("SELECT number FROM tickets WHERE order_id=? ORDER BY number",(r["id"],)).fetchall()]
        r["proof_url"]="/admin/proof/"+r["proof_path"] if r["proof_path"] else None
    c.close()
    return jsonify(orders=rows)

@app.get("/admin/proof/<filename>")
@admin_required
def proof(filename):
    # filename comes from our own generated code, not arbitrary user input.
    if Path(filename).name != filename: return "bad",400
    return send_from_directory(UPLOADS,filename)

@app.post("/api/admin/orders/<int:oid>/approve")
@admin_required
def approve(oid):
    c=db(); row=c.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()
    if not row: c.close(); return jsonify(error="No encontrado"),404
    if row["status"]!="pending": c.close(); return jsonify(error="La solicitud ya fue procesada"),400
    c.execute("UPDATE orders SET status='approved',reviewed_at=datetime('now'),review_note=? WHERE id=?",((request.json or {}).get("note","Pago validado"),oid))
    c.execute("UPDATE tickets SET status='confirmed' WHERE order_id=?",(oid,))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.post("/api/admin/orders/<int:oid>/reject")
@admin_required
def reject(oid):
    c=db(); row=c.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()
    if not row: c.close(); return jsonify(error="No encontrado"),404
    if row["status"]!="pending": c.close(); return jsonify(error="La solicitud ya fue procesada"),400
    c.execute("UPDATE orders SET status='rejected',reviewed_at=datetime('now'),review_note=? WHERE id=?",((request.json or {}).get("note","Pago rechazado"),oid))
    c.execute("DELETE FROM tickets WHERE order_id=?",(oid,))
    c.commit(); c.close()
    return jsonify(ok=True)

@app.get("/api/admin/stats")
@admin_required
def stats():
    c=db()
    out={}
    for s in ("pending","approved","rejected","expired"):
        out[s]=c.execute("SELECT COUNT(*) FROM orders WHERE status=?",(s,)).fetchone()[0]
    out["confirmed_tickets"]=c.execute("SELECT COUNT(*) FROM tickets WHERE status='confirmed'").fetchone()[0]
    out["reserved_tickets"]=c.execute("SELECT COUNT(*) FROM tickets WHERE status='reserved'").fetchone()[0]
    out["sales_approved"]=c.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE status='approved'").fetchone()[0]
    c.close(); return jsonify(out)

@app.get("/admin")
def admin_page():
    return send_from_directory(BASE,"admin.html")

init_db()

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
