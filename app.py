
import os, sqlite3, secrets, hashlib, hmac, time, mimetypes
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

@app.post("/api/orders")
def create_order():
    cleanup_expired()
    name=(request.form.get("name") or "").strip()
    phone=(request.form.get("phone") or "").strip()
    try: quantity=int(request.form.get("quantity","1"))
    except: quantity=0
    proof=request.files.get("proof")
    if not name or len(name)>120: return jsonify(error="Nombre inválido"),400
    if not phone or len(phone)>30: return jsonify(error="Celular inválido"),400
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
        c.execute("INSERT INTO orders(code,name,phone,quantity,total) VALUES(?,?,?,?,?)",(code,name,phone,quantity,quantity*PRICE))
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
