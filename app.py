
import os, secrets, hmac, time, mimetypes, json, urllib.request, urllib.error, re, unicodedata
from io import BytesIO
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, make_response, redirect, session, send_file
from google.cloud import storage
from google.cloud import firestore

BASE = Path(__file__).resolve().parent
PUBLIC = BASE / "public"

app = Flask(__name__, static_folder=str(PUBLIC), static_url_path="")
app.secret_key = os.environ.get("FLASK_SECRET", "CHANGE_THIS_SECRET_IN_PRODUCTION")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "CAMBIA_ESTA_CLAVE")
MAX_TICKETS = 999999
PRICE = 10
JSONPE_TOKEN = os.environ.get("JSONPE_TOKEN", "").strip()
GCS_BUCKET_NAME = os.environ.get("GCS_BUCKET_NAME", "").strip()
DNI_CACHE = {}
DNI_CACHE_SECONDS = 90*24*60*60
_FIRESTORE_DB = None
_ADMIN_SESSION_CACHE = {}
_LAST_EXPIRED_CLEANUP = 0

def firestore_db():
    global _FIRESTORE_DB
    if _FIRESTORE_DB is None:
        _FIRESTORE_DB = firestore.Client(database="(default)")
    return _FIRESTORE_DB

def storage_bucket():
    if not GCS_BUCKET_NAME:
        raise RuntimeError("GCS_BUCKET_NAME no está configurado")
    return storage.Client().bucket(GCS_BUCKET_NAME)

def safe_filename_part(value):
    value=unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    value=re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").upper()
    return value[:60] or "SIN_NOMBRE"

def lima_datetime_text(timestamp):
    """Convierte un timestamp UTC a la fecha y hora administrativa de Perú."""
    if not timestamp:
        return ""
    return datetime.fromtimestamp(int(timestamp),timezone.utc).astimezone(
        ZoneInfo("America/Lima")
    ).strftime("%Y-%m-%d %H:%M:%S")

def cleanup_expired():
    """Libera reservas pendientes con más de 30 minutos."""
    global _LAST_EXPIRED_CLEANUP
    now=int(time.time())
    # Evita repetir la misma consulta de mantenimiento en cada carga del panel.
    if now-_LAST_EXPIRED_CLEANUP < 60:
        return
    _LAST_EXPIRED_CLEANUP=now
    cutoff=now-1800
    pending=firestore_db().collection("orders").where("status", "==", "pending").limit(200).stream()
    for snapshot in pending:
        order=snapshot.to_dict()
        if int(order.get("created_at", now)) >= cutoff:
            continue
        batch=firestore_db().batch()
        batch.update(snapshot.reference, {
            "status":"expired", "reviewed_at":now,
            "reviewed_at_text":time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now)),
            "review_note":"Reserva vencida", "released_tickets":order.get("tickets",[]), "tickets":[],
        })
        for number in order.get("tickets", []):
            batch.delete(firestore_db().collection("tickets").document(str(number)))
        batch.commit()

def make_code():
    return "CTS-" + secrets.token_hex(4).upper()

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token=request.cookies.get("admin_session")
        if not token: return jsonify(error="No autorizado"),401
        now=int(time.time())
        cached_until=_ADMIN_SESSION_CACHE.get(token,0)
        if cached_until <= now:
            snapshot=firestore_db().collection("admin_sessions").document(token).get()
            if not snapshot.exists or int((snapshot.to_dict() or {}).get("created_at",0)) <= now-86400:
                _ADMIN_SESSION_CACHE.pop(token,None)
                return jsonify(error="No autorizado"),401
            # La cookie sigue siendo la autoridad; este caché solo ahorra lecturas
            # repetidas durante cinco minutos dentro de la misma instancia.
            _ADMIN_SESSION_CACHE[token]=now+300
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
        return jsonify(success=True, data=cached, cached=True, cache_source="memory")

    # Caché permanente: sobrevive a suspensiones, reinicios y despliegues de Render.
    now=int(time.time())
    cache_ref=firestore_db().collection("dni_cache").document(dni)
    try:
        cache_snapshot=cache_ref.get()
        if cache_snapshot.exists:
            saved=cache_snapshot.to_dict() or {}
            if (int(saved.get("updated_at",0)) >= now-DNI_CACHE_SECONDS
                    and str(saved.get("nombre_completo") or "").strip()):
                clean={key:saved.get(key) for key in (
                    "numero","nombres","apellido_paterno","apellido_materno",
                    "nombre_completo","codigo_verificacion"
                )}
                clean["numero"]=dni
                DNI_CACHE[dni]=clean
                return jsonify(success=True,data=clean,cached=True,cache_source="firestore")
    except Exception:
        # Si el caché no está disponible, la validación oficial todavía puede continuar.
        pass

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
    try:
        cache_ref.set({**clean,"updated_at":now})
    except Exception:
        # No se invalida una consulta oficial exitosa por un fallo al guardar el caché.
        pass
    return jsonify(success=True, data=clean, cached=False, cache_source="jsonpe")


@app.post("/api/orders")
def create_order():
    cleanup_expired()
    name=(request.form.get("name") or "").strip()
    phone=re.sub(r"\D", "", request.form.get("phone") or "")
    document_type=(request.form.get("document_type") or "").strip().upper()
    document_number=(request.form.get("document_number") or "").strip()
    try: quantity=int(request.form.get("quantity","1"))
    except: quantity=0
    proof=request.files.get("proof")
    if not name or len(name)>120: return jsonify(error="Nombre inválido"),400
    if not re.fullmatch(r"9\d{8}", phone):
        return jsonify(error="Número de WhatsApp inválido"),400
    if document_type not in {"DNI","CE"}: return jsonify(error="Tipo de documento inválido"),400
    if not document_number.isdigit(): return jsonify(error="Número de documento inválido"),400
    if document_type=="DNI" and len(document_number)!=8: return jsonify(error="El DNI debe tener 8 dígitos"),400
    if document_type=="CE" and not 6<=len(document_number)<=12: return jsonify(error="El Carnet de Extranjería debe tener entre 6 y 12 dígitos"),400
    if quantity<1 or quantity>50: return jsonify(error="Cantidad inválida"),400
    if not proof: return jsonify(error="Falta el comprobante"),400
    if proof.mimetype not in {"image/jpeg","image/png","image/webp"}: return jsonify(error="Formato no permitido"),400
    raw=proof.read()
    if len(raw)>5*1024*1024: return jsonify(error="Comprobante demasiado grande"),400

    code=make_code()
    oid=str(int(time.time()*1000)*100+secrets.randbelow(100))
    now=int(time.time())
    created_at_text=time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(now))
    orders=firestore_db().collection("orders")
    tickets=firestore_db().collection("tickets")
    nums=[]
    try:
        # Reserva todos los números y crea la solicitud en una sola transacción.
        for _ in range(12):
            candidates=[]
            while len(candidates)<quantity:
                n=secrets.randbelow(900000)+100000
                if n not in candidates: candidates.append(n)

            transaction=firestore_db().transaction()
            @firestore.transactional
            def reserve(transaction):
                refs=[tickets.document(str(n)) for n in candidates]
                snapshots=[ref.get(transaction=transaction) for ref in refs]
                if any(snapshot.exists for snapshot in snapshots):
                    return False
                transaction.set(orders.document(oid), {
                    "id":oid, "code":code, "name":name, "phone":phone,
                    "document_type":document_type, "document_number":document_number,
                    "quantity":quantity, "total":quantity*PRICE,
                    "proof_path":None, "status":"pending", "tickets":candidates,
                    "created_at":now, "created_at_text":created_at_text,
                    "reviewed_at":None, "reviewed_at_text":None, "review_note":None,
                })
                for ref,n in zip(refs,candidates):
                    transaction.set(ref, {
                        "number":n, "order_id":oid, "order_code":code,
                        "status":"reserved", "created_at":now,
                    })
                return True
            if reserve(transaction):
                nums=candidates
                break
        if not nums:
            raise RuntimeError("No se pudieron reservar números únicos")

        ext={ "image/jpeg":".jpg","image/png":".png","image/webp":".webp"}[proof.mimetype]
        timestamp=time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        filename=(f"{document_type}_{document_number}_{safe_filename_part(name)}_"
                  f"{timestamp}_{code}{ext}")
        blob=storage_bucket().blob(filename)
        blob.upload_from_string(raw, content_type=proof.mimetype)
        orders.document(oid).update({"proof_path":filename})
    except Exception:
        # Si falla la imagen, libera la reserva para no dejar tickets bloqueados.
        if nums:
            batch=firestore_db().batch()
            batch.delete(orders.document(oid))
            for number in nums:
                batch.delete(tickets.document(str(number)))
            batch.commit()
        return jsonify(error="No se pudo crear la solicitud"),500
    return jsonify(order_code=code,quantity=quantity,total=quantity*PRICE,tickets=nums,status="pending"),201

@app.get("/api/tickets/<number>")
def ticket(number):
    if not number.isdigit() or len(number)!=6: return jsonify(error="Número inválido"),400
    ticket_snapshot=firestore_db().collection("tickets").document(number).get()
    if not ticket_snapshot.exists: return jsonify(error="No encontrado"),404
    ticket_data=ticket_snapshot.to_dict()
    order_snapshot=firestore_db().collection("orders").document(ticket_data["order_id"]).get()
    if not order_snapshot.exists: return jsonify(error="No encontrado"),404
    order=order_snapshot.to_dict()
    status_map={
      ("reserved","pending"):("RESERVADO · PENDIENTE DE PAGO/VALIDACIÓN"),
      ("reserved","expired"):("RESERVA VENCIDA"),
      ("reserved","rejected"):("RECHAZADO"),
      ("confirmed","approved"):("CONFIRMADO"),
    }
    label=status_map.get((ticket_data["status"],order["status"]),"EN REVISIÓN")
    return jsonify(number=ticket_data["number"],name=order["name"],status_label=label)


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
    cleanup_expired()
    snapshots=firestore_db().collection("orders").where("document_number", "==", document_number).limit(200).stream()
    orders=[snapshot.to_dict() for snapshot in snapshots]
    orders=[o for o in orders if o.get("document_type")==document_type]
    if not orders: return jsonify(error="No se encontraron tickets para ese documento"),404
    labels={"pending":"PENDIENTE DE VALIDACIÓN","approved":"CONFIRMADO","rejected":"RECHAZADO","expired":"RESERVA VENCIDA"}
    orders.sort(key=lambda o:int(o.get("created_at",0)), reverse=True)
    result=[]
    for order in orders:
        ticket_status="confirmed" if order.get("status")=="approved" else "reserved"
        result.append({
            "order_code":order["code"], "name":order["name"],
            "document_type":order["document_type"], "document_number":order["document_number"],
            "quantity":order["quantity"], "total":order["total"],
            "status":order["status"], "status_label":labels.get(order["status"],"EN REVISIÓN"),
            "created_at":order.get("created_at_text",""),
            "tickets":[{"number":n,"status":ticket_status} for n in sorted(order.get("tickets",[]))]
        })
    return jsonify(document_type=document_type,document_number=document_number,total_orders=len(result),
                   total_tickets=sum(len(x["tickets"]) for x in result),orders=result)

@app.post("/admin/login")
def login():
    data=request.form or request.json or {}
    if data.get("username")!=ADMIN_USER or not hmac.compare_digest(str(data.get("password","")),ADMIN_PASSWORD):
        return jsonify(error="Credenciales incorrectas"),401
    token=secrets.token_urlsafe(32)
    firestore_db().collection("admin_sessions").document(token).set({"created_at":int(time.time())})
    _ADMIN_SESSION_CACHE[token]=int(time.time())+300
    r=jsonify(ok=True); r.set_cookie("admin_session",token,httponly=True,samesite="Lax",secure=bool(os.environ.get("COOKIE_SECURE")),max_age=86400)
    return r

@app.post("/admin/logout")
def logout():
    token=request.cookies.get("admin_session")
    if token:
        _ADMIN_SESSION_CACHE.pop(token,None)
        firestore_db().collection("admin_sessions").document(token).delete()
    r=jsonify(ok=True); r.delete_cookie("admin_session"); return r

@app.get("/api/admin/orders")
@admin_required
def admin_orders():
    cleanup_expired()
    status=request.args.get("status","all")
    query=firestore_db().collection("orders")
    if status!="all": query=query.where("status", "==", status)
    rows=[snapshot.to_dict() for snapshot in query.limit(200).stream()]
    rows.sort(key=lambda row:int(row.get("created_at",0)), reverse=True)
    for row in rows:
        row["created_at"]=lima_datetime_text(row.get("created_at")) or row.get("created_at_text","")
        row["tickets"]=sorted(row.get("tickets",[]) or row.get("released_tickets",[]))
        row["proof_url"]="/admin/proof/"+row["proof_path"] if row.get("proof_path") else None
    return jsonify(orders=rows)

@app.get("/api/admin/export.xlsx")
@admin_required
def export_admin_excel():
    # Estas librerías son pesadas; se cargan solo cuando se descarga el Excel,
    # no durante el arranque normal de la web ni del panel.
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
    rows=[snapshot.to_dict() for snapshot in firestore_db().collection("orders").stream()]
    rows.sort(key=lambda row:int(row.get("created_at",0)), reverse=True)
    status_labels={"pending":"Pendiente","approved":"Aprobada","rejected":"Rechazada","expired":"Vencida"}
    lima=ZoneInfo("America/Lima")

    def local_datetime(timestamp):
        if not timestamp: return None
        return datetime.fromtimestamp(int(timestamp),timezone.utc).astimezone(lima).replace(tzinfo=None)

    def safe_excel_text(value):
        text=str(value or "")
        return "'"+text if text.startswith(("=","+","-","@")) else text

    workbook=Workbook()
    summary=workbook.active
    summary.title="Resumen"
    detail=workbook.create_sheet("Participantes y pagos")
    yellow="FFD400"; dark="111117"; white="FFFFFF"; light="F2F2F2"
    thin=Side(style="thin",color="D9D9D9")
    summary.sheet_view.showGridLines=False
    detail.sheet_view.showGridLines=False

    approved=[row for row in rows if row.get("status")=="approved"]
    pending=[row for row in rows if row.get("status")=="pending"]
    rejected=[row for row in rows if row.get("status")=="rejected"]
    expired=[row for row in rows if row.get("status")=="expired"]
    confirmed_tickets=sum(int(row.get("quantity",0)) for row in approved)
    approved_sales=sum(int(row.get("total",0)) for row in approved)
    reactivated=sum(bool(row.get("reactivated_from_expired")) for row in rows)

    summary.merge_cells("A1:H2")
    summary["A1"]="CHAPA TU SUERTE — REPORTE ADMINISTRATIVO"
    summary["A1"].font=Font(name="Calibri",bold=True,size=20,color=white)
    summary["A1"].fill=PatternFill("solid",fgColor=dark)
    summary["A1"].alignment=Alignment(horizontal="center",vertical="center")
    summary.merge_cells("A3:H3")
    summary["A3"]="Generado el "+datetime.now(lima).strftime("%d/%m/%Y %H:%M")+" · Hora de Perú"
    summary["A3"].font=Font(italic=True,color="D1D5DB")
    summary["A3"].fill=PatternFill("solid",fgColor="24242D")
    summary["A3"].alignment=Alignment(horizontal="center")

    top_labels=["TOTAL SOLICITUDES","PENDIENTES","APROBADAS","RECHAZADAS"]
    top_values=[len(rows),len(pending),len(approved),len(rejected)]
    bottom_labels=["VENTAS APROBADAS","TICKETS CONFIRMADOS","VENCIDAS","REACTIVADAS"]
    bottom_values=[approved_sales,confirmed_tickets,len(expired),reactivated]
    for column,(label,value) in enumerate(zip(top_labels,top_values),1):
        summary.cell(5,column,label); summary.cell(6,column,value)
    for column,(label,value) in enumerate(zip(bottom_labels,bottom_values),1):
        summary.cell(8,column,label); summary.cell(9,column,value)
    for row_number in (5,8):
        for cell in summary[row_number][:4]:
            cell.font=Font(bold=True,color=white,size=11)
            cell.fill=PatternFill("solid",fgColor="24242D")
            cell.alignment=Alignment(horizontal="center",vertical="center",wrap_text=True)
    for row_number in (6,9):
        for cell in summary[row_number][:4]:
            cell.font=Font(bold=True,color=dark,size=22)
            cell.fill=PatternFill("solid",fgColor=light)
            cell.alignment=Alignment(horizontal="center",vertical="center")
            cell.border=Border(bottom=thin)
    summary["A9"].number_format='"S/" #,##0'
    summary.row_dimensions[5].height=26; summary.row_dimensions[6].height=46
    summary.row_dimensions[8].height=26; summary.row_dimensions[9].height=46

    summary.append([])
    status_summary=[
        ["ESTADO","SOLICITUDES","TICKETS","VENTAS (S/)"],
        ["Aprobada",len(approved),confirmed_tickets,approved_sales],
        ["Pendiente",len(pending),sum(int(row.get("quantity",0)) for row in pending),sum(int(row.get("total",0)) for row in pending)],
        ["Rechazada",len(rejected),sum(int(row.get("quantity",0)) for row in rejected),sum(int(row.get("total",0)) for row in rejected)],
        ["Vencida",len(expired),sum(int(row.get("quantity",0)) for row in expired),sum(int(row.get("total",0)) for row in expired)],
    ]
    for row_index,row_values in enumerate(status_summary,11):
        for column,value in enumerate(row_values,1): summary.cell(row_index,column,value)
    for cell in summary[11][:4]:
        cell.font=Font(bold=True,color=dark); cell.fill=PatternFill("solid",fgColor=yellow)
        cell.alignment=Alignment(horizontal="center")
    for row_number in range(12,16):
        summary.cell(row_number,1).font=Font(bold=True,color="1F2937")
        summary.cell(row_number,4).number_format='"S/" #,##0'
        for cell in summary[row_number][:4]: cell.border=Border(bottom=thin)
    summary.merge_cells("A17:H17")
    summary["A17"]="La hoja ‘Participantes y pagos’ contiene el detalle completo y permite filtrar los registros."
    summary["A17"].font=Font(italic=True,color="594A00")
    summary["A17"].fill=PatternFill("solid",fgColor="FFF7CC")
    summary["A17"].alignment=Alignment(horizontal="center",vertical="center",wrap_text=True)
    for column in "ABCD": summary.column_dimensions[column].width=23
    for column in "EFGH": summary.column_dimensions[column].width=4
    summary.freeze_panes="A4"

    headers=["Código de solicitud","Nombre completo","Número de WhatsApp","Tipo de documento",
             "Número de documento","Cantidad","Total (S/)","Estado","Tickets confirmados/asignados",
             "Tickets originales/liberados","Fecha de registro","Fecha de revisión","Observación",
             "Reactivada desde vencida"]
    detail.append(headers)
    for row in rows:
        current_tickets=row.get("tickets",[]) or []
        historical=row.get("original_tickets",[]) or row.get("released_tickets",[]) or current_tickets
        detail.append([
            safe_excel_text(row.get("code")),safe_excel_text(row.get("name")),safe_excel_text(row.get("phone")),
            safe_excel_text(row.get("document_type")),safe_excel_text(row.get("document_number")),
            int(row.get("quantity",0)),int(row.get("total",0)),status_labels.get(row.get("status"),row.get("status","")),
            ", ".join(str(number) for number in current_tickets),
            ", ".join(str(number) for number in historical),
            local_datetime(row.get("created_at")),local_datetime(row.get("reviewed_at")),
            safe_excel_text(row.get("review_note")),"Sí" if row.get("reactivated_from_expired") else "No",
        ])

    for cell in detail[1]:
        cell.font=Font(bold=True,color=white)
        cell.fill=PatternFill("solid",fgColor=dark)
        cell.alignment=Alignment(horizontal="center",vertical="center",wrap_text=True)
        cell.border=Border(bottom=thin)
    for row in detail.iter_rows(min_row=2):
        status=row[7].value
        for cell in row:
            cell.alignment=Alignment(vertical="top",wrap_text=True)
            cell.border=Border(bottom=thin)
        if row[0].row%2==0:
            for cell in row: cell.fill=PatternFill("solid",fgColor="F8FAFC")
        status_colors={"Aprobada":("DCFCE7","166534"),"Pendiente":("FEF3C7","92400E"),
                       "Rechazada":("FEE2E2","991B1B"),"Vencida":("E5E7EB","374151")}
        if status in status_colors:
            fill_color,font_color=status_colors[status]
            row[7].fill=PatternFill("solid",fgColor=fill_color)
            row[7].font=Font(bold=True,color=font_color)
        row[6].number_format='"S/" #,##0'
        row[10].number_format='dd/mm/yyyy hh:mm'
        row[11].number_format='dd/mm/yyyy hh:mm'
    widths=[20,32,20,18,20,12,14,16,30,30,21,21,48,23]
    for index,width in enumerate(widths,1):
        detail.column_dimensions[chr(64+index)].width=width
    detail.freeze_panes="A2"
    detail.auto_filter.ref=f"A1:N{max(detail.max_row,1)}"

    output=BytesIO()
    workbook.save(output)
    output.seek(0)
    filename="chapa-tu-suerte-participantes-"+datetime.now(lima).strftime("%Y%m%d-%H%M")+".xlsx"
    return send_file(output,as_attachment=True,download_name=filename,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")

@app.get("/admin/proof/<filename>")
@admin_required
def proof(filename):
    # filename comes from our own generated code, not arbitrary user input.
    if Path(filename).name != filename: return "bad",400
    try:
        blob=storage_bucket().blob(filename)
        raw=blob.download_as_bytes()
        response=make_response(raw)
        response.headers["Content-Type"]=blob.content_type or mimetypes.guess_type(filename)[0] or "application/octet-stream"
        # Permite que el navegador reutilice el comprobante durante la sesión.
        response.headers["Cache-Control"]="private, max-age=300"
        return response
    except Exception:
        return "No se pudo cargar el comprobante",404

@app.post("/api/admin/orders/<oid>/approve")
@admin_required
def approve(oid):
    ref=firestore_db().collection("orders").document(oid)
    snapshot=ref.get()
    if not snapshot.exists: return jsonify(error="No encontrado"),404
    order=snapshot.to_dict()
    if order["status"] not in {"pending","expired"}:
        return jsonify(error="La solicitud ya fue procesada"),400
    now=int(time.time())
    reviewed_at_text=time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(now))
    requested_note=(request.json or {}).get("note") or "Pago validado"

    if order["status"]=="pending":
        batch=firestore_db().batch()
        batch.update(ref, {"status":"approved", "reviewed_at":now,
                           "reviewed_at_text":reviewed_at_text,
                           "review_note":requested_note})
        for number in order.get("tickets",[]):
            batch.update(firestore_db().collection("tickets").document(str(number)), {"status":"confirmed"})
        batch.commit()
        return jsonify(ok=True,message="Pago aprobado y tickets confirmados",tickets=order.get("tickets",[]))

    # Una reserva vencida ya liberó sus números. Recuperamos los disponibles
    # y reemplazamos únicamente los que hayan sido asignados a otra compra.
    original=[int(number) for number in order.get("released_tickets",[]) or order.get("tickets",[])]
    quantity=int(order.get("quantity",len(original)))
    tickets_collection=firestore_db().collection("tickets")
    for _ in range(12):
        replacement_pool=[]
        while len(replacement_pool)<max(quantity*3,20):
            number=secrets.randbelow(900000)+100000
            if number not in original and number not in replacement_pool:
                replacement_pool.append(number)

        transaction=firestore_db().transaction()
        @firestore.transactional
        def restore_expired(transaction):
            current=ref.get(transaction=transaction)
            if not current.exists or current.to_dict().get("status")!="expired":
                return None
            candidates=original+replacement_pool
            candidate_refs=[tickets_collection.document(str(number)) for number in candidates]
            candidate_snapshots=[ticket_ref.get(transaction=transaction) for ticket_ref in candidate_refs]
            available={number for number,ticket_snapshot in zip(candidates,candidate_snapshots)
                       if not ticket_snapshot.exists}
            selected=[number for number in original if number in available]
            selected.extend(number for number in replacement_pool
                            if number in available and len(selected)<quantity)
            if len(selected)<quantity:
                return False
            selected=selected[:quantity]
            replaced=[number for number in original if number not in selected]
            replacements=[number for number in selected if number not in original]
            history_note=requested_note
            if replacements:
                history_note+=(". Reserva vencida reactivada; números reemplazados: "
                               +", ".join(str(number) for number in replaced)
                               +" por "+", ".join(str(number) for number in replacements))
            else:
                history_note+=". Reserva vencida reactivada con sus números originales"
            transaction.update(ref,{"status":"approved", "tickets":selected,
                                    "reviewed_at":now, "reviewed_at_text":reviewed_at_text,
                                    "review_note":history_note,
                                    "reactivated_from_expired":True,
                                    "original_tickets":original})
            for number in selected:
                transaction.set(tickets_collection.document(str(number)),{
                    "number":number, "order_id":oid, "order_code":order.get("code"),
                    "status":"confirmed", "created_at":now,
                })
            return {"tickets":selected,"replaced":replaced,"replacements":replacements}

        result=restore_expired(transaction)
        if result is None:
            return jsonify(error="La solicitud ya fue procesada"),400
        if result:
            message="Pago vencido aprobado con los números originales"
            if result["replacements"]:
                message="Pago vencido aprobado; se asignaron números de reemplazo"
            return jsonify(ok=True,message=message,**result)
    return jsonify(error="No se pudieron reservar números disponibles. Intenta nuevamente"),409

@app.post("/api/admin/orders/<oid>/reject")
@admin_required
def reject(oid):
    ref=firestore_db().collection("orders").document(oid)
    snapshot=ref.get()
    if not snapshot.exists: return jsonify(error="No encontrado"),404
    order=snapshot.to_dict()
    if order["status"]!="pending": return jsonify(error="La solicitud ya fue procesada"),400
    now=int(time.time())
    batch=firestore_db().batch()
    batch.update(ref, {"status":"rejected", "reviewed_at":now,
                       "reviewed_at_text":time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(now)),
                       "review_note":(request.json or {}).get("note") or "Pago rechazado",
                       "released_tickets":order.get("tickets",[]), "tickets":[]})
    for number in order.get("tickets",[]):
        batch.delete(firestore_db().collection("tickets").document(str(number)))
    batch.commit()
    return jsonify(ok=True)

@app.get("/api/admin/stats")
@admin_required
def stats():
    rows=[snapshot.to_dict() for snapshot in firestore_db().collection("orders").stream()]
    out={status:sum(1 for row in rows if row.get("status")==status)
         for status in ("pending","approved","rejected","expired")}
    approved=[row for row in rows if row.get("status")=="approved"]
    pending=[row for row in rows if row.get("status")=="pending"]
    out["confirmed_tickets"]=sum(int(row.get("quantity",0)) for row in approved)
    out["reserved_tickets"]=sum(int(row.get("quantity",0)) for row in pending)
    out["sales_approved"]=sum(int(row.get("total",0)) for row in approved)
    return jsonify(out)

@app.get("/admin")
def admin_page():
    return send_from_directory(BASE,"admin.html")

if __name__=="__main__":
    app.run(host="0.0.0.0",port=int(os.environ.get("PORT",5000)),debug=False)
