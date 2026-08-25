# Chapa Tu Suerte — plataforma real de tickets

Incluye:
- Frontend de la campaña.
- Compra de 1 a 50 tickets a S/10.
- Pago manual por Yape a los dos números indicados.
- Carga de comprobante (JPG/PNG/WebP, máximo 5 MB).
- Base Firestore permanente para solicitudes y tickets.
- Comprobantes privados en Google Cloud Storage.
- Reserva de números únicos de 6 dígitos.
- Panel `/admin` para aprobar/rechazar comprobantes.
- Al aprobar, los tickets pasan a `CONFIRMADO`.
- Consulta pública de ticket.
- Las reservas pendientes vencen a los 30 minutos.

## Ejecutar localmente

1. Instala Python 3.10+.
2. `python -m venv .venv`
3. Activa el entorno.
4. `pip install -r requirements.txt`
5. Copia `env.example` a `.env` y define una contraseña fuerte.
6. Exporta las variables del `.env` (o usa tu gestor de secretos).
7. `python app.py`
8. Abre `http://localhost:5000`.
9. Administración: `http://localhost:5000/admin`.

## Importante antes de publicar

- Cambia `ADMIN_PASSWORD` y `FLASK_SECRET`.
- Usa HTTPS.
- Usa `COOKIE_SECURE=1`.
- Configura `GOOGLE_APPLICATION_CREDENTIALS` y `GCS_BUCKET_NAME`.
- Mantén el bucket sin acceso público y protege la clave de la cuenta de servicio.
- Verifica y publica las bases, autorizaciones, términos y condiciones del sorteo según la normativa aplicable.
- Este sistema NO confirma automáticamente un pago de Yape: el administrador debe revisar el comprobante y aprobarlo.

## Flujo

Cliente -> crea solicitud + comprobante -> tickets reservados -> administrador revisa -> aprobar -> tickets confirmados.


## WhatsApp de recepción
Las solicitudes generadas desde la web abren WhatsApp al número 905674389 con los datos de la compra. El comprador debe enviar además la captura del pago de Yape a ese mismo número.
