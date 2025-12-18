from flask import Flask, request, jsonify, g
from functools import wraps
from dotenv import load_dotenv
from supabase import create_client, Client
from flask_cors import CORS
import os

# --------------------------------------------------
# Configuración
# --------------------------------------------------
load_dotenv()
app = Flask(__name__)
CORS(app)

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
supabase_admin: Client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

# --------------------------------------------------
# Helpers
# --------------------------------------------------
def api_response(success=True, data=None, error=None, meta=None, status=200):
    response = {
        "success": success,
        "data": data,
        "error": error
    }

    if meta is not None:
        response["meta"] = meta

    return jsonify(response), status

# --------------------------------------------------
# Middleware JWT
# --------------------------------------------------
def authenticate_user(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization")

        if not auth or not auth.startswith("Bearer "):
            return api_response(False, error="Token no proporcionado", status=401)

        token = auth.split(" ")[1]

        try:
            user = supabase_admin.auth.get_user(token).user
            g.user_id = user.id
            g.user_email = user.email
        except Exception:
            return api_response(False, error="Token inválido o expirado", status=401)

        return f(*args, **kwargs)
    return wrapper


# --------------------------------------------------
# Health Check
# --------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return api_response(True, data={"status": "ok"})


# --------------------------------------------------
# Auth
# --------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return api_response(False, error="Email y password requeridos", status=400)

    try:
        supabase.auth.sign_up({
            "email": email,
            "password": password
        })
        return api_response(True, data="Usuario registrado")
    except Exception as e:
        return api_response(False, error=str(e), status=400)


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    try:
        res = supabase.auth.sign_in_with_password({
            "email": data.get("email"),
            "password": data.get("password")
        })

        return api_response(True, data={
            "access_token": res.session.access_token,
            "expires_in": res.session.expires_in
        })
    except Exception:
        return api_response(False, error="Credenciales inválidas", status=401)


# --------------------------------------------------
# Mensajes
# --------------------------------------------------
@app.route("/api/messages", methods=["POST"])
@authenticate_user
def send_message():
    data = request.get_json() or {}

    for field in ["to", "subject", "body"]:
        if not data.get(field):
            return api_response(False, error=f"Campo requerido: {field}", status=400)

    users = supabase_admin.auth.admin.list_users()
    recipient = next(
        (u for u in users if u.email.lower() == data["to"].lower()),
        None
    )

    if not recipient:
        return api_response(False, error="Destinatario no existe", status=404)

    res = supabase.table("messages").insert({
        "from_user_id": g.user_id,
        "to_user_id": recipient.id,
        "subject": data["subject"],
        "body": data["body"],
        "attachments": data.get("attachments", []),
        "is_read": False,
        "in_trash_from": False,
        "in_trash_to": False
    }).execute()

    return api_response(True, data={"id": res.data[0]["id"]}, status=201)
#obtine la bandeja de entrada



@app.route("/api/messages", methods=["GET"])
@authenticate_user
def list_messages():
    box = request.args.get("box")
    user_id = g.user_id

    page = int(request.args.get("page", 1))
    limit = int(request.args.get("limit", 20))
    offset = (page - 1) * limit
    search = request.args.get("search")

    # =========================
    # QUERY BASE (DATA)
    # =========================
    data_query = supabase.table("messages").select("*")

    # =========================
    # QUERY BASE (COUNT)
    # =========================
    count_query = supabase.table("messages").select("id", count="exact")

    if box == "inbox":
        data_query = (
            data_query
            .eq("to_user_id", user_id)
            .eq("in_trash_to", False)
        )
        count_query = (
            count_query
            .eq("to_user_id", user_id)
            .eq("in_trash_to", False)
        )

    elif box == "sent":
        data_query = (
            data_query
            .eq("from_user_id", user_id)
            .eq("in_trash_from", False)
        )
        count_query = (
            count_query
            .eq("from_user_id", user_id)
            .eq("in_trash_from", False)
        )

    elif box == "trash":
        or_filter = (
            f"and(to_user_id.eq.{user_id},in_trash_to.eq.true),"
            f"and(from_user_id.eq.{user_id},in_trash_from.eq.true)"
        )
        data_query = data_query.or_(or_filter)
        count_query = count_query.or_(or_filter)

    else:
        return api_response(False, error="Box inválido", status=400)

    # 🔍 BUSCADOR
    if search and search.strip():
        data_query = data_query.ilike("subject", f"%{search.strip()}%")
        count_query = count_query.ilike("subject", f"%{search.strip()}%")

    # =========================
    # EJECUCIÓN
    # =========================
    data_res = (
        data_query
        .order("created_at", desc=True)
        .range(offset, offset + limit - 1)
        .execute()
    )

    count_res = count_query.execute()

    total = count_res.count or 0
    total_pages = (total + limit - 1) // limit

    return jsonify({
        "success": True,
        "data": data_res.data,
        "meta": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": total_pages
        }
    }), 200



#abre los mensajes 
# Marcar como leido un mensaje enviado
@app.route("/api/messages/<message_id>", methods=["GET"])
@authenticate_user
def get_message(message_id):
    res = supabase.table("messages").select("*").eq("id", message_id).execute()

    if not res.data:
        return api_response(False, error="Mensaje no encontrado", status=404)

    msg = res.data[0]

    if g.user_id not in [msg["from_user_id"], msg["to_user_id"]]:
        return api_response(False, error="Acceso denegado", status=403)

    if msg["to_user_id"] == g.user_id and not msg["is_read"]:
        supabase.table("messages").update({"is_read": True}).eq("id", message_id).execute()
        msg["is_read"] = True

    return api_response(True, data=msg)

@app.route("/api/messages/<message_id>/read", methods=["PATCH"])
@authenticate_user
def mark_read(message_id):
    data = request.get_json() or {}
    is_read = data.get("is_read")

    if is_read is None:
        return api_response(False, error="is_read requerido", status=400)

    res = supabase.table("messages") \
        .update({"is_read": is_read}) \
        .eq("id", message_id) \
        .eq("to_user_id", g.user_id) \
        .execute()

    if not res.data:
        return api_response(False, error="No autorizado o no existe", status=404)

    return api_response(True, data="Estado actualizado")


@app.route("/api/messages/<message_id>/trash", methods=["PATCH"])
@authenticate_user
def move_trash(message_id):
    data = request.get_json() or {}
    in_trash = data.get("in_trash")

    if in_trash is None:
        return api_response(False, error="in_trash requerido", status=400)

    msg = supabase.table("messages").select("*").eq("id", message_id).single().execute().data

    if g.user_id == msg["to_user_id"]:
        supabase.table("messages") \
            .update({"in_trash_to": in_trash}) \
            .eq("id", message_id) \
            .execute()

    elif g.user_id == msg["from_user_id"]:
        supabase.table("messages") \
            .update({"in_trash_from": in_trash}) \
            .eq("id", message_id) \
            .execute()

    else:
        return api_response(False, error="No autorizado", status=403)

    return api_response(True, data="Movido a papelera")
#--------------------------------------------------
# recuperar password
@app.route("/api/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.get_json() or {}
    email = data.get("email")

    if not email:
        return api_response(False, error="Email requerido", status=400)

    try:
        supabase.auth.reset_password_for_email(
            email,
            {
                "redirect_to": "/login"
            }
        )

        return api_response(
            True,
            data="Te enviamos un correo para recuperar tu contraseña"
        )

    except Exception as e:
        return api_response(False, error=str(e), status=400)

 #--------------------------------------------------
 # resetear password
@app.route("/api/auth/reset-password", methods=["POST"])
def reset_password():
    data = request.get_json() or {}

    access_token = data.get("access_token")
    new_password = data.get("password")

    if not access_token or not new_password:
        return api_response(False, error="Token y contraseña requeridos", status=400)

    try:
        client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

        # Autenticamos temporalmente con el token de recuperación
        client.auth.set_session(access_token, "")

        client.auth.update_user({
            "password": new_password
        })

        return api_response(True, data="Contraseña actualizada correctamente")

    except Exception as e:
        return api_response(False, error=str(e), status=400)


# --------------------------------------------------
# Run
# --------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True)
