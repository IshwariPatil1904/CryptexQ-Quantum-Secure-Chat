import os
import ssl
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from flask_socketio import SocketIO, emit
from pymongo import MongoClient
from datetime import datetime
import base64
import json
import oqs  # pip install oqs
import socket

# ---- Local CryptexQ utility imports ----
from crypto_utils import encrypt_aes, decrypt_aes, sign_message, verify_message
from qkd import generate_qkd_key, derive_aes_key_from_qkd
import pqc_utils  # optional

from flask_socketio import SocketIO

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",   # ✅ confirmed working for this version set
    logger=False,
    engineio_logger=False
)


# ---------------- DATABASE -----------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client["cryptexq_db"]
messages_col = db["messages"]
users_col = db["users"]
sessions_col = db["sessions"]

# ---------------- ROUTES -------------------
@app.route("/")
def index_page():
    return render_template("index.html")

@app.route("/talkroom")
def talkroom_page():
    return render_template("talkroom.html")

@app.route("/forgetpg")
def forgetpg_page():
    return render_template("forgetpg.html")

@app.route("/logout")
def logout_page():
    return render_template("logout.html")

@app.route("/home")
def home_page():
    return render_template("home.html")

@app.route("/team")
def team_page():
    return render_template("team.html")

@app.route("/faq")
def faq_page():
    return render_template("faq.html")

@app.route("/contact")
def contact_page():
    return render_template("contact.html")

@app.route("/term")
def terms_page():
    return render_template("terms.html")

@app.route("/about")
def about_page():
    return render_template("about.html")

@app.route("/demo")
def demo_page():
    return render_template("demo.html")

@app.route("/profile")
def profile_page():
    return render_template("profile.html")

# ---------------- SOCKET STATE -------------

KEM_NAME = "Kyber512"

# USERS is the single source of truth
# username -> {
#   "sid": <socket id>,
#   "kyber": {"public": bytes, "private": bytes},
#   "x25519_pub_b64": <browser ECDH public key>
# }
USERS = {}

# ---------------- SOCKET EVENTS ------------

# ---------------- AUTH ROUTES -------------------

@app.route("/signup", methods=["GET", "POST"])
def signup_route():
    if request.method == "GET":
        return render_template("signup.html")

    data = request.get_json(force=True)
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"success": False, "message": "All fields required"}), 400

    if users_col.find_one({"username": username}):
        return jsonify({"success": False, "message": "Username already exists"}), 400

    users_col.insert_one({
        "username": username,
        "email": email,
        "password": password
    })
    return jsonify({"success": True, "message": "Signup successful!"}), 200


@app.route("/login", methods=["GET", "POST"])
def login_route():
    if request.method == "GET":
        return render_template("login.html")

    data = request.get_json(force=True)
    user_input = data.get("username")
    password = data.get("password")

    # Allow login by either username OR email
    user = users_col.find_one({
        "$or": [
            {"username": user_input},
            {"email": user_input}
        ],
        "password": password
    })

    if user:
        return jsonify({"success": True, "message": "Login successful"}), 200
    else:
        return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/logout")
def logout_route():
    return render_template("logout.html")

KEM_NAME = "Kyber512"
USERS = {}  # single shared dictionary for all connections

@socketio.on("connect")
def on_connect():
    print(f"[+] Client connected: {request.sid}")

@socketio.on("disconnect")
def on_disconnect(reason=None):
    sid = request.sid
    disconnected_user = None

    for username, info in list(USERS.items()):
        if info.get("sid") == sid:
            disconnected_user = username
            USERS.pop(username, None)
            break

    if disconnected_user:
        print(f"[-] {disconnected_user} disconnected")

    # Flask-SocketIO v6+ doesn’t support broadcast=True anymore
    socketio.emit("online_users", {"users": list(USERS.keys())})


@socketio.on("register")
def handle_register(data):
    print("\n==== [REGISTER EVENT TRIGGERED] ====")
    print("Raw data received:", data)

    username = data.get("username")
    pub_b64 = data.get("x25519_pub_b64")

    if not username or not pub_b64:
        print("[ERROR] Invalid data — username or pub key missing")
        emit("error", {"message": "Invalid registration data"})
        return

    USERS[username] = {
        "sid": request.sid,
        "pub": pub_b64
    }

    # Simulated Kyber keypair if oqs not available
    try:
        if hasattr(oqs, "KeyEncapsulation"):
            with oqs.KeyEncapsulation(KEM_NAME) as kem:
                pk = kem.generate_keypair()
                sk = kem.export_secret_key()
        else:
            pk = os.urandom(64)
            sk = os.urandom(64)
        USERS[username]["kyber"] = {"public": pk, "private": sk}
        kyber_pub_b64 = base64.b64encode(pk).decode()
    except Exception as e:
        print("[KYBER ERROR - simulated mode]", e)
        kyber_pub_b64 = ""

    emit("registered", {"username": username, "kyber_pub_b64": kyber_pub_b64})

    # ✅ emit to all clients (no 'broadcast' argument)
    socketio.emit("online_users", {"users": list(USERS.keys())})

    print(f"[REGISTER] {username} ({request.sid})")
    print("[DEBUG] USERS dict:", USERS)
    print("=====================================\n")

# -------------- HYBRID (Kyber+AES) -----------------

@socketio.on("request_start_session")
def handle_request_start(data):
    """
    Hybrid PQC mode.
    Client sends: { "from": "Alice", "to": "Bob" }
    We:
      - use Bob's Kyber public key to encapsulate
      - derive the same shared secret on both sides
      - send:
          'kyber_shared_for_initiator' to Alice
          'kyber_ready_peer'          to Bob
    """
    initiator = data.get("from")
    peer = data.get("to")

    if not initiator or not peer:
        emit("error", {"error": "from/to required"})
        return
    if initiator not in USERS or peer not in USERS:
        emit("error", {"error": "user(s) not online"})
        return

    initiator_info = USERS[initiator]
    peer_info = USERS[peer]
    peer_pk = peer_info["kyber"]["public"]

    # Encapsulate using peer's public key
    with oqs.KeyEncapsulation(KEM_NAME) as kem:
        ciphertext, ss_initiator = kem.encap_secret(peer_pk)

    # Decapsulate on peer side, using stored secret key
    peer_sk = peer_info["kyber"]["private"]
    with oqs.KeyEncapsulation(KEM_NAME) as kem_dec:
        ss_peer = kem_dec.decap_secret(ciphertext, peer_sk)

    # Both ss_* should be identical
    ct_b64 = base64.b64encode(ciphertext).decode()
    ss_initiator_b64 = base64.b64encode(ss_initiator).decode()
    ss_peer_b64 = base64.b64encode(ss_peer).decode()

    # Send to initiator
    socketio.emit(
        "kyber_shared_for_initiator",
        {
            "from": peer,
            "kyber_ss_b64": ss_initiator_b64,
            "peer_x25519_b64": peer_info.get("x25519_pub_b64"),
            "cipher_b64": ct_b64,
        },
        room=initiator_info["sid"],
    )

    # Send to peer
    socketio.emit(
        "kyber_ready_peer",
        {
            "from": initiator,
            "cipher_b64": ct_b64,
            "initiator_x25519_b64": initiator_info.get("x25519_pub_b64"),
            "kyber_ss_b64": ss_peer_b64,
        },
        room=peer_info["sid"],
    )

    emit("session_initiated", {"ok": True})
    print(f"[HYBRID] Session started {initiator} <-> {peer}")


# -------------- QKD-AES MODE (Simulated) ------------

@socketio.on("start_qkd_session")
def handle_start_qkd_session(data):
    """
    QKD mode (simulated).
    Client sends: { "from": "Alice", "to": "Bob" }
    We:
      - generate QKD bits (simulate)
      - derive AES key from them
      - send same base64 key to both clients as 'qkd_shared_key'
    """
    initiator = data.get("from")
    peer = data.get("to")

    if not initiator or not peer:
        emit("error", {"error": "from/to required"})
        return
    if initiator not in USERS or peer not in USERS:
        emit("error", {"error": "user(s) not online"})
        return

    # Use your qkd.py helpers
    qkd_bits = generate_qkd_key(512)
    shared_key_bytes = derive_aes_key_from_qkd(qkd_bits)
    shared_b64 = base64.b64encode(shared_key_bytes).decode()

    i_sid = USERS[initiator]["sid"]
    p_sid = USERS[peer]["sid"]

    socketio.emit(
        "qkd_shared_key",
        {"peer": peer, "shared_b64": shared_b64},
        room=i_sid,
    )
    socketio.emit(
        "qkd_shared_key",
        {"peer": initiator, "shared_b64": shared_b64},
        room=p_sid,
    )

    print(f"key established between {initiator} and {peer}")


# -------------- ENCRYPTED CHAT ----------------------

@socketio.on("send_encrypted_message")
def handle_encrypted_message(data):
    """
    Client sends AES-GCM ciphertext:
      {
        "from": "Alice",
        "to": "Bob",
        "ciphertext_b64": "...",
        "iv_b64": "...",
        ...
      }
    We:
      - forward it to recipient only
      - optionally confirm delivery to sender
    """
    to = data.get("to")
    sender = data.get("from")

    if not to or to not in USERS:
        emit("error", {"error": "recipient not available"})
        return

    recipient_sid = USERS[to]["sid"]
    socketio.emit("new_encrypted_message", data, room=recipient_sid)

    # Simple delivery ack
    socketio.emit(
        "message_delivered",
        {"to": to, "ok": True},
        room=request.sid,
    )

    print(f"[MSG] {sender} → {to} (encrypted)")
    
if __name__ == "__main__":
    print("🚀 CryptexQ Server running (Kyber512 + QKD modes) with HTTPS.")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("certs/cert.pem", "certs/key.pem")

    socketio.run(
        app,
        host="0.0.0.0",
        port=5000,
        debug=False,
        ssl_context=context,
        allow_unsafe_werkzeug=True
    )



