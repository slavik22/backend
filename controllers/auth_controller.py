import re

from flask import Blueprint, jsonify, request, session
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash

from siwe import generate_nonce, SiweMessage, VerificationError
from eth_utils import to_checksum_address

from models.user import User
from models.user_profile import UserProfile
from extentions import db
from helpers import auth_payload, user_min_dict, current_user_jwt

from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
from flask import current_app as app
from sqlalchemy.exc import IntegrityError


auth_bp = Blueprint("auth", __name__)
EMAIL_REGEX = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"


# ================================
# REGISTER
# ================================

@auth_bp.post("/auth/register")
def auth_register():
    """
    Register a new user (email + password)
    ---
    tags:
      - Auth
    summary: Create a new user account
    description: >
      Створює нового користувача за email і паролем.
      Валідує email, пароль, роль і Ethereum-адресу.

    consumes:
      - application/json

    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              description: Valid email
              example: "test@example.com"
            password:
              type: string
              description: Password (min 6 chars)
              example: "MySecret123"
            role:
              type: string
              enum: ["user", "recruiter"]
              example: "user"
            wallet_address:
              type: string
              example: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

    responses:
      201:
        description: User registered successfully
        schema:
          type: object
          properties:
            ok:
              type: boolean
            access_token:
              type: string
            refresh_token:
              type: string
            user:
              type: object
              properties:
                id:
                  type: integer
                email:
                  type: string
                role:
                  type: string
                wallet_address:
                  type: string

      400:
        description: Validation error
        schema:
          type: object
          properties:
            ok:
              type: boolean
            error:
              type: string
            message:
              type: string

      409:
        description: Email or wallet already registered
        schema:
          type: object
          properties:
            ok:
              type: boolean
              example: False
            error:
              type: string
              example: "email_exists"
            message:
              type: string
              example: "Email вже зареєстрований"
    """
    data = request.get_json(force=True) or {}

    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    role = data.get("role", "user")
    wallet = (data.get("wallet_address") or "").strip()

    # 1. Basic required fields
    if not email or not password:
        return jsonify({"ok": False, "error": "invalid_data",
                        "message": "Email і пароль обов'язкові"}), 400

    # 2. Email format validation
    if not re.match(EMAIL_REGEX, email):
        return jsonify({"ok": False, "error": "invalid_email",
                        "message": "Невірний формат email"}), 400

    # 3. Password validation
    if len(password) < 6:
        return jsonify({"ok": False, "error": "weak_password",
                        "message": "Пароль має бути мінімум 6 символів"}), 400

    # 4. Role validation
    if role not in ["user", "recruiter"]:
        return jsonify({"ok": False, "error": "invalid_role"}), 400

    # 5. Wallet validation (optional)
    if wallet:
        try:
            wallet = to_checksum_address(wallet)
        except Exception:
            return jsonify({"ok": False, "error": "invalid_wallet",
                            "message": "Невірний формат Ethereum адреси"}), 400

        # ✅ Перевірка унікальності гаманця
        if User.query.filter_by(wallet_address=wallet).first():
            return jsonify({
                "ok": False,
                "error": "wallet_exists",
                "message": "Ця Ethereum адреса вже прив'язана до іншого акаунта",
            }), 409

    # 6. Check email existence
    if User.query.filter_by(email=email).first():
        return jsonify({
            "ok": False,
            "error": "email_exists",
            "message": "Email вже зареєстрований",
        }), 409

    # 7. Create user
    user = User(
        email=email,
        password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
        role=role,
        wallet_address=wallet or None,
    )

    db.session.add(user)

    try:
        db.session.commit()
    except IntegrityError as e:
        db.session.rollback()
        # На випадок race conditions або якщо щось пропустили в перевірках
        msg = str(e.orig)
        if "users_wallet_address_key" in msg:
            return jsonify({
                "ok": False,
                "error": "wallet_exists",
                "message": "Ця Ethereum адреса вже прив'язана до іншого акаунта",
            }), 409
        if "users_email_key" in msg:
            return jsonify({
                "ok": False,
                "error": "email_exists",
                "message": "Email вже зареєстрований",
            }), 409
        # якщо причина інша — нехай впаде далі
        raise

    # Create empty profile
    profile = UserProfile(user_id=user.id)
    db.session.add(profile)
    db.session.commit()

    return jsonify({"ok": True, **auth_payload(user)}), 201

# ================================
# LOGIN
# ================================
@auth_bp.post("/auth/login")
def auth_login():
    """
    Login using email and password
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: credentials
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
            password:
              type: string
    responses:
      200:
        description: Logged in successfully
      401:
        description: Invalid credentials
    """
    data = request.get_json(force=True) or {}
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        return jsonify({"ok": True, **auth_payload(user)})
    return jsonify({"ok": False, "error": "invalid_credentials"}), 401


# ================================
# REFRESH TOKEN
# ================================
@auth_bp.post("/auth/refresh")
@jwt_required(refresh=True)
def auth_refresh():
    """
    Refresh JWT access token
    ---
    tags:
      - Auth
    security:
      - Bearer: []
    responses:
      200:
        description: New access token created
      404:
        description: User not found
    """
    uid = get_jwt_identity()
    user = User.query.get(int(uid))
    if not user:
        return jsonify({"ok": False}), 404

    from flask_jwt_extended import create_access_token
    return jsonify({"ok": True, "access_token": create_access_token(identity=str(user.id))})


# ================================
# GOOGLE AUTH
# ================================
@auth_bp.post("/auth/google")
def auth_google():
    """
    Login/Register using Google OAuth2 ID token
    ---
    tags:
      - Auth
    parameters:
      - in: body
        schema:
          type: object
          properties:
            credential:
              type: string
              description: Google ID token
            role:
              type: string
              enum: ["user", "recruiter"]
    responses:
      200:
        description: Authenticated
      400:
        description: Invalid data
      401:
        description: Google verification failed
    """
    data = request.get_json(force=True) or {}
    credential = data.get("credential")
    desired_role = data.get("role")

    if not credential:
        return jsonify({"ok": False, "message": "Missing Google credential"}), 400

    try:
        idinfo = id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            app.config["GOOGLE_CLIENT_ID"],
        )
        email = idinfo.get("email")
        if not email:
            return jsonify({"ok": False, "message": "Google token missing email"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User()
            user.email = email
            user.role = desired_role if desired_role in ["user", "recruiter"] else "user"
            user.wallet_address = None
            db.session.add(user)
            db.session.commit()

            if not user.profile:
                db.session.add(UserProfile(user_id=user.id, full_name=idinfo.get("name")))
                db.session.commit()

        full_name = idinfo.get("name")
        if full_name and user.profile and user.profile.full_name != full_name:
            user.profile.full_name = full_name
            db.session.commit()

        return jsonify({"ok": True, **auth_payload(user)})
    except Exception:
        return jsonify({"ok": False, "message": "Google verification failed"}), 401


# ================================
# SIWE NONCE
# ================================
@auth_bp.get("/auth/siwe/nonce")
def siwe_nonce():
    """
    Get SIWE nonce for crypto wallet login
    ---
    tags:
      - Auth
    responses:
      200:
        description: Nonce generated
    """
    nonce = session.get("siwe_nonce")
    if not nonce:
        nonce = generate_nonce()
        session["siwe_nonce"] = nonce
    return jsonify({"ok": True, "nonce": nonce})


# ================================
# SIWE VERIFY
# ================================
@auth_bp.post("/auth/siwe/verify")
def siwe_verify():
    """
    Verify SIWE signature and log in user
    ---
    tags:
      - Auth
    parameters:
      - in: body
        schema:
          type: object
          required:
            - message
            - signature
          properties:
            message:
              type: string
            signature:
              type: string
            role:
              type: string
              enum: ["user", "recruiter"]
    responses:
      200:
        description: SIWE login successful
      400:
        description: Missing data or nonce
      401:
        description: Verification failed
    """
    data = request.get_json(force=True) or {}
    message_str = data.get("message")
    signature = data.get("signature")
    desired_role = data.get("role")

    if not message_str or not signature:
        return jsonify({"ok": False, "error": "invalid_data"}), 400

    nonce = session.get("siwe_nonce")
    if not nonce:
        return jsonify({"ok": False, "error": "no_nonce"}), 400

    try:
        msg = SiweMessage.from_message(message_str)
        msg.verify(signature, nonce=nonce)
        wallet_address = to_checksum_address(msg.address)
        session.pop("siwe_nonce", None)

        user = User.query.filter_by(wallet_address=wallet_address).first()
        if not user:
            user = User()
            user.email = f"{wallet_address}@web3jobs.com"
            user.role = desired_role if desired_role in ["user", "recruiter"] else "user"
            user.wallet_address = wallet_address
            db.session.add(user)
            db.session.commit()

            profile = UserProfile(user_id=user.id)
            db.session.add(profile)
            db.session.commit()

        return jsonify({"ok": True, **auth_payload(user)})

    except VerificationError as e:
        return jsonify({"ok": False, "error": "VerificationError", "message": str(e)}), 401
    except Exception as e:
        return jsonify({"ok": False, "error": "siwe_failed"}), 401


# ================================
# CURRENT USER
# ================================
@auth_bp.get("/me")
@jwt_required(optional=True)
def me():
    """
    Get current user (minimal info)
    ---
    tags:
      - Auth
    security:
      - Bearer: []
    responses:
      200:
        description: Current user info
    """
    uid = get_jwt_identity()
    if not uid:
        return jsonify({"ok": False, "user": None})
    user = User.query.get(int(uid))
    return jsonify({"ok": True, "user": user_min_dict(user) if user else None})


# ================================
# LOGOUT
# ================================
@auth_bp.post("/logout")
def logout():
    """
    Logout (client-side only)
    ---
    tags:
      - Auth
    responses:
      200:
        description: Logout success
    """
    return jsonify({"ok": True, "message": "Logged out"})
