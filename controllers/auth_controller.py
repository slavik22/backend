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
from flask import current_app as app  # для GOOGLE_CLIENT_ID


auth_bp = Blueprint("auth", __name__)


@auth_bp.post("/auth/register")
def auth_register():
    """
    Register user with email/password
    ---
    tags:
      - Auth
    """
    data = request.get_json(force=True) or {}
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")
    wallet = data.get("wallet_address")

    if not email or not password:
        return jsonify(
            {"ok": False, "error": "invalid_data", "message": "Email і пароль обов'язкові."}
        ), 400

    if User.query.filter_by(email=email).first():
        return jsonify(
            {"ok": False, "error": "exists", "message": "Email вже зареєстрований."}
        ), 409

    user = User(
    )
    user.email = email
    user.password_hash = generate_password_hash(password, method="pbkdf2:sha256")
    user.role = role
    user.wallet_address = wallet if wallet else None

    db.session.add(user)
    db.session.commit()

    profile = UserProfile(user_id=user.id)
    db.session.add(profile)
    db.session.commit()

    return jsonify({"ok": True, **auth_payload(user)}), 201


@auth_bp.post("/auth/login")
def auth_login():
    """
    Login with email/password
    ---
    tags:
      - Auth
    """
    data = request.get_json(force=True) or {}
    email = data.get("email")
    password = data.get("password")
    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password_hash, password):
        return jsonify({"ok": True, **auth_payload(user)})
    return jsonify(
        {"ok": False, "error": "invalid_credentials", "message": "Невірний email або пароль."}
    ), 401


@auth_bp.post("/auth/refresh")
@jwt_required(refresh=True)
def auth_refresh():
    """
    Refresh access token
    ---
    tags:
      - Auth
    """
    uid = get_jwt_identity()
    user = User.query.get(int(uid))
    if not user:
        return jsonify({"ok": False, "error": "not_found"}), 404
    from flask_jwt_extended import create_access_token

    new_access = create_access_token(identity=str(user.id))
    return jsonify({"ok": True, "access_token": new_access})


@auth_bp.post("/auth/google")
def auth_google():
    """
    Login / Register via Google OAuth (id_token)
    ---
    tags:
      - Auth
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
                db.session.add(
                    UserProfile(user_id=user.id, full_name=idinfo.get("name"))
                )
                db.session.commit()

        if user.profile:
            changed = False
            full_name = idinfo.get("name")
            if full_name and user.profile.full_name != full_name:
                user.profile.full_name = full_name
                changed = True
            if changed:
                db.session.add(user.profile)
                db.session.commit()

        payload = auth_payload(user)
        return jsonify({"ok": True, **payload})
    except Exception:
        return jsonify({"ok": False, "message": "Google verification failed"}), 401


@auth_bp.get("/auth/siwe/nonce")
def siwe_nonce():
    """
    Get nonce for SIWE (Sign-In with Ethereum)
    ---
    tags:
      - Auth
    """
    nonce = session.get("siwe_nonce")
    if not nonce:
        nonce = generate_nonce()
        session["siwe_nonce"] = nonce
    return jsonify({"ok": True, "nonce": nonce})


@auth_bp.post("/auth/siwe/verify")
def siwe_verify():
    """
    Login/Register via crypto wallet (SIWE)
    ---
    tags:
      - Auth
    """
    data = request.get_json(force=True) or {}
    message_str = data.get("message")
    signature = data.get("signature")
    desired_role = data.get("role")

    if not message_str or not signature:
        return jsonify(
            {"ok": False, "error": "invalid_data", "message": "message і signature обов'язкові"}
        ), 400

    nonce = session.get("siwe_nonce")
    if not nonce:
        return jsonify(
            {"ok": False, "error": "no_nonce", "message": "SIWE nonce відсутній або застарілий"}
        ), 400

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

        payload = auth_payload(user)
        return jsonify({"ok": True, **payload})

    except VerificationError as e:
        return jsonify({"ok": False, "error": "VerificationError", "message": str(e)}), 401
    except Exception as e:
        return jsonify(
            {"ok": False, "error": "siwe_failed", "message": f"SIWE verification failed {e}"}
        ), 401


@auth_bp.get("/me")
@jwt_required(optional=True)
def me():
    """
    Get current user (short info)
    ---
    tags:
      - Auth
    """
    uid = get_jwt_identity()
    if not uid:
        return jsonify({"ok": False, "user": None})
    user = User.query.get(int(uid))
    return jsonify({"ok": True, "user": user_min_dict(user) if user else None})


@auth_bp.post("/logout")
def logout():
    """
    Logout (client-side token clear hint)
    ---
    tags:
      - Auth
    """
    return jsonify({"ok": True, "message": "Logged out (client-side token clear)"})
