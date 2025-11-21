from flask import jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
)
from models.user import User


def user_min_dict(u: User):
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "wallet_address": u.wallet_address,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }


def auth_payload(user: User):
    uid = str(user.id)  # identity має бути рядком
    access = create_access_token(identity=uid)
    refresh = create_refresh_token(identity=uid)
    return {"access_token": access, "refresh_token": refresh, "user": user_min_dict(user)}


def current_user_jwt():
    uid = get_jwt_identity()
    try:
        uid = int(uid)
    except (TypeError, ValueError):
        return None
    return User.query.get(uid)


def recruiter_guard(user: User):
    if (not user) or (user.role not in ["recruiter", "admin"]):
        return jsonify(
            {
                "ok": False,
                "error": "forbidden",
                "message": "Доступ заборонено. Тільки для рекрутерів.",
            }
        ), 403


def admin_guard(user: User):
    if (not user) or (user.role != "admin"):
        return jsonify(
            {
                "ok": False,
                "error": "forbidden",
                "message": "Доступ заборонено. Тільки для адміністраторів.",
            }
        ), 403


from decimal import Decimal, InvalidOperation


def to_decimal(val):
    if val is None:
        return None
    if isinstance(val, (int, float, Decimal)):
        return Decimal(str(val))
    s = str(val).strip()
    if s == "":
        return None
    try:
        return Decimal(s)
    except InvalidOperation:
        return None


def to_int(val):
    if val is None:
        return None
    s = str(val).strip()
    if s == "":
        return None
    return int(s)
