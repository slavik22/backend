import os
import secrets
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation
from flasgger import Swagger

from eth_typing import ValidationError
from eth_utils import to_checksum_address
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from siwe import generate_nonce, SiweMessage, VerificationError
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config
from extentions import db, login_manager  # login_manager можна залишити, але він не використовується в guard'ах
from models.application import Application
from models.company import Company
from models.job import Job
from models.user import User
from models.user_profile import UserProfile

from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity
)

# --------- helpers ---------
def user_min_dict(u: User):
    return {
        "id": u.id,
        "email": u.email,
        "role": u.role,
        "wallet_address": u.wallet_address,
        "created_at": u.created_at.isoformat() if u.created_at else None,
    }

def auth_payload(user: User):
    uid = str(user.id)  # <-- рядок!
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
        return jsonify({"ok": False, "error": "forbidden", "message": "Доступ заборонено. Тільки для рекрутерів."}), 403

def admin_guard(user: User):
    if (not user) or (user.role != "admin"):
        return jsonify({"ok": False, "error": "forbidden", "message": "Доступ заборонено. Тільки для адміністраторів."}), 403


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    #
    CORS(
        app,
        resources={r"/*": {"origins": ["https://web3jobs-frontend-1055266214449.europe-central2.run.app", "http://localhost:3000", "http://127.0.0.1:3000",]}},
        supports_credentials=True,
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        expose_headers=["Authorization"]
    )

    app.config["SWAGGER"] = {
        "title": "web3jobs API",
        "uiversion": 3,
    }

    swagger_template = {
        "swagger": "2.0",
        "info": {
            "title": "web3jobs API",
            "description": "API документація для web3jobs",
            "version": "1.0.0"
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": "JWT в заголовку Authorization. Наприклад: \"Bearer eyJ...\""
            }
        }
        # Можна ще глобально задати security, але не обовʼязково:
        # "security": [
        #     {"Bearer": []}
        # ]
    }

    Swagger(app, template=swagger_template)


    app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")

    db.init_app(app)
    with app.app_context():
        db.create_all()
    # login_manager.init_app(app)  # можна залишити/прибрати; не використовується для доступу
    jwt = JWTManager(app)

    # ---------------- Error handlers (JSON) ----------------
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"ok": False, "error": "bad_request", "message": str(e)}), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return jsonify({"ok": False, "error": "forbidden"}), 403

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"ok": False, "error": "not_found"}), 404

    @jwt.unauthorized_loader
    def jwt_unauth(msg):
        return jsonify({"ok": False, "error": "unauthorized", "message": msg}), 401

    @jwt.invalid_token_loader
    def jwt_invalid(reason):
        return jsonify({"ok": False, "error": "invalid_token", "message": reason}), 401

    @jwt.expired_token_loader
    def jwt_expired(h, p):
        return jsonify({"ok": False, "error": "token_expired"}), 401

    # ---------------- Public routes ----------------


    @app.get("/")
    def root():
        """
        Get landing data (recent jobs and stats)
        ---
        tags:
          - Public
        responses:
          200:
            description: Останні активні вакансії та статистика
            schema:
              type: object
              properties:
                ok:
                  type: boolean
                jobs:
                  type: array
                  items:
                    type: object
                stats:
                  type: object
        """
        jobs = Job.query.filter_by(is_active=True).order_by(Job.created_at.desc()).limit(10).all()
        stats = {
            "total_jobs": Job.query.filter_by(is_active=True).count(),
            "dao_jobs": Job.query.filter_by(is_active=True, is_dao_job=True).count(),
            "companies": Company.query.count(),
        }
        return jsonify({"ok": True, "jobs": [j.to_dict(with_company=True) for j in jobs], "stats": stats})

    @app.get("/about")
    def about():
        """
        Get API info
        ---
        tags:
          - Public
        responses:
          200:
            description: Інформація про API
            schema:
              type: object
              properties:
                ok:
                  type: boolean
                app:
                  type: string
                version:
                  type: string
        """
        return jsonify({"ok": True, "app": "web3jobs-api", "version": "1.0"})

    # ---------------- JWT Auth ----------------
    @app.post("/auth/register")
    def auth_register():
        """
        Register user with email/password
        ---
        tags:
          - Auth
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                email:
                  type: string
                password:
                  type: string
                role:
                  type: string
                  enum: [user, recruiter, admin]
                wallet_address:
                  type: string
        responses:
          201:
            description: Користувача створено
          400:
            description: Некоректні дані
          409:
            description: Email вже існує
        """
        data = request.get_json(force=True) or {}
        email = data.get("email")
        password = data.get("password")
        role = data.get("role", "user")
        wallet = data.get("wallet_address")

        if not email or not password:
            return jsonify({"ok": False, "error": "invalid_data", "message": "Email і пароль обов'язкові."}), 400

        if User.query.filter_by(email=email).first():
            return jsonify({"ok": False, "error": "exists", "message": "Email вже зареєстрований."}), 409

        user = User(
            email=email,
            password_hash=generate_password_hash(password, method="pbkdf2:sha256"),
            role=role,
            wallet_address=wallet if wallet else None,
        )
        db.session.add(user)
        db.session.commit()

        profile = UserProfile(user_id=user.id)
        db.session.add(profile)
        db.session.commit()

        return jsonify({"ok": True, **auth_payload(user)}), 201

    @app.post("/auth/login")
    def auth_login():
        """
         Login with email/password
         ---
         tags:
           - Auth
         consumes:
           - application/json
         parameters:
           - in: body
             name: body
             required: true
             schema:
               type: object
               properties:
                 email:
                   type: string
                 password:
                   type: string
         responses:
           200:
             description: Успішний логін, повертаються JWT токени
           401:
             description: Невірні облікові дані
         """
        data = request.get_json(force=True) or {}
        email = data.get("email")
        password = data.get("password")
        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            return jsonify({"ok": True, **auth_payload(user)})
        return jsonify({"ok": False, "error": "invalid_credentials", "message": "Невірний email або пароль."}), 401

    @app.post("/auth/refresh")
    @jwt_required(refresh=True)
    def auth_refresh():
        """
        Refresh access token
        ---
        tags:
          - Auth
        security:
          - Bearer: []
        responses:
          200:
            description: Новий access токен
          404:
            description: Користувача не знайдено
        """
        uid = get_jwt_identity()  # <- рядок
        user = User.query.get(int(uid))  # <- приводимо назад до int
        if not user:
            return jsonify({"ok": False, "error": "not_found"}), 404
        new_access = create_access_token(identity=str(user.id))
        return jsonify({"ok": True, "access_token": new_access})

    from google.oauth2 import id_token
    from google.auth.transport import requests as google_requests

    @app.post("/auth/google")
    def auth_google():
        """
        Login / Register via Google OAuth (id_token)
        ---
        tags:
          - Auth
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                credential:
                  type: string
                  description: Google ID token (JWT)
                role:
                  type: string
                  enum: [user, recruiter]
                  description: Бажана роль (опційно)
        responses:
          200:
            description: Успішний логін, повертаються JWT токени
          400:
            description: Некоректний або неповний токен
          401:
            description: Валідація Google токена не пройшла
        """
        data = request.get_json(force=True) or {}
        credential = data.get("credential")
        desired_role = data.get("role")  # optional; fallback 'user'

        if not credential:
            return jsonify({"ok": False, "message": "Missing Google credential"}), 400

        try:
            idinfo = id_token.verify_oauth2_token(
                credential,
                google_requests.Request(),
                app.config["GOOGLE_CLIENT_ID"]
            )
            # If verification failed, it raises.
            # idinfo includes: sub, email, email_verified, name, picture, given_name, family_name, etc.
            email = idinfo.get("email")
            if not email:
                return jsonify({"ok": False, "message": "Google token missing email"}), 400

            user = User.query.filter_by(email=email).first()
            if not user:
                # Create new user. No password required.
                user = User(
                )
                user.email=email
                user.role=desired_role if desired_role in ["user", "recruiter"] else "user"
                user.wallet_address=None
                db.session.add(user)
                db.session.commit()
                # Ensure profile exists
                if not user.profile:
                    db.session.add(UserProfile(user_id=user.id, full_name=idinfo.get("name")))
                    db.session.commit()

            # (Optional) update profile name/picture if you want
            if user.profile:
                changed = False
                full_name = idinfo.get("name")
                if full_name and user.profile.full_name != full_name:
                    user.profile.full_name = full_name
                    changed = True
                if changed:
                    db.session.add(user.profile)
                    db.session.commit()

            # Return your own JWT like regular login
            payload = auth_payload(user)  # uses your existing helper
            return jsonify({"ok": True, **payload})
        except Exception as e:
            # Don't leak internals; log e if needed
            return jsonify({"ok": False, "message": "Google verification failed"}), 401

    @app.get("/auth/siwe/nonce")
    def siwe_nonce():
        """
        Get nonce for SIWE (Sign-In with Ethereum)
        """
        # якщо nonce вже є в сесії — віддаємо його,
        # а не генеруємо новий
        nonce = session.get("siwe_nonce")
        if not nonce:
            nonce = generate_nonce()
            session["siwe_nonce"] = nonce
        return jsonify({"ok": True, "nonce": nonce})

    @app.post("/auth/siwe/verify")
    def siwe_verify():
        """
        Login/Register via crypto wallet (SIWE)
        ---
        tags:
          - Auth
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                message:
                  type: string
                  description: SIWE message (EIP-4361)
                signature:
                  type: string
                  description: Signed SIWE message
                role:
                  type: string
                  enum: [user, recruiter]
                  description: Бажана роль (опційно, тільки для нового акаунту)
        responses:
          200:
            description: Успішний логін, повертаються JWT токени
          400:
            description: Некоректні дані / nonce
          401:
            description: Валідація SIWE не пройшла
        """
        data = request.get_json(force=True) or {}
        message_str = data.get("message")
        signature = data.get("signature")
        desired_role = data.get("role")

        if not message_str or not signature:
            return jsonify(
                {"ok": False, "error": "invalid_data", "message": "message і signature обов'язкові"}), 400

        nonce = session.get("siwe_nonce")
        if not nonce:
            return jsonify(
                {"ok": False, "error": "no_nonce", "message": "SIWE nonce відсутній або застарілий"}), 400

        try:
            msg = SiweMessage.from_message(message_str)

            # Перевірка підпису + nonce
            msg.verify(signature, nonce=nonce)

            # Додаткові перевірки безпеки
            # expected_domain = request.host.split(":")[0]
            # if msg.domain != expected_domain:
            #     return jsonify({"ok": False, "error": "invalid_domain"}), 401

            # Можна перевірити chainId, якщо хочеш
            # if msg.chain_id != 1: ...

            wallet_address = to_checksum_address(msg.address)

            # nonce використали — очищаємо
            session.pop("siwe_nonce", None)

            # Шукаємо або створюємо юзера
            user = User.query.filter_by(wallet_address=wallet_address).first()
            if not user:
                # Якщо email необов'язковий — можна залишити None
                user = User(

                )
                user.email = f"{wallet_address}@web3jobs.com"
                user.role = desired_role if desired_role in ["user", "recruiter"] else "user"
                user.wallet_address = wallet_address

                db.session.add(user)
                db.session.commit()

                # Створюємо профіль
                profile = UserProfile()
                profile.user_id = user.id
                db.session.add(profile)
                db.session.commit()

            # Логін через JWT
            payload = auth_payload(user)
            return jsonify({"ok": True, **payload})

        except VerificationError as e:
            return jsonify({"ok": False, "error": "VerificationError", "message": e}), 401
        except Exception as e:
            # Логи можна писати в stdout/файл
            return jsonify({"ok": False, "error": "siwe_failed", "message": f"SIWE verification failed {e}"}), 401

    @app.get("/me")
    @jwt_required(optional=True)
    def me():
        """
        Get current user (short info)
        ---
        tags:
          - Auth
        security:
          - Bearer: []
        responses:
          200:
            description: Поточний користувач або None
        """
        uid = get_jwt_identity()
        if not uid:
            return jsonify({"ok": False, "user": None})
        user = User.query.get(uid)
        return jsonify({"ok": True, "user": user_min_dict(user) if user else None})

    @app.post("/logout")
    def logout():
        """
        Logout (client-side token clear hint)
        ---
        tags:
          - Auth
        responses:
          200:
            description: Логаут з боку клієнта (видалення токенів)
        """
        return jsonify({"ok": True, "message": "Logged out (client-side token clear)"})


    # ---------------- User dashboard & profile ----------------
    @app.get("/dashboard")
    @jwt_required()
    def dashboard():

        """
        Get user dashboard
        ---
        tags:
          - User
        security:
          - Bearer: []
        responses:
          200:
            description: Дані для дашборду користувача
          401:
            description: Неавторизовано
        """
        user = current_user_jwt()
        if not user:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        if user.role == "recruiter":
            return jsonify({"ok": True, "redirect": "/recruiter/dashboard"})
        if user.role == "admin":
            return jsonify({"ok": True, "redirect": "/admin/dashboard"})

        apps = (
            Application.query
            .filter_by(user_id=user.id)
            .order_by(Application.applied_at.desc())
            .all()
        )

        return jsonify({
            "ok": True,
            "applications": [
                {
                    **a.to_dict(),
                    "job_title": a.job.title if a.job else None,
                    "company_name": a.job.company.name if a.job and a.job.company else None
                }
                for a in apps
            ]
        })

    @app.get("/profile")
    @jwt_required()
    def get_profile():
        """
        Get user profile
        ---
        tags:
          - User
        security:
          - Bearer: []
        responses:
          200:
            description: Профіль користувача
          401:
            description: Неавторизовано
        """
        user = current_user_jwt()
        if not user:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        base = user.profile.to_dict() if user.profile else {}
        base["email"] = user.email
        base["role"] = user.role

        return jsonify({"ok": True, "profile": base})
    @app.put("/profile")
    @jwt_required()
    def update_profile():
        """
        Update user profile
        ---
        tags:
          - User
        security:
          - Bearer: []
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                full_name:
                  type: string
                phone:
                  type: string
                telegram:
                  type: string
                discord:
                  type: string
                github:
                  type: string
                linkedin:
                  type: string
                portfolio_url:
                  type: string
                ens_domain:
                  type: string
                skills:
                  type: string
                bio:
                  type: string
                preferred_tokens:
                  type: string
                nft_portfolio:
                  type: string
                experience_years:
                  type: integer
        responses:
          200:
            description: Профіль оновлено
          401:
            description: Неавторизовано
        """
        user = current_user_jwt()
        if not user:
            return jsonify({"ok": False, "error": "unauthorized"}), 401

        data = request.get_json(force=True) or {}

        # ---- оновлюємо User.email / User.role ----
        if "email" in data:
            new_email = (data["email"] or "").strip() or None
            # тут за бажанням можна додати перевірку унікальності
            if new_email and User.query.filter(User.email == new_email, User.id != user.id).first():
                return jsonify({"ok": False, "error": "email_exists", "message": "Email вже зайнятий"}), 409
            user.email = new_email

        if "role" in data and data["role"] in ["user", "recruiter"]:
            user.role = data["role"]
        # (admin краще не дозволяти міняти з фронта)

        profile = user.profile or UserProfile(user_id=user.id)
        for field in [
            "full_name", "phone", "telegram", "discord", "github", "linkedin", "portfolio_url",
            "ens_domain", "skills", "bio", "preferred_tokens", "nft_portfolio"
        ]:
            if field in data:
                setattr(profile, field, data[field])

        if "experience_years" in data:
            profile.experience_years = int(data["experience_years"]) if data["experience_years"] is not None else None

        db.session.add(user)
        db.session.add(profile)
        db.session.commit()

        merged = profile.to_dict()
        merged["email"] = user.email
        merged["role"] = user.role

        return jsonify({"ok": True, "message": "Профіль оновлено", "profile": merged})

    # ---------------- Jobs ----------------
    @app.get("/jobs")
    def jobs_list():
        """
              Get list of active jobs (with filters)
              ---
              tags:
                - Jobs
              parameters:
                - in: query
                  name: page
                  type: integer
                  required: false
                  default: 1
                - in: query
                  name: per_page
                  type: integer
                  required: false
                  default: 20
                - in: query
                  name: type
                  type: string
                  required: false
                - in: query
                  name: token
                  type: string
                  required: false
                - in: query
                  name: dao
                  type: string
                  required: false
              responses:
                200:
                  description: Пагінований список вакансій
              """
        page = request.args.get("page", 1, type=int)
        per_page = request.args.get("per_page", 20, type=int)
        job_type = request.args.get("type")
        token = request.args.get("token")
        is_dao = request.args.get("dao")

        query = Job.query.filter_by(is_active=True)
        if job_type:
            query = query.filter_by(job_type=job_type)
        if token:
            query = query.filter_by(salary_token=token)
        if is_dao:
            query = query.filter_by(is_dao_job=True)

        pagination = query.order_by(Job.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            "ok": True,
            "page": pagination.page,
            "pages": pagination.pages,
            "total": pagination.total,
            "items": [j.to_dict(with_company=True) for j in pagination.items],
        })

    @app.get("/job/<int:job_id>")
    @jwt_required(optional=True)
    def job_detail(job_id):
        """
        Get job details
        ---
        tags:
          - Jobs
        parameters:
          - in: path
            name: job_id
            type: integer
            required: true
        responses:
          200:
            description: Детальна інформація про вакансію
          404:
            description: Вакансію не знайдено
        """
        job = Job.query.get_or_404(job_id)
        job.views_count += 1
        db.session.commit()

        has_applied = False
        user = current_user_jwt()
        if user:
            has_applied = Application.query.filter_by(job_id=job_id, user_id=user.id).first() is not None

        return jsonify({"ok": True, "job": job.to_dict(with_company=True), "has_applied": has_applied})

    @app.post("/job/<int:job_id>/apply")
    @jwt_required()
    def apply_job(job_id):
        """
        Apply to a job
        ---
        tags:
          - Jobs
        security:
          - Bearer: []
        parameters:
          - in: path
            name: job_id
            type: integer
            required: true
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                cover_letter:
                  type: string
                resume_url:
                  type: string
        responses:
          201:
            description: Заявку створено
          400:
            description: Некоректні дані
          401:
            description: Неавторизовано
          403:
            description: Тільки кандидати можуть подавати заявки
          409:
            description: Заявку вже подано
        """
        user = current_user_jwt()
        if not user:
            return jsonify({"ok": False, "error": "unauthorized"}), 401
        if user.role != "user":
            return jsonify({"ok": False, "error": "forbidden", "message": "Тільки кандидати можуть подавати заявки."}), 403

        job = Job.query.get_or_404(job_id)
        existing = Application.query.filter_by(job_id=job_id, user_id=user.id).first()
        if existing:
            return jsonify({"ok": False, "error": "duplicate", "message": "Ви вже подали заявку на цю вакансію."}), 409

        data = request.get_json(force=True) or {}
        application = Application(
            job_id=job.id,
            user_id=user.id,
            cover_letter=data.get("cover_letter"),
            resume_url=data.get("resume_url"),
        )
        db.session.add(application)
        db.session.commit()
        return jsonify({"ok": True, "message": "Заявку відправлено", "application": application.to_dict()}), 201

    # ---------------- Recruiter ----------------
    @app.get("/recruiter/dashboard")
    @jwt_required()
    def recruiter_dashboard():
        """
        Recruiter dashboard
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        responses:
          200:
            description: Дані дашборду рекрутера
          403:
            description: Доступ тільки для рекрутерів/адмінів
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        company = user.company
        if not company:
            return jsonify({"ok": True, "needs_company_profile": True, "message": "Створіть профіль компанії."})

        jobs = Job.query.filter_by(company_id=company.id).order_by(Job.created_at.desc()).all()
        total_applications = Application.query.join(Job).filter(Job.company_id == company.id).count()
        pending_applications = Application.query.join(Job).filter(
            Job.company_id == company.id, Application.status == "pending"
        ).count()

        return jsonify({
            "ok": True,
            "company": company.to_dict(),
            "jobs": [j.to_dict() for j in jobs],
            "metrics": {
                "total_applications": total_applications,
                "pending_applications": pending_applications
            }
        })

    @app.get("/recruiter/company")
    @jwt_required()
    def get_company():
        """
        Get recruiter company profile
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        responses:
          200:
            description: Профіль компанії або None
          403:
            description: Доступ тільки для рекрутерів/адмінів
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard:
            return guard

        if not user.company:
            return jsonify({"ok": True, "company": None})

        return jsonify({"ok": True, "company": user.company.to_dict()})

    @app.post("/recruiter/company")
    @jwt_required()
    def create_company():
        """
        Create company profile
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                name:
                  type: string
                website:
                  type: string
                description:
                  type: string
                logo_url:
                  type: string
                company_type:
                  type: string
                treasury_address:
                  type: string
                token_symbol:
                  type: string
                founded_year:
                  type: integer
                team_size:
                  type: string
                location:
                  type: string
        responses:
          201:
            description: Компанію створено
          400:
            description: Некоректні дані
          403:
            description: Доступ тільки для рекрутерів/адмінів
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        if user.company:
            return jsonify({"ok": True, "redirect": "/recruiter/company/edit"})

        data = request.get_json(force=True) or {}
        company = Company(
            recruiter_id=user.id,
            name=data.get("name"),
            website=data.get("website"),
            description=data.get("description"),
            logo_url=data.get("logo_url"),
            company_type=data.get("company_type"),
            treasury_address=data.get("treasury_address"),
            token_symbol=data.get("token_symbol"),
            founded_year=data.get("founded_year"),
            team_size=data.get("team_size"),
            location=data.get("location"),
        )
        db.session.add(company)
        db.session.commit()
        return jsonify({"ok": True, "message": "Компанію створено", "company": company.to_dict()}), 201

    @app.put("/recruiter/company/edit")
    @jwt_required()
    def edit_company():
        """
         Edit company profile
         ---
         tags:
           - Recruiter
         security:
           - Bearer: []
         consumes:
           - application/json
         parameters:
           - in: body
             name: body
             required: true
             schema:
               type: object
               properties:
                 name:
                   type: string
                 website:
                   type: string
                 description:
                   type: string
                 logo_url:
                   type: string
                 company_type:
                   type: string
                 treasury_address:
                   type: string
                 token_symbol:
                   type: string
                 founded_year:
                   type: integer
                 team_size:
                   type: string
                 location:
                   type: string
         responses:
           200:
             description: Компанію оновлено
           403:
             description: Доступ тільки для рекрутерів/адмінів
           404:
             description: Компанії не знайдено
         """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        company = user.company
        if not company:
            return jsonify({"ok": False, "error": "not_found", "message": "Компанії немає."}), 404

        data = request.get_json(force=True) or {}
        for field in ["name","website","description","logo_url","company_type","treasury_address","token_symbol","team_size","location"]:
            if field in data:
                setattr(company, field, data[field])
        if "founded_year" in data:
            company.founded_year = data["founded_year"]

        db.session.commit()
        return jsonify({"ok": True, "message": "Компанію оновлено", "company": company.to_dict()})

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
            return None  # або підніміть 400

    def to_int(val):
        if val is None:
            return None
        s = str(val).strip()
        if s == "":
            return None
        return int(s)

    @app.post("/recruiter/job/create")
    @jwt_required()
    def create_job():
        """
        Create job
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        consumes:
          - application/json
        parameters:
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                title:
                  type: string
                description:
                  type: string
                requirements:
                  type: string
                responsibilities:
                  type: string
                salary_min:
                  type: number
                salary_max:
                  type: number
                salary_token:
                  type: string
                salary_usd_equivalent:
                  type: number
                job_type:
                  type: string
                experience_level:
                  type: string
                location_type:
                  type: string
                location:
                  type: string
                is_dao_job:
                  type: boolean
                uses_escrow:
                  type: boolean
                escrow_contract:
                  type: string
                required_on_chain_proof:
                  type: boolean
                skills_required:
                  type: string
                benefits:
                  type: string
        responses:
          201:
            description: Вакансію створено
          400:
            description: Немає профілю компанії
          403:
            description: Доступ тільки для рекрутерів/адмінів
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        company = user.company
        if not company:
            return jsonify({"ok": False, "error": "no_company", "message": "Спочатку створіть профіль компанії."}), 400

        data = request.get_json(force=True) or {}
        job = Job(
            company_id=company.id,
            title=data.get("title"),
            description=data.get("description"),
            requirements=data.get("requirements"),
            responsibilities=data.get("responsibilities"),
            salary_min= to_decimal(data.get("salary_min")),
            salary_max= to_decimal(data.get("salary_max")),
            salary_token=data.get("salary_token", "USDC"),
            salary_usd_equivalent=to_decimal(data.get("salary_usd_equivalent")),
            job_type=data.get("job_type"),
            experience_level=data.get("experience_level"),
            location_type=data.get("location_type"),
            location=data.get("location"),
            is_dao_job=bool(data.get("is_dao_job")),
            uses_escrow=bool(data.get("uses_escrow")),
            escrow_contract=data.get("escrow_contract"),
            required_on_chain_proof=bool(data.get("required_on_chain_proof")),
            skills_required=data.get("skills_required"),
            benefits=data.get("benefits"),
        )
        db.session.add(job)
        db.session.commit()
        return jsonify({"ok": True, "message": "Вакансію створено", "job": job.to_dict()}), 201

    @app.put("/recruiter/job/<int:job_id>/edit")
    @jwt_required()
    def edit_job(job_id):
        """
              Edit job
              ---
              tags:
                - Recruiter
              security:
                - Bearer: []
              parameters:
                - in: path
                  name: job_id
                  type: integer
                  required: true
                - in: body
                  name: body
                  required: true
                  schema:
                    type: object
                    properties:
                      title:
                        type: string
                      description:
                        type: string
                      requirements:
                        type: string
                      responsibilities:
                        type: string
                      salary_token:
                        type: string
                      job_type:
                        type: string
                      experience_level:
                        type: string
                      location_type:
                        type: string
                      location:
                        type: string
                      escrow_contract:
                        type: string
                      skills_required:
                        type: string
                      benefits:
                        type: string
                      salary_min:
                        type: number
                      salary_max:
                        type: number
                      salary_usd_equivalent:
                        type: number
                      is_dao_job:
                        type: boolean
                      uses_escrow:
                        type: boolean
                      required_on_chain_proof:
                        type: boolean
                      is_active:
                        type: boolean
              responses:
                200:
                  description: Вакансію оновлено
                403:
                  description: Доступ заборонено
                404:
                  description: Вакансію не знайдено
              """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        job = Job.query.get_or_404(job_id)
        if job.company.recruiter_id != user.id and user.role != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403

        data = request.get_json(force=True) or {}
        for field in [
            "title","description","requirements","responsibilities","salary_token","job_type",
            "experience_level","location_type","location","escrow_contract","skills_required","benefits"
        ]:
            if field in data:
                setattr(job, field, data[field])

        for numeric in ["salary_min","salary_max","salary_usd_equivalent"]:
            if numeric in data:
                setattr(job, numeric, data[numeric])

        for boolean in ["is_dao_job","uses_escrow","required_on_chain_proof","is_active"]:
            if boolean in data:
                setattr(job, boolean, bool(data[boolean]))

        db.session.commit()
        return jsonify({"ok": True, "message": "Вакансію оновлено", "job": job.to_dict()})

    @app.get("/recruiter/candidate/<int:user_id>")
    @jwt_required()
    def recruiter_candidate(user_id):
        """
               Get candidate profile (for recruiter)
               ---
               tags:
                 - Recruiter
               security:
                 - Bearer: []
               parameters:
                 - in: path
                   name: user_id
                   type: integer
                   required: true
               responses:
                 200:
                   description: Профіль кандидата
                 403:
                   description: Доступ заборонено
                 404:
                   description: Кандидата не знайдено
               """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        # доступ тільки якщо кандидат подавався на вакансії цього рекрутера
        applied = (
            db.session.query(Application)
            .join(Job, Application.job_id == Job.id)
            .join(Company, Job.company_id == Company.id)
            .filter(Application.user_id == user_id, Company.recruiter_id == user.id)
            .first()
        )
        if not applied and user.role != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403

        candidate = User.query.get_or_404(user_id)

        # якщо є таблиця CandidateProfile — дістаємо з неї:
        profile = getattr(candidate, "profile", None)  # optional relationship

        data = {
            "id": candidate.id,
            "full_name": getattr(profile, "full_name", None),
            "email": candidate.email,
            "phone": getattr(profile, "phone", None),
            "location": getattr(profile, "location", None),
            "github": getattr(profile, "github", None),
            "linkedin": getattr(profile, "linkedin", None),
            "portfolio": getattr(profile, "portfolio", None),
            "skills": getattr(profile, "skills", None) or [],  # список/JSON
            "bio": getattr(profile, "bio", None),
        }
        return jsonify({"ok": True, "candidate": data})

    @app.get("/recruiter/job/<int:job_id>/applications")
    @jwt_required()
    def job_applications(job_id):
        """
        Get applications for a job
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        parameters:
          - in: path
            name: job_id
            type: integer
            required: true
        responses:
          200:
            description: Список заявок на вакансію
          403:
            description: Доступ заборонено
          404:
            description: Вакансію не знайдено
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        job = Job.query.get_or_404(job_id)
        if job.company.recruiter_id != user.id and user.role != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403

        apps = Application.query.filter_by(job_id=job_id).order_by(Application.applied_at.desc()).all()
        return jsonify({"ok": True, "job": job.to_dict(), "applications": [a.to_dict() for a in apps]})

    @app.put("/recruiter/application/<int:app_id>/update")
    @jwt_required()
    def update_application(app_id):
        """
        Update application status/notes
        ---
        tags:
          - Recruiter
        security:
          - Bearer: []
        parameters:
          - in: path
            name: app_id
            type: integer
            required: true
          - in: body
            name: body
            required: true
            schema:
              type: object
              properties:
                status:
                  type: string
                recruiter_notes:
                  type: string
        responses:
          200:
            description: Статус/примітки заявки оновлено
          403:
            description: Доступ заборонено
          404:
            description: Заявку не знайдено
        """
        user = current_user_jwt()
        guard = recruiter_guard(user)
        if guard: return guard

        application = Application.query.get_or_404(app_id)
        if application.job.company.recruiter_id != user.id and user.role != "admin":
            return jsonify({"ok": False, "error": "forbidden"}), 403

        data = request.get_json(force=True) or {}
        if "status" in data:
            application.status = data["status"]
        if "recruiter_notes" in data:
            application.recruiter_notes = data["recruiter_notes"]
        db.session.commit()
        return jsonify({"ok": True, "message": "Статус оновлено", "application": application.to_dict()})

    # ---------------- Admin ----------------
    @app.get("/admin/dashboard")
    @jwt_required()
    def admin_dashboard():
        """
        Admin dashboard
        ---
        tags:
          - Admin
        security:
          - Bearer: []
        responses:
          200:
            description: Загальна статистика платформи
          403:
            description: Доступ тільки для адміністраторів
        """
        user = current_user_jwt()
        guard = admin_guard(user)
        if guard: return guard

        total_users = User.query.count()
        total_companies = Company.query.count()
        total_jobs = Job.query.count()
        total_applications = Application.query.count()
        recent_users = User.query.order_by(User.created_at.desc()).limit(5).all()
        pending_companies = Company.query.filter_by(is_verified=False).all()

        return jsonify({
            "ok": True,
            "totals": {
                "users": total_users,
                "companies": total_companies,
                "jobs": total_jobs,
                "applications": total_applications
            },
            "recent_users": [u.to_dict() for u in recent_users],
            "pending_companies": [c.to_dict() for c in pending_companies]
        })

    @app.post("/admin/verify-company/<int:company_id>")
    @jwt_required()
    def verify_company(company_id):
        """
        Verify company
        ---
        tags:
          - Admin
        security:
          - Bearer: []
        parameters:
          - in: path
            name: company_id
            type: integer
            required: true
        responses:
          200:
            description: Компанію верифіковано
          403:
            description: Доступ тільки для адміністраторів
          404:
            description: Компанію не знайдено
        """
        user = current_user_jwt()
        guard = admin_guard(user)
        if guard: return guard

        company = Company.query.get_or_404(company_id)
        company.is_verified = True
        db.session.commit()
        return jsonify({"ok": True, "message": f"Компанію {company.name} верифіковано!", "company": company.to_dict()})

    # ---------------- Dev helpers ----------------
    @app.post("/dev/create-admin")
    def dev_create_admin():
        email = "admin@web3jobs.com"
        admin = User.query.filter_by(email=email).first()
        if not admin:
            admin = User()
            admin.email = email
            admin.password_hash = generate_password_hash("admin123", method="pbkdf2:sha256")
            admin.role = "admin"
            db.session.add(admin)
            db.session.commit()
        return jsonify({"ok": True, "admin": admin.to_dict()})

    return app

app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
