import os
from datetime import timedelta

from flask import Flask, jsonify
from flask_cors import CORS
from flasgger import Swagger
from flask_jwt_extended import JWTManager

from config import Config
from controllers.stats_controller import stats_bp
from extentions import db
from models.user import User
from models.job import Job
from models.company import Company


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    CORS(
        app,
        resources={
            r"/*": {
                "origins": [
                    "https://web3jobs-frontend-1055266214449.europe-central2.run.app",
                    "http://localhost:3000",
                    "http://127.0.0.1:3000",
                ]
            }
        },
        supports_credentials=True,
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
        expose_headers=["Authorization"],
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
            "version": "1.0.0",
        },
        "securityDefinitions": {
            "Bearer": {
                "type": "apiKey",
                "name": "Authorization",
                "in": "header",
                "description": 'JWT в заголовку Authorization. Наприклад: "Bearer eyJ..."',
            }
        },
    }
    Swagger(app, template=swagger_template)

    app.config["GOOGLE_CLIENT_ID"] = os.getenv("GOOGLE_CLIENT_ID")

    db.init_app(app)
    with app.app_context():
        db.create_all()

    jwt = JWTManager(app)

    # -------- Error handlers --------
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

    # -------- Simple public routes (root, about, dev-create-admin) --------
    @app.get("/")
    def root():
        jobs = Job.query.filter_by(is_active=True).order_by(Job.created_at.desc()).limit(10).all()
        stats = {
            "total_jobs": Job.query.filter_by(is_active=True).count(),
            "dao_jobs": Job.query.filter_by(is_active=True, is_dao_job=True).count(),
            "companies": Company.query.count(),
        }
        return jsonify(
            {
                "ok": True,
                "jobs": [j.to_dict(with_company=True) for j in jobs],
                "stats": stats,
            }
        )

    from werkzeug.security import generate_password_hash

    @app.post("/dev/create-admin")
    def dev_create_admin():
        email = "admin@web3jobs.com"
        admin = User.query.filter_by(email=email).first()
        if not admin:
            admin = User()
            admin.email = email
            admin.password_hash = generate_password_hash(
                "admin123", method="pbkdf2:sha256"
            )
            admin.role = "admin"
            db.session.add(admin)
            db.session.commit()
        return jsonify({"ok": True, "admin": admin.to_dict()})

    # -------- Register controllers (blueprints) --------
    from controllers.auth_controller import auth_bp
    from controllers.user_controller import user_bp
    from controllers.jobs_controller import jobs_bp
    from controllers.recruiter_controller import recruiter_bp
    from controllers.admin_controller import admin_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(jobs_bp)
    app.register_blueprint(recruiter_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(stats_bp)

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
