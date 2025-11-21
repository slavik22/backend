# tests/test_app.py
import json
import os
import sys

import pytest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import app as backend  # <-- якщо модуль називається інакше, заміни "app"


class TestConfig(backend.Config):
    """Тестова конфігурація: in-memory SQLite, TESTING mode."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    WTF_CSRF_ENABLED = False
    # Менший час життя токенів можна поставити, але не обов'язково


@pytest.fixture(scope="function")
def app(monkeypatch):
    """
    Створюємо окремий app для кожного тесту.
    Патчимо Config у модулі backend на TestConfig.
    """
    monkeypatch.setattr(backend, "Config", TestConfig)
    app = backend.create_app()

    # Налаштовуємо базу як in-memory
    app.config.update(
        SQLALCHEMY_DATABASE_URI=TestConfig.SQLALCHEMY_DATABASE_URI,
        TESTING=True,
    )

    with app.app_context():
        backend.db.drop_all()
        backend.db.create_all()
        yield app

        # Прибираємо після тесту
        backend.db.session.remove()
        backend.db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def auth_headers(access_token: str) -> dict:
    return {"Authorization": f"Bearer {access_token}"}


# ------------------------ BASIC ROUTES ------------------------


def test_root_empty_db(client, app):
    """Кореневий маршрут / повертає ок та статистику."""
    resp = client.get("/")
    assert resp.status_code == 200
    payload = resp.get_json()
    assert payload["ok"] is True
    assert isinstance(payload["jobs"], list)
    assert payload["stats"]["total_jobs"] == 0
    assert payload["stats"]["dao_jobs"] == 0
    assert payload["stats"]["companies"] == 0


def test_about(client):
    resp = client.get("/about")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["app"] == "web3jobs-api"


# ------------------------ AUTH: REGISTER / LOGIN / REFRESH / ME ------------------------


def test_register_login_refresh_and_me(client, app):
    email = "user@example.com"
    password = "secret123"

    # REGISTER
    resp = client.post(
        "/auth/register",
        json={"email": email, "password": password, "role": "user"},
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["ok"] is True
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == email

    access = data["access_token"]
    refresh = data["refresh_token"]

    # LOGIN
    resp = client.post("/auth/login", json={"email": email, "password": password})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "access_token" in data
    assert "refresh_token" in data

    # ME з access
    resp = client.get("/me", headers=auth_headers(access))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["user"]["email"] == email

    # REFRESH з refresh
    resp = client.post("/auth/refresh", headers=auth_headers(refresh))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "access_token" in data


def test_register_conflict(client, app):
    email = "dup@example.com"
    password = "secret123"

    # перша реєстрація
    resp = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 201

    # друга така сама -> 409
    resp = client.post(
        "/auth/register",
        json={"email": email, "password": password},
    )
    assert resp.status_code == 409
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "exists"


def test_login_invalid_credentials(client, app):
    resp = client.post(
        "/auth/login",
        json={"email": "no-such@example.com", "password": "whatever"},
    )
    assert resp.status_code == 401
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "invalid_credentials"


# ------------------------ RECRUITER / ADMIN GUARDS ------------------------


def create_user(db, email, role="user", wallet_address=None):
    """Хелпер для створення користувача напряму через ORM."""
    user = backend.User(
        email=email,
        password_hash=backend.generate_password_hash("password123", method="pbkdf2:sha256"),
        role=role,
        wallet_address=wallet_address,
    )
    db.session.add(user)
    db.session.commit()
    # профіль
    profile = backend.UserProfile(user_id=user.id)
    db.session.add(profile)
    db.session.commit()
    return user


def jwt_for_user(user):
    """Створює access/refresh токени через той самий helper."""
    return backend.create_access_token(identity=str(user.id))


def test_recruiter_dashboard_forbidden_for_user(client, app):
    with app.app_context():
        user = create_user(backend.db, "u1@example.com", role="user")
        token = jwt_for_user(user)

    resp = client.get("/recruiter/dashboard", headers=auth_headers(token))
    assert resp.status_code == 403
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "forbidden"


def test_recruiter_dashboard_ok_for_recruiter_without_company(client, app):
    with app.app_context():
        rec = create_user(backend.db, "rec@example.com", role="recruiter")
        token = jwt_for_user(rec)

    resp = client.get("/recruiter/dashboard", headers=auth_headers(token))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["needs_company_profile"] is True


def test_admin_dashboard_for_admin(client, app):
    with app.app_context():
        admin = create_user(backend.db, "admin@example.com", role="admin")
        token = jwt_for_user(admin)

    resp = client.get("/admin/dashboard", headers=auth_headers(token))
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    # прості sanity-check’и
    assert "totals" in data
    assert "users" in data["totals"]


# ------------------------ JOBS LIST ------------------------


def test_jobs_list_empty(client, app):
    resp = client.get("/jobs?page=1&per_page=5")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["total"] == 0
    assert data["items"] == []


def test_jobs_created_by_recruiter(client, app):
    with app.app_context():
        rec = create_user(backend.db, "rec2@example.com", role="recruiter")
        token = jwt_for_user(rec)

        # створюємо компанію
        company = backend.Company(
            recruiter_id=rec.id,
            name="Test Company",
            website="https://example.com",
            description="Desc",
        )
        backend.db.session.add(company)
        backend.db.session.commit()

    # створюємо job через API
    resp = client.post(
        "/recruiter/job/create",
        headers=auth_headers(token),
        json={
            "title": "Solidity Dev",
            "description": "Build smart contracts",
            "requirements": "Solidity, EVM",
            "salary_min": "1000",
            "salary_max": "2000",
            "salary_token": "USDC",
            "job_type": "full_time",
            "experience_level": "mid",
            "location_type": "remote",
            "location": "Global",
            "is_dao_job": True,
        },
    )
    assert resp.status_code == 201
    data = resp.get_json()
    assert data["ok"] is True
    job_id = data["job"]["id"]

    # тепер /jobs повинен показати цю вакансію
    resp = client.get("/jobs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["total"] == 1
    assert data["items"][0]["id"] == job_id


# ------------------------ GOOGLE AUTH (mock) ------------------------


from google.oauth2 import id_token as google_id_token  # додай імпорт нагорі файлу

def test_auth_google_creates_user(monkeypatch, client, app):
    """Мокаємо Google id_token.verify_oauth2_token, щоб не дзвонити в Google."""
    def fake_verify_oauth2_token(credential, request, client_id):
        assert credential == "fake-google-token"
        return {
            "email": "guser@example.com",
            "name": "Google User",
            "email_verified": True,
            "sub": "1234567890",
        }

    # патчимо справжній модуль google.oauth2.id_token
    monkeypatch.setattr(
        google_id_token, "verify_oauth2_token", fake_verify_oauth2_token
    )

    resp = client.post(
        "/auth/google",
        json={"credential": "fake-google-token", "role": "recruiter"},
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["user"]["email"] == "guser@example.com"
    assert data["user"]["role"] in ("recruiter", "user")
    assert "access_token" in data
    assert "refresh_token" in data


# ------------------------ SIWE WALLET AUTH (mock) ------------------------


class FakeSiweMessage:
    def __init__(self, address, nonce):
        self.address = address
        self.nonce = nonce

    def verify(self, signature, nonce):
        # тут можемо просто приймати будь-які signature/nonce
        assert nonce == self.nonce
        return True


def test_wallet_siwe_flow(monkeypatch, client, app):
    """
    1) /auth/wallet/nonce -> отримуємо nonce
    2) /auth/wallet/verify з підробленим SiweMessage, який поверне ту ж адресу/nonce
    """

    address = "0x1234567890abcdef1234567890abcdef12345678".lower()

    # Крок 1: отримати nonce
    resp = client.post("/auth/wallet/nonce", json={"address": address})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    nonce = data["nonce"]

    # Мокаємо SiweMessage.from_message, щоб повертав FakeSiweMessage з цією адресою/nonce
    def fake_from_message(message: str):
        # message можемо ігнорувати, ми вже знаємо address та nonce
        return FakeSiweMessage(address=address, nonce=nonce)

    monkeypatch.setattr(backend.SiweMessage, "from_message", staticmethod(fake_from_message))

    # signature будь-який
    resp = client.post(
        "/auth/wallet/verify",
        json={
            "message": "dummy-siwe-message",
            "signature": "0xdeadbeef",
        },
    )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["wallet_address"] == address


def test_wallet_nonce_invalid_address(client, app):
    resp = client.post("/auth/wallet/nonce", json={"address": "invalid"})
    assert resp.status_code == 400
    data = resp.get_json()
    assert data["ok"] is False
    assert data["error"] == "invalid_address"
