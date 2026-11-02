"""
NetShield-NIDS - Unit Tests for Authentication & Session Access Control
Tests user registration, secure password hashing, login, logout, and route security.
"""
import pytest
import os
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from config import Config
from app import create_app
import database.db as db

@pytest.fixture
def client(monkeypatch):
    """Create isolated test client and test database."""
    temp_dir = tempfile.mkdtemp()
    test_db = os.path.join(temp_dir, "test_auth.db")
    monkeypatch.setattr(Config, "DATABASE_PATH", test_db)
    
    app = create_app({"TESTING": True, "DATABASE_PATH": test_db})
    with app.test_client() as test_client:
        yield test_client
        
    try:
        if os.path.exists(test_db):
            os.remove(test_db)
    except Exception:
        pass

def test_user_creation_and_hashing():
    """Verify user creation with secure non-plaintext password hashing."""
    user_id, err = db.create_user("sec_analyst", "analyst@test.local", "StrongPassword123", "Analyst Bob")
    assert err is None
    assert user_id is not None
    assert user_id > 0

    # Retrieve user from database
    user = db.get_user_by_id(user_id)
    assert user["username"] == "sec_analyst"
    assert user["email"] == "analyst@test.local"
    assert "password_hash" not in user  # get_user_by_id strips password_hash for safety

    # Verify duplicate username prevention
    dup_id, dup_err = db.create_user("sec_analyst", "other@test.local", "Password123", "Other")
    assert dup_id is None
    assert "already exists" in dup_err

    # Verify short password rejection
    short_id, short_err = db.create_user("short_user", "short@test.local", "123", "Short")
    assert short_id is None
    assert "at least 6 characters" in short_err

def test_authentication_success_and_failure():
    """Verify password hash matching and failure cases."""
    db.create_user("triage_lead", "lead@test.local", "ValidSecret99", "Lead Jane")
    
    # Correct credentials
    user = db.authenticate_user("triage_lead", "ValidSecret99")
    assert user is not None
    assert user["username"] == "triage_lead"
    assert user["last_login"] is not None

    # Authenticate via email
    user_by_email = db.authenticate_user("lead@test.local", "ValidSecret99")
    assert user_by_email is not None

    # Incorrect password
    bad_user = db.authenticate_user("triage_lead", "WrongPassword")
    assert bad_user is None

    # Non-existent user
    none_user = db.authenticate_user("ghost_operator", "SomePass123")
    assert none_user is None

def test_login_flow(client):
    """Verify /login GET and POST endpoints."""
    # Ensure test user exists
    db.create_user("operator1", "op1@test.local", "PassWord@123", "Operator One")

    # GET /login
    res_get = client.get("/login")
    assert res_get.status_code == 200
    assert b"SOC Access Authentication" in res_get.data

    # POST /login (Invalid)
    res_invalid = client.post("/login", data={"identifier": "operator1", "password": "BadPassword"})
    assert res_invalid.status_code == 200
    assert b"Invalid username/email or password" in res_invalid.data

    # POST /login (Valid)
    res_valid = client.post("/login", data={"identifier": "operator1", "password": "PassWord@123"}, follow_redirects=True)
    assert res_valid.status_code == 200
    assert b"Operator One" in res_valid.data

def test_registration_flow(client):
    """Verify /register GET and POST endpoints."""
    res_get = client.get("/register")
    assert res_get.status_code == 200
    assert b"Register SOC Operator" in res_get.data

    # POST /register
    reg_data = {
        "username": "new_analyst",
        "email": "new.analyst@soc.local",
        "full_name": "New Analyst Sarah",
        "role": "Security Analyst",
        "password": "SecurePassword#2026",
        "confirm_password": "SecurePassword#2026"
    }
    res_post = client.post("/register", data=reg_data, follow_redirects=True)
    assert res_post.status_code == 200
    assert b"New Analyst Sarah" in res_post.data

def test_protected_routes_require_login(client):
    """Verify unauthenticated requests are redirected or denied."""
    # Web view redirect
    res_dash = client.get("/")
    assert res_dash.status_code == 302
    assert "/login" in res_dash.headers["Location"]

    # API 401 Unauthorized
    res_api = client.get("/api/dashboard")
    assert res_api.status_code == 401
    assert "Authentication required" in res_api.get_json()["message"]

def test_logout_clears_session(client):
    """Verify /logout clears session and protects subsequent requests."""
    db.create_user("temp_user", "temp@test.local", "TempPass@123", "Temp User")
    client.post("/login", data={"identifier": "temp_user", "password": "TempPass@123"})
    
    # Verify logged in
    res_dash = client.get("/")
    assert res_dash.status_code == 200

    # Logout
    res_logout = client.get("/logout", follow_redirects=True)
    assert res_logout.status_code == 200
    assert b"SOC Access Authentication" in res_logout.data

    # Subsequent access should be blocked
    res_blocked = client.get("/")
    assert res_blocked.status_code == 302
    assert "/login" in res_blocked.headers["Location"]

