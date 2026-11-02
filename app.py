"""
NetShield-NIDS - Advanced Network Intrusion Detection & Monitoring System
Main Application Entry Point, Flask Server Factory, & Security Headers.
"""
import os
import sys

# Ensure NetShield-NIDS root directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from flask import Flask, render_template, session, jsonify
from config import Config
from database.db import init_db, get_dashboard_stats, seed_demo_data

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from routes.monitoring import monitoring_bp
from routes.alerts import alerts_bp
from routes.analysis import analysis_bp
from routes.settings import settings_bp

def create_app(test_config=None):
    """Application factory for NetShield-NIDS."""
    app = Flask(
        __name__,
        static_folder="static",
        template_folder="templates"
    )
    
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
        
    # Database Initialization & Baseline Telemetry Check
    try:
        init_db()
        stats = get_dashboard_stats()
        if stats["kpis"]["total_events"] == 0:
            seed_demo_data()
    except Exception as e:
        print(f"[NetShield Notice] Database initialization notice: {e}")

    # Register Blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(settings_bp)

    # Inject authenticated user context into all Jinja2 templates
    @app.context_processor
    def inject_user():
        if "user_id" in session:
            return {
                "current_user": {
                    "id": session.get("user_id"),
                    "username": session.get("username"),
                    "email": session.get("email"),
                    "full_name": session.get("full_name"),
                    "role": session.get("role")
                }
            }
        return {"current_user": None}

    # Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://fonts.gstatic.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self';"
        )
        return response

    # Global Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        msg = getattr(e, "description", "The requested resource was not found on this NetShield node.")
        return render_template(
            "base.html",
            page_title="404 - Not Found",
            error_code=404,
            error_message=msg
        ), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template(
            "base.html",
            page_title="500 - System Error",
            error_code=500,
            error_message="An internal sensor error occurred. Please consult the SOC logs."
        ), 500

    @app.errorhandler(401)
    def unauthorized_error(e):
        return render_template(
            "base.html",
            page_title="401 - Unauthorized",
            error_code=401,
            error_message="Authentication credentials required to access this SOC resource."
        ), 401

    return app

app = create_app()

if __name__ == "__main__":
    host = os.environ.get("NETSHIELD_HOST", "127.0.0.1")
    port = int(os.environ.get("NETSHIELD_PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "True").lower() in ("true", "1")
    
    print("=" * 65)
    print("  NETSHIELD-NIDS - Advanced Network Intrusion Detection System")
    print(f"  Version: {Config.VERSION}")
    print(f"  Console URL: http://{host}:{port}")
    print("  Default Admin: admin | Password: Admin@123")
    print("  Press CTRL+C to halt.")
    print("=" * 65)
    app.run(host=host, port=port, debug=debug)

