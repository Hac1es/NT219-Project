from .auth_routes import auth_bp
from .key_routes import key_bp
from .data_routes import data_bp
from .computation_routes import comp_bp

def register_routes(app):
    """Register all blueprints with the Flask app"""
    app.register_blueprint(auth_bp, url_prefix='/api')
    app.register_blueprint(key_bp, url_prefix='/api')
    app.register_blueprint(data_bp, url_prefix='/api')
    app.register_blueprint(comp_bp, url_prefix='/api')