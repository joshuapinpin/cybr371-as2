from flask import Flask
from . import crypto


def create_app(testing=False):
    app = Flask(__name__)
    app.secret_key = 'test-secret-key'
    if testing:
        app.config['TESTING'] = True

    crypto.init_app(app)

    from .oauth import oauth_bp
    from .client import client_bp
    from .resource import resource_bp

    app.register_blueprint(oauth_bp, url_prefix='/oauth')
    app.register_blueprint(client_bp, url_prefix='/client')
    app.register_blueprint(resource_bp, url_prefix='/api')

    return app
