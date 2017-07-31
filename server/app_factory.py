import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


def create_app():
    app = Flask(__name__)

    if os.environ.get('ENV') == 'DEV':
        app.config.from_json('../config/dev.json')
    else:
        app.config.from_json('../config/dev.json')

    db.init_app(app)

    from server.auth import auth_blueprint
    app.register_blueprint(auth_blueprint)

    from server.user import user_blueprint
    app.register_blueprint(user_blueprint)

    return app