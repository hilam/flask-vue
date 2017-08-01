import os
from server.app_factory import create_app, db
from server.models import User, RegisterUser, UserLoginLog
from flask_script import Manager, Shell
from flask_migrate import Migrate, MigrateCommand

app = create_app()
manager = Manager(app)
migrate = Migrate(app, db)


def make_shell_context():
    return dict(app=app, db=db, User=User, RegisterUser=RegisterUser, UserLoginLog=UserLoginLog)
manager.add_command("shell", Shell(make_context=make_shell_context))
manager.add_command('db', MigrateCommand)


@manager.command
def deploy():
    """Run deployment tasks."""
    from flask_migrate import upgrade
    from server.models import User

    # migrate database to latest revision
    upgrade()



if __name__ == '__main__':
    manager.run()
