from main import db, app

# Asegúrate de que la aplicación esté configurada correctamente
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Crea todas las tablas definidas en los modelos
with app.app_context():
    db.create_all()
