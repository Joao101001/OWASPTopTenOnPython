from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'  # Clave secreta para proteger cookies y sesiones
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

# Ruta para el registro de usuarios
@app.route('/templates/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Validar que la contraseña tenga al menos 8 caracteres
        if len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres', 'error')
            return redirect(url_for('register'))
        # Crear un nuevo usuario y guardar su contraseña de manera segura
        with app.app_context():
            new_user = User(username=username)
            new_user.set_password(password)
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('El nombre de usuario ya está en uso', 'error')
            else:
                db.session.add(new_user)
                db.session.commit()
                flash('¡Registro exitoso!', 'success')
                return redirect(url_for('login'))
    return render_template('register.html')

# Ruta para el inicio de sesión de usuarios
@app.route('/templates/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Verificar las credenciales del usuario
        with app.app_context():
            user = User.query.filter_by(username=username).first()
            if user and user.check_password(password):
                session['username'] = username  # Establecer la sesión del usuario
                flash('Inicio de sesión exitoso', 'success')
                return redirect(url_for('home'))
            else:
                flash('Credenciales inválidas', 'error')
    return render_template('login.html')

# Ruta protegida que requiere inicio de sesión
@app.route('/home')
def home():
    if 'username' in session:  # Verificar si el usuario está autenticado
        return 'Bienvenido a la página de inicio (solo visible para usuarios autenticados)'
    else:
        flash('Debe iniciar sesión para acceder a esta página', 'error')
        return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
