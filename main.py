# Importación de módulos y clases necesarios desde Flask y sus extensiones
from flask import Flask, request, render_template, redirect, url_for, flash, session, abort
import html
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_login import LoginManager, current_user, login_user, logout_user, UserMixin
import secrets

# Creación de la aplicación Flask
app = Flask(__name__)

# Configuración de la clave secreta de la aplicación
app.config['SECRET_KEY'] = 'your_secret_key_here'

# Configuración de la URI de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

# Configuración para cookies seguras
app.config['SESSION_COOKIE_SECURE'] = True

# Habilitación de CSRF para protección contra ataques CSRF
app.config['WTF_CSRF_ENABLED'] = True

# Generación de una clave secreta de CSRF
csrf_secret_key = secrets.token_hex(32)

# Configuración de la clave secreta de CSRF en la aplicación Flask
app.config['WTF_CSRF_SECRET_KEY'] = csrf_secret_key

# Inicialización de CSRF
csrf = CSRFProtect(app)

# Inicialización de la base de datos SQLAlchemy
db = SQLAlchemy(app)

# Configuración del LoginManager para gestionar la autenticación de usuarios
login_manager = LoginManager(app)


# Definición de la clase de usuario con los campos de la base de datos
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)
    failed_login_attempts = db.relationship('FailedLoginAttempt', backref='user', lazy=True)

    # Método para establecer la contraseña del usuario
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Método para verificar la contraseña del usuario
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# Función para cargar un usuario dado su ID
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Definición de la clase de intentos de inicio de sesión fallidos
class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


# Definición del formulario para el registro e inicio de sesión
class MyForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')


# Ruta para el registro de usuarios
@app.route('/register', methods=['GET', 'POST'])
def register():
    # Creación del formulario de registro
    form = MyForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Validación de la longitud de la contraseña
        if len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres', 'error')
            return redirect(url_for('register'))

        # Verificación de si el nombre de usuario ya está en uso
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está en uso', 'error')
            return redirect(url_for('register'))

        # Creación de un nuevo usuario y almacenamiento en la base de datos
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('¡Registro exitoso!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


# Ruta para el inicio de sesión de usuarios
@app.route('/login', methods=['GET', 'POST'])
def login():
    # Creación del formulario de inicio de sesión
    form = MyForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Obtención del usuario desde la base de datos
        user = User.query.filter_by(username=username).first()
        if user:
            # Manejo de cuentas bloqueadas
            if user.is_blocked:
                flash('Tu cuenta está bloqueada. Contacta al administrador para más detalles.', 'error')
                return redirect(url_for('login'))

            # Manejo de múltiples intentos fallidos
            if len(user.failed_login_attempts) >= 3:
                flash('La cuenta está bloqueada temporalmente debido a demasiados intentos fallidos.', 'error')
                return redirect(url_for('login'))

            # Verificación de las credenciales del usuario
            if user.check_password(password):
                # Establecimiento de la sesión de usuario y redirección a la página de inicio
                session['username'] = username
                user.failed_login_attempts = []  # Reiniciar intentos fallidos
                db.session.commit()
                flash('Inicio de sesión exitoso', 'success')
                login_user(user)  # Iniciar sesión con Flask-Login
                return redirect(url_for('home'))
            else:
                # Registro de intento de inicio de sesión fallido
                failed_attempt = FailedLoginAttempt(user_id=user.id)
                db.session.add(failed_attempt)
                db.session.commit()
                flash('Credenciales inválidas', 'error')
        else:
            flash('Credenciales inválidas', 'error')
    return render_template('login.html', form=form)


# Ruta para el cierre de sesión de usuarios
@app.route('/logout')
def logout():
    logout_user()  # Cerrar sesión con Flask-Login
    return redirect(url_for('login'))


# Ruta para la página de inicio
@app.route('/home')
def home():
    # Verificación de si el usuario está autenticado
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        flash('Debe iniciar sesión para acceder a esta página', 'error')
        return redirect(url_for('login'))


# Ruta para el panel de administrador
@app.route('/admin/dashboard')
def admin_dashboard():
    # Verificación de si el usuario es administrador y está autenticado
    if current_user.is_authenticated and current_user.is_admin:
        total_users = User.query.count()
        users_blocked_failed_attempts = User.query.filter(User.is_blocked == True,
                                                          User.failed_login_attempts.any()).count()
        users_blocked_by_admin = User.query.filter_by(is_blocked=True).count()
        users = User.query.all()
        return render_template('admin_dashboard.html', total_users=total_users,
                               users_blocked_failed_attempts=users_blocked_failed_attempts,
                               users_blocked_by_admin=users_blocked_by_admin, users=users)
    else:
        abort(403)  # Forbidden


# Ruta para bloquear/desbloquear usuarios por parte del administrador
@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    # Verificación de si el usuario es administrador y está autenticado
    if current_user.is_authenticated and current_user.is_admin:
        user = User.query.get_or_404(user_id)
        user.is_blocked = not user.is_blocked  # Cambiar el estado de bloqueo
        db.session.commit()
        flash(f'Usuario {user.username} {"desbloqueado" if user.is_blocked else "bloqueado"} correctamente', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        abort(403)  # Forbidden


# Ruta para desbloquear usuarios bloqueados por intentos fallidos
@app.route('/admin/unblock_failed_attempts/<int:user_id>', methods=['POST'])
def unblock_failed_attempts(user_id):
    # Verificación de si el usuario es administrador y está autenticado
    if current_user.is_authenticated and current_user.is_admin:
        user = User.query.get_or_404(user_id)
        user.is_blocked = False  # Desbloquear usuario

        # Eliminar los intentos fallidos registrados para este usuario
        FailedLoginAttempt.query.filter_by(user_id=user.id).delete()

        db.session.commit()
        flash(f'Usuario {user.username} desbloqueado correctamente', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        abort(403)  # Forbidden


# Ejecución de la aplicación Flask
if __name__ == '__main__':
    # Creación de todas las tablas definidas en los modelos
    with app.app_context():
        db.create_all()
    # Ejecución de la aplicación en modo debug
    app.run(debug=True)
