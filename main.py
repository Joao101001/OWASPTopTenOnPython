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

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SESSION_COOKIE_SECURE'] = True  # Para cookies seguras
app.config['WTF_CSRF_ENABLED'] = True

# Generar una clave secreta de 32 bytes
csrf_secret_key = secrets.token_hex(32)

# Configurar la clave secreta en la aplicación Flask
app.config['WTF_CSRF_SECRET_KEY'] = csrf_secret_key

csrf = CSRFProtect(app)
db = SQLAlchemy(app)
login_manager = LoginManager(app)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    is_blocked = db.Column(db.Boolean, default=False)  # Nuevo campo para indicar si el usuario está bloqueado
    failed_login_attempts = db.relationship('FailedLoginAttempt', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class FailedLoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class MyForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Submit')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = MyForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        if len(password) < 8:
            flash('La contraseña debe tener al menos 8 caracteres', 'error')
            return redirect(url_for('register'))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('El nombre de usuario ya está en uso', 'error')
            return redirect(url_for('register'))

        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('¡Registro exitoso!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = MyForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()
        if user:
            if user.is_blocked:
                flash('Tu cuenta está bloqueada. Contacta al administrador para más detalles.', 'error')
                return redirect(url_for('login'))

            if len(user.failed_login_attempts) >= 3:
                flash('La cuenta está bloqueada temporalmente debido a demasiados intentos fallidos.', 'error')
                return redirect(url_for('login'))

            if user.check_password(password):
                session['username'] = username
                user.failed_login_attempts = []  # Reiniciar intentos fallidos
                db.session.commit()
                flash('Inicio de sesión exitoso', 'success')
                login_user(user)  # Iniciar sesión con Flask-Login
                return redirect(url_for('home'))
            else:
                failed_attempt = FailedLoginAttempt(user_id=user.id)
                db.session.add(failed_attempt)
                db.session.commit()
                flash('Credenciales inválidas', 'error')
        else:
            flash('Credenciales inválidas', 'error')
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    logout_user()  # Cerrar sesión con Flask-Login
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        flash('Debe iniciar sesión para acceder a esta página', 'error')
        return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if current_user.is_authenticated and current_user.is_admin:
        total_users = User.query.count()
        users_blocked_failed_attempts = User.query.filter(User.is_blocked == True, User.failed_login_attempts.any()).count()
        users_blocked_by_admin = User.query.filter_by(is_blocked=True).count()
        users = User.query.all()
        return render_template('admin_dashboard.html', total_users=total_users, users_blocked_failed_attempts=users_blocked_failed_attempts, users_blocked_by_admin=users_blocked_by_admin, users=users)
    else:
        abort(403)  # Forbidden

@app.route('/admin/block_user/<int:user_id>', methods=['POST'])
def block_user(user_id):
    if current_user.is_authenticated and current_user.is_admin:
        user = User.query.get_or_404(user_id)
        user.is_blocked = not user.is_blocked  # Cambiar el estado de bloqueo
        db.session.commit()
        flash(f'Usuario {user.username} {"desbloqueado" if user.is_blocked else "bloqueado"} correctamente', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        abort(403)  # Forbidden

@app.route('/admin/unblock_failed_attempts/<int:user_id>', methods=['POST'])
def unblock_failed_attempts(user_id):
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



if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
