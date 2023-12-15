from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

from utils.util import generate_captcha, hash_password

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # ./instance/user.db

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

    def set_password(self, password):
        self.password = password

    def check_password(self, password):
        return self.password == password  # TODO: secure equal

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        captcha = request.form.get('captcha')

        if captcha.lower() != session['captcha'].lower():
            flash('Register failed. Wrong Captcha', 'danger')
        else:
            if not username or not password:
                flash('Please provide both username and password.', 'danger')
            elif password != confirm_password:
                flash('Passwords do not match. Please try again.', 'danger')
            elif User.query.filter_by(username=username).first():
                flash('Username is already taken. Please choose another one.', 'danger')
            else:
                new_user = User(username=username, password=password)
                db.session.add(new_user)
                db.session.commit()
                flash('Registration success! You can now log in.', 'success')
                return redirect(url_for('login'))

    captcha_label, captcha_base64 = generate_captcha()
    session['captcha'] = captcha_label
    return render_template('register.html', captcha_base64='data:image/jpg;base64,'+captcha_base64)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        captcha = request.form.get('captcha')
        user = User.query.filter_by(username=username).first()

        if captcha.lower() != session['captcha'].lower():
            flash('Login failed. Wrong Captcha', 'danger')
        else:
            if user and user.password == password:
                login_user(user)
                # flash('Login success!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Login failed. Please check your username and password.', 'danger')

    captcha_label, captcha_base64 = generate_captcha()
    session['captcha'] = captcha_label
    return render_template('login.html', captcha_base64='data:image/jpg;base64,'+captcha_base64)


@app.route('/refresh_captcha', methods=['GET'])
def refresh_captcha():
    captcha_label, captcha_base64 = generate_captcha()
    session['captcha'] = captcha_label
    return 'data:image/jpg;base64,'+captcha_base64


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if the old password is correct
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
        elif current_user.check_password(old_password):
            current_user.set_password(new_password)
            db.session.commit()
            logout_user()
            flash('Password changed successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Incorrect old password. Please try again.', 'danger')

    return render_template('change_password.html')

@app.route('/')
@login_required
def index():
    return render_template('index.html')
    #return f'Hello, {current_user.username}! <a href="/logout">Logout</a>'


@app.route('/logout')
@login_required
def logout(flash_alert=True):
    logout_user()
    flash('Logout success!', 'success')
    return redirect(url_for('login'))


with app.app_context():
    db.create_all()
# app.run(host='0.0.0.0', debug=True)
# flask run --host=0.0.0.0 --debugger
