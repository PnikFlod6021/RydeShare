from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['STATIC_FOLDER'] = 'static'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'ASDA3D35ASD'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# region models ############

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    can_host = db.Column(db.Boolean(), default=True)
    community_id = db.Column(db.Integer, db.ForeignKey('community.id'), nullable=False)
    
class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    addresses = db.relationship('User', backref='community', lazy=True)
    url = db.Column(db.String(100), nullable=False, unique=True)
    
# endregion

# region forms #############

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError


class RegisterForm(FlaskForm):
    first_name = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "First Name"})
    last_name  = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Last Name"})
    
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    can_host = BooleanField(label="You can drive: ", default="unchecked")
    
    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                        InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                            InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')
        
# endregion

# color palatte: https://coolors.co/061a40-f1f0ea-4cb963-1c6e8c-274156


@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    else:
        return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        new_user = User(username=form.username.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data, can_host=form.can_host.data)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
    
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html', calendar_url="src=06a233e6f808f3713e70450a644351dc6a89d5114093bbc8cd9c1da2965709d6%40group.calendar.google.com")

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# from forms import * # import forms for our register and login pages

if __name__ == '__main__':
    app.run(debug=True)