from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

import datetime as dt
import os

from google.auth.transport.requests import Request
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

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
    
    def get_community_calendar_id(self):
        return Community.query.filter_by(id=self.community_id).first().calendarId
    
class Community(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    calendarId = db.Column(db.String(100), nullable=True)
    users = db.relationship('User', backref='community', lazy=True)
    
# endregion

# region forms #############

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError


class RegisterForm(FlaskForm):
    first_name = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "First Name"})
    last_name  = StringField(validators=[InputRequired(), Length(min=1, max=20)], render_kw={"placeholder": "Last Name"})
    
    email = EmailField(validators=[InputRequired(), Length(min=1, max=100)], render_kw={"placeholder": "Email"})
    
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    password = PasswordField(validators=[InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})
    
    community = StringField(validators=[InputRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Community"}, id="community")

    can_host = BooleanField(label="You can drive: ", default="checked")
    
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

# region Google api ########

SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/calendar.readonly']

cred = Credentials.from_service_account_file('service_account_cred.json', scopes=SCOPES)

service = build('calendar', 'v3', credentials=cred)

# Call the Calendar API
now = dt.datetime.utcnow().isoformat() + 'Z'  # 'Z' indicates UTC time

def create_calendar(community:Community):    
    new_calendar = service.calendars().insert(body={'summary':community.name}).execute()
    
    # write it to the database
    community.calendarId = new_calendar['id']
    db.session.commit()
    
    #make the calendar public
    rules = {
        "role": "reader",
        "scope": {
            "type": "default"
        }
    }
    created_rule = service.acl().insert(calendarId=new_calendar['id'], body=rules).execute()
    
def create_event(comm:Community, event_name:str, driver:User, location):
    event = {
        'summary': f'{event_name}: {driver.first_name} {driver.last_name}',
        'description': '',
        'start': {
            'dateTime': '2023-10-31T09:00:00-07:00',
            'timeZone': 'America/Chicago',
        },
        'end': {
            'dateTime': '2023-10-31T17:00:00-07:00',
            'timeZone': 'America/Chicago',
        },
        'reminders': {
            'useDefault': False,
            'overrides': [
                {'method': 'email', 'minutes': 24 * 60},
                {'method': 'popup', 'minutes': 30},
            ],
        },
        'visibility': 'public',
        'privateCopy': False,
        'locked': False,
        'anyoneCanAddSelf': True,
    }    
    new_event = service.events().insert(calendarId=f'{comm.calendarId}', body=event).execute()
    
    events = service.events().get(calendarId=f'{comm.calendarId}', eventId=f"{new_event.get('id')}").execute()

    print(events['summary'])

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
    communities = Community.query.all()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        
        community = Community.query.filter_by(name=form.community.data).first()
        
        if not community:
            community = Community(name=form.community.data)
            db.session.add(community)
            create_calendar(community)
        
        new_user = User(username=form.username.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data, can_host=form.can_host.data, community_id=community.id)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form, communities=communities)

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
    cal_id = current_user.get_community_calendar_id()
    cal_url = f"{cal_id[:64]}%40group.calendar.google.com"
    print(cal_url)
    return render_template('dashboard.html', calendar_url=cal_url)

@app.route('/request_carpool')
@login_required
def request():
    comm_id = current_user.community_id
    comm = Community.query.filter_by(id=comm_id).first()
    create_event(comm, "Sussy", current_user, "")
    
    return "sussy bussy"

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# from forms import * # import forms for our register and login pages

if __name__ == '__main__':
    app.run(debug=True)