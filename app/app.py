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
from wtforms import StringField, PasswordField, SubmitField, BooleanField, EmailField, SelectField, TimeField, TimeField, DateField
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


class RequestCarpoolForm(FlaskForm):
    def __init__(self, cur_user):
        FlaskForm.__init__(self)
    
    event_name = StringField(validators=[InputRequired(), Length(min=1, max=50)], render_kw={"placeholder": "Event Name"})
        
    driver = SelectField(validators=[InputRequired()], render_kw={"placeholder": "Driver"})
        
    location = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Location"})
    
    start_time = TimeField(validators=[InputRequired()], render_kw={"placeholder": "Start:Time"})
    date = DateField(validators=[InputRequired()])

    is_recurring = BooleanField(label="Weekly recurring: ", default="checked")
        
    submit = SubmitField('Register')
        
# endregion

# region Google api ########

import datetime as dt
import os

from google.auth.transport.requests import Request
from google.oauth2.service_account import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/calendar.readonly'
          
          'https://www.googleapis.com/auth/chat.spaces',
          'https://www.googleapis.com/auth/chat.import']

cred = Credentials.from_service_account_file('service_account_cred.json', scopes=SCOPES)

service = build('calendar', 'v3', credentials=cred)
chat_space_creator_service = build('chat', 'v1', credentials=cred)

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

def create_chat_space(comm:Community):
    new_space = chat_space_creator_service.spaces().create(
        body={
            'spaceType': "SPACE",
            'displayName': f'{comm.name} Chat'
        }
    ).execute()
    
def add_user_to_chat_space(user:User):
    new_user = chat_space_creator_service.spaces().members().create(
        parent="space/",
        body={
            'member': {
                'name': 'users/',
                'type': 'HUMAN'
            }
            
        }
    )

def create_event(comm:Community, event_name:str, driver:User, start_time, date, location, weekly_recurring:bool):
    time = dt.datetime(date.year, date.month, date.day, start_time.hour, start_time.minute)
    end_time = time + dt.timedelta(minutes=30)
    print(time)
    
    event = {
        'summary': f'{event_name}: {driver.username}',
        'start': {
            'dateTime': time.isoformat(),
            'timeZone': 'America/Chicago'
        },
        'end': {
            'dateTime': end_time.isoformat(),
            'timeZone': 'America/Chicago'
        },
        'recurrence': [
            'RRULE:FREQ=WEEKLY'
        ],
        'location': location,
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
    if not weekly_recurring:
        event["recurrence"] = []
        
    new_event = service.events().insert(calendarId=f'{comm.calendarId}', body=event).execute()
    
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

@app.route('/logout')
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

@app.route('/request_carpool', methods=['GET', 'POST'])
@login_required
def request_carpool():
    form = RequestCarpoolForm(current_user)
    
    drivers = User.query.filter_by(community_id=current_user.community_id).all()
    community_members = [f'{d.username}' for d in drivers]
    
    form.driver.choices = community_members
    
    if form.validate_on_submit():
        comm_id = current_user.community_id
        comm = Community.query.filter_by(id=comm_id).first()
        print(type(form.date.data))
        create_event(comm, form.event_name.data, User.query.filter_by(username=form.driver.data).first(), form.start_time.data, form.date.data, form.location.data, form.is_recurring.data)
        return redirect(url_for('home'))

    return render_template('request_carpool.html', form=form)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

# from forms import * # import forms for our register and login pages
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')


@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    user = current_user

    user.first_name = request.form.get('first_name')
    user.last_name = request.form.get('last_name')
    user.username = request.form.get('username')

    new_password = request.form.get('password')
    if new_password:
        user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    new_community_name = request.form.get('community')
    if new_community_name != user.community.name:
        community = Community.query.filter_by(name=new_community_name).first()
        if not community:
            community = Community(name=new_community_name)
            db.session.add(community)
            create_calendar(community)
        user.community = community

    db.session.commit()

    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)
    
