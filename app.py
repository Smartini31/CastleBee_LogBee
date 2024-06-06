import os
from flask import Flask, render_template, render_template_string, flash, redirect, url_for, session, request, logging, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from flask_mail import Mail, Message
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField, SubmitField
from wtforms.fields import DateField,DateTimeField, DateTimeLocalField
from wtforms.validators import DataRequired, Length, EqualTo, Email
from passlib.hash import sha256_crypt
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from functools import wraps
from datetime import datetime
from templates.auth.rest_password_email_content import (reset_password_email_html_content)
from templates.auth.notification_email_content import (notification_email_html_content)
from templates.auth.answer_email_content import (answer_email_content)

#Access Environment Variables
secret_key = os.getenv("SECRET_KEY")
sqlalchemy_database_uri = os.getenv('SQLALCHEMY_DATABASE_URI')
mail_server = os.getenv('MAIL_SERVER')
mail_port = os.getenv('MAIL_PORT')
mail_username = os.getenv('MAIL_USERNAME')
mail_password = os.getenv('MAIL_PASSWORD')
mail_use_tls = os.getenv('MAIL_USE_TLS')
mail_use_ssl = os.getenv('MAIL_USE_SSL')
admin_mail = os.getenv('ADMIN_MAIL')

#Config
app = Flask(__name__)
app.config['SECRET_KEY']= secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = sqlalchemy_database_uri
app.config['MAIL_SERVER']= mail_server
app.config['MAIL_PORT'] = int(mail_port)
app.config['MAIL_USERNAME'] = mail_username
app.config['MAIL_PASSWORD'] = mail_password
app.config['MAIL_USE_TLS'] = bool(int(mail_use_tls))
app.config['MAIL_USE_SSL'] = bool(int(mail_use_ssl))
mail = Mail(app)

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    is_admin = db.Column(db.Boolean, nullable=False)

    @staticmethod
    def validate_reset_password_token(token: str, user_id: int):
        user = db.session.get(User, user_id)

        if user is None:
            return None

        serializer = URLSafeTimedSerializer(secret_key)
        try:
            token_user_email = serializer.loads(
                token,
                max_age=3600,
                salt=user.password,
            )
        except (BadSignature, SignatureExpired):
            return None

        if token_user_email != user.email:
            return None

        return user
    
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(100), nullable=False)
    start = db.Column(db.DateTime, nullable=False)
    end = db.Column(db.DateTime, nullable=False)
    is_processed = db.Column(db.Boolean, nullable=False)
    is_valid = db.Column(db.Boolean, nullable=False)
    user = db.Column(db.String(130), nullable=False)

# Automatically create the database tables if they don't exist
with app.app_context():
    db.create_all()

# Register Form Classes
class RegisterForm(FlaskForm):
    email = StringField('E-mail', [validators.Length(min=6, max=50)])
    password = PasswordField('Mot de passe', [
        validators.DataRequired(),
        validators.EqualTo('Confirmer', message='Les mots de passe ne correspondent pas')
    ])
    confirm = PasswordField('Confirmer le mot de passe')

#Event Form
class EventForm(FlaskForm):
    title = StringField('Titre', [Length(min=1, max=200)])
    type = SelectField('Type', choices=["Heures supplémentaires", "Congés payés", "Arrêt maladie et congés payés annuels", "Jours fériés et ponts", "Réduction du temps de travail (RTT)", "Congés sans solde", "Congé maternité", "Congé de paternité et d'accueil de l'enfant", "Congé en cas d'hospitalisation immédiate de l'enfant après sa naissance", "Congé d'adoption", "Congé de 3 jours pour naissance ou adoption", "Congé parental à temps plein", "Congé pour enfant malade", "Congé de présence parentale", "Congé de proche aidant", "Congé de solidarité familiale", "Allocation journalière d'accompagnement d'une personne en fin de vie", "Survenue du handicap d'un enfant", "Don de jours de repos pour enfant gravement malade", "Don de jours de repos à un salarié dont l'enfant est décédé", "Création ou reprise d'entreprise", "Exercice d'un mandat politique local", "Mariage ou Pacs", "Mariage de son enfant", "Décès d'un membre de sa famille", "Congé sabbatique"])
    start_datetime = DateTimeLocalField('Date de début',
                                        format='%Y-%m-%dT%H:%M',
                                        validators=[DataRequired()])
    end_datetime = DateTimeLocalField('Date de fin',
                                      format='%Y-%m-%dT%H:%M',
                                      validators=[DataRequired()])

    def validate(self, **kwargs):
        # Standard validation
        rv = FlaskForm.validate(self)
        # Ensure start date/time is before end date/time
        if rv:
            if self.start_datetime.data >= self.end_datetime.data:
                self.start_datetime.errors.append("La date de début doit etre anterieure a la date de fin")
                return False
            return True

        return False

#PasswordReset Form
class PassResetForm(FlaskForm):
    email = StringField("E-mail", validators=[DataRequired()])

class NewPasswordForm(FlaskForm):
    password = PasswordField("Nouveau mot de passe", validators=[DataRequired()])
    password2 = PasswordField("Nouveau mot de passe", validators=[DataRequired(), EqualTo("password")])
    
class UserSelectionForm(FlaskForm):
    user_id = SelectField('Select User', coerce=int, validators=[DataRequired()])

@app.route('/')
def index():
    return render_template('home.html')


@app.route('/password', methods=['GET', 'POST'])
def password():
    form = PassResetForm()
    if form.validate_on_submit():
        email = form.email.data

        # check if someone already register with the email
        user = User.query.filter_by(email=email).first()
        print(user)
        if user:
            send_reset_password_email(user)
            flash("User exists")
        else:
            flash("User does not exist")
        
        return redirect(url_for('login'))
        

    return render_template('password.html', form=form)

@app.route("/reset_password/<token>/<int:user_id>", methods=["GET", "POST"])
def reset_password(token, user_id):

    user = User.validate_reset_password_token(token, user_id)
    if not user:
        return render_template("reset_password_error.html", title="Reset Password error")

    form = NewPasswordForm()
    if form.validate_on_submit():
        new_password = sha256_crypt.encrypt(str(form.password.data))
        user.password = new_password
        db.session.commit()
        flash('You have successfully updated your password')
        #return render_template("reset_password_success.html", title="Reset Password success")

    return render_template("reset_password.html", title="Reset Password", form=form)

# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        #Check if email is admin email to create the admin account
        if email == admin_mail:
            is_admin = True
        else:
            is_admin = False

        new_user = User(email=email, password=password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


# User login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user:
            password = user.password
            if sha256_crypt.verify(password_candidate, password):
                session['logged_in'] = True
                session['email'] = email
                if user.is_admin == True:
                    session['is_admin'] = True
                    flash('You are now logged in as admin', 'success')
                    return redirect(url_for('admin_dashboard'))
                else:
                    flash('You are now logged in', 'success')
                    return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session and 'is_admin' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, admin access required', 'danger')
            return redirect(url_for('login'))
    return wrap

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/admin_dashboard', methods=['GET', 'POST'])
@admin_required
def admin_dashboard():
    form = UserSelectionForm()
    all_users = User.query.all()
    user_choices = [(user.id, user.email) for user in all_users]

    form.user_id.choices = user_choices
    selected_user_id = request.args.get('user_id', type=int)

    if selected_user_id:
        selected_user_email = User.query.filter_by(id=selected_user_id).first()
        calendar = Event.query.filter_by(user=selected_user_email.email, is_valid=True).all()
    else:
        calendar = Event.query.filter_by(user=session['email'], is_valid=True).all()

    return render_template('admin_dashboard.html', calendar=calendar, form=form)

# Dashboard
@app.route('/dashboard')
@is_logged_in
def dashboard():
    user = User.query.filter_by(email=session['email']).first()

    if user:
        calendar = Event.query.filter_by(user=session['email'], is_valid=True).all()
        list = Event.query.filter_by(user=session['email']).all()

        if calendar:
            return render_template('dashboard.html', calendar=calendar, list=list)
        else:
            msg = 'No Events Created'
            return render_template('dashboard.html', msg=msg)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('login'))

#Admin
@app.route('/admin')
@admin_required
def admin():
    user = User.query.filter_by(email=session['email']).first()

    if user:
        calendar = Event.query.all()

        if calendar:
            return render_template('admin.html', calendar=calendar)
        else:
            msg = 'No Events or Supps to Process'
            return render_template('admin.html', msg=msg)
    else:
        flash('User not found', 'danger')
        return redirect(url_for('login'))


#Add Conges
@app.route('/add_events', methods=['GET', 'POST'])
@is_logged_in
def add_events():
    form = EventForm()
    if form.validate_on_submit():
        title = form.title.data
        type = form.type.data
        start = form.start_datetime.data
        end = form.end_datetime.data
        is_processed = False
        is_valid = False

        new_event = Event(title=title, type=type, start=start, end=end, is_processed=is_processed, is_valid=is_valid, user=session['email'])
        db.session.add(new_event)
        db.session.commit()

        user = User.query.filter_by(email=session['email']).first()
        email = user.email
        send_notification_email(email, title, type, start, end)

        flash('Event Created', 'success')
        return redirect(url_for('dashboard'))
    return render_template('add_events.html', form=form)

@app.route('/accept_event/<int:event_id>', methods=['POST'])
@admin_required  # Ensure only admin can access this route
def accept_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        event.is_valid = True
        event.is_processed = True
        db.session.commit()
        flash('Event accepted', 'success')
        send_event_answer_email(event.user, event.title, event.type, event.start, event.end, 'accepté')
    else:
        flash('Invalid event or already processed', 'danger')
    return redirect(url_for('admin'))

@app.route('/reject_event/<int:event_id>', methods=['POST'])
@admin_required  # Ensure only admin can access this route
def reject_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        event.is_valid = False
        event.is_processed = True
        db.session.commit()
        flash('Event rejected', 'success')
        send_event_answer_email(event.user, event.title, event.type, event.start, event.end, 'refusé')
    else:
        flash('Invalid event or already processed', 'danger')
    return redirect(url_for('admin'))

@app.route('/remove_event/<int:event_id>', methods=['POST'])
@is_logged_in
def remove_event(event_id):
    event = Event.query.get(event_id)
    if event and not event.is_processed:
        db.session.delete(event)
        db.session.commit()
        flash('Event deleted', 'success')
    calendar = Event.query.filter_by(user=session['email']).all()

    events = []
    if calendar:
        for event in calendar:
            event_data = {
                'start': event.start.strftime('%Y-%m-%dT%H:%M:%S'),
                'end': event.end.strftime('%Y-%m-%dT%H:%M:%S'),
                'type': event.type,
                'title': event.title,
                'id': event.id,
                'backgroundColor': '#f56954'
            }
            events.append(event_data)

    return jsonify(events)

# Insert event
@app.route('/insert_event', methods=['POST'])
def insert_event():
    if request.method == 'POST':
        title = request.form['title']
        start = request.form['start']
        end = request.form['end']

        new_event = Event(title=title, start=start, end=end, user=session['email'])
        db.session.add(new_event)
        db.session.commit()

        return jsonify({'status': 'success'})

# Update event
@app.route('/update_event', methods=['POST'])
def update_event():
    if request.method == 'POST':
        title = request.form['title']
        start = request.form['start']
        end = request.form['end']
        event_id = request.form['id']

        event = Event.query.get(event_id)
        if event:
            event.title = title
            event.start = start
            event.end = end
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})

# Delete event
@app.route('/delete_event', methods=['POST'])
def delete_event():
    if request.method == 'POST':
        event_id = request.form['id']

        event = Event.query.get(event_id)
        if event:
            db.session.delete(event)
            db.session.commit()
            return jsonify({'status': 'success'})
        else:
            return jsonify({'status': 'error'})

def send_reset_password_email(user):
    reset_password_url = url_for("reset_password", token=generate_reset_password_token(user), user_id=user.id)
    
    email_body = render_template_string(reset_password_email_html_content, reset_password_url=reset_password_url)

    msg = Message(subject="Réinitialisation du mot de passe",recipients = [user.email], sender=mail_username)
    msg.html = email_body

    mail.send(msg)
    print("E-mail envoyé")

def send_notification_email(user_email, title, type, start, end):
    email_body = render_template_string(notification_email_html_content, user_email=user_email, event_title=title, event_type=type, event_start=start, event_end=end)
    stripped_mail = cut_email(user_email)

    msg= Message(subject=f"Nouvelle demande de { stripped_mail }", recipients= [user_email], sender=mail_username)
    msg.html = email_body

    mail.send(msg)
    print("E-mail envoyé")

def send_event_answer_email(user_email, title, type, start, end, answer):
    email_body = render_template_string(answer_email_content, user_email=user_email, event_title=title, event_type=type, event_start=start, event_end=end, answer=answer)

    msg = Message(subject= "Mise à jour de votre CRA", recipients= [user_email], sender=mail_username)
    msg.html = email_body
    mail.send(msg)

def cut_email(email):
    sep = '@'
    stripped = email.split(sep, 1)[0]
    
    return stripped

def generate_reset_password_token(user):
    #Changer ici pour ne pas avoir la cle secrete dans le code quand ca bougera dans les configs
    serializer = URLSafeTimedSerializer(secret_key)

    return serializer.dumps(user.email, salt=user.password)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(host='0.0.0.0', debug=True)
