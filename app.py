from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, SelectField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from classes import *
from globals import *

# Connect to the database
engine = create_engine(database_url)

# Test the connection
connection = engine.connect()

# Create database tables
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')


# Register class
class RegisterForm(Form):
    name = StringField('Ім\'я', [validators.Length(min=1, max=40)])
    surname = StringField('Прізвище', [validators.Length(min=4, max=50)])
    patronymic = StringField('По батькові', [validators.Length(min=4, max=40)])
    gender_choices = [('MALE', 'чоловік'), ('FEMALE', 'жінка')]  # Enum of male or female
    gender = SelectField('Стать', choices=gender_choices)
    email = StringField('Електронна пошта', [validators.Length(min=6, max=255)])
    phone_number = StringField('Номер телефону', [validators.Length(min=6, max=20)])
    password = PasswordField('Пароль', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message="Password do not match"),
    ])
    confirm = PasswordField("Підтвердити пароль")


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        surname = form.surname.data
        patronymic = form.patronymic.data
        gender = form.gender.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data)
        phone_number = form.phone_number.data

        # Check if email already exists in 'user', 'doctor', or 'admin' tables
        if User.query.filter_by(email=email).first() or Doctor.query.filter_by(email=email).first() or Admin.query.filter_by(email=email).first():
            flash('This email is already taken', 'danger')
            return render_template('register.html', form=form)

        # Create a new User object
        new_user = User(name=name, surname=surname, patronymic=patronymic, gender=gender, email=email, password=password, phone_number=phone_number)

        # Add the new user to the session
        db.session.add(new_user)

        # Commit changes to the database
        db.session.commit()

        flash('You are now registered and can log in', 'success')
        return redirect(url_for('index'))

    return render_template('register.html', form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        # Get Form Fields
        email = request.form['email']
        password_candidate = request.form['password']

        # Check if email exists in 'user' table
        user = User.query.filter_by(email=email).first()
        if user:
            role = 'user'
        else:
            # Check if email exists in 'doctor' table
            doctor = Doctor.query.filter_by(email=email).first()
            if doctor:
                role = 'doctor'
            else:
                # Check if email exists in 'admin' table
                admin = Admin.query.filter_by(email=email).first()
                if admin:
                    role = 'admin'
                else:
                    # Email not found in any table
                    error = 'Уведена електронна пошта не знайдена'
                    return render_template('login.html', error=error)

        # Based on the role, check password and set session role
        if role == 'user':
            user_obj = user
        elif role == 'doctor':
            user_obj = doctor
        else:
            user_obj = admin

        # Get stored hash
        password_hash = user_obj.password

        # Compare Password
        if sha256_crypt.verify(password_candidate, password_hash):
            # Passed
            session['logged_in'] = True
            session['user_id'] = user_obj.id
            session['role'] = role

            flash('Ви увійшли', 'success')
            return redirect(url_for('dashboard'))
        else:
            error = 'Неправильний пароль'
            return render_template('login.html', error=error)

    return render_template('login.html')


# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Ви не увійшли, будь ласка, увійдіть', 'danger')
            return redirect(url_for('login'))

    return wrap


# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash("Ви вийшли", 'success')
    return redirect(url_for('login'))


@app.route('/dashboard')
@is_logged_in
def dashboard():
    # Query appointments for the current user
    appointments = Appointment.query.filter_by(user_id=session['user_id']).all()

    if appointments:
        return render_template("dashboard.html", appointments=appointments)
    else:
        msg = 'У вас ще не було записів до лікарів'
        return render_template("dashboard.html", msg=msg)

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(host='0.0.0.0', debug=True)