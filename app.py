from flask import Flask, render_template, flash, redirect, url_for, session, request, logging
from flask_sqlalchemy import SQLAlchemy
from wtforms import Form, StringField, SelectField, DateTimeField, PasswordField, validators
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


# Register User
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
    # hospitals = Hospital.query.filter_by(id=appointments.hospital_id).all()
    # doctors = Doctor.query.filter_by(id=appointments.doctor_id).all()
    if appointments:
        return render_template("dashboard.html", appointments=appointments)
    else:
        msg = 'У вас ще не було записів до лікарів'
        return render_template("dashboard.html", msg=msg)


@app.route('/users')
@is_logged_in
def users():
    if session['role'] == 'admin':
        users_list = User.query.all()
        doctors = Doctor.query.all()
        admins = Admin.query.all()
        hospitals_list = Hospital.query.all()
        return render_template("users.html", users=users_list, doctors=doctors, admins=admins, hospitals=hospitals_list)
    else:
        return redirect(url_for('dashboard'))


@app.route('/confirm_delete_user/<id>', methods=['POST'])
def confirm_delete_user(id):
    if request.method == 'POST':
        admin_obj = Admin.query.filter_by(id=session['user_id']).first()
        # Get stored hash
        password_hash = admin_obj.password
        # Verify password here
        password = request.form.get('password')
        if sha256_crypt.verify(password, password_hash):
            user = User.query.get(id)
            if user:
                db.session.delete(user)
                db.session.commit()
            return redirect(url_for('users'))
        else:
            flash('Неправильний пароль. Видалення скасовано.')
            return redirect(url_for('users'))


@app.route('/confirm_delete_doctor/<id>', methods=['POST'])
def confirm_delete_doctor(id):
    if request.method == 'POST':
        admin_obj = Admin.query.filter_by(id=session['user_id']).first()
        # Get stored hash
        password_hash = admin_obj.password
        # Verify password here
        password = request.form.get('password')
        if sha256_crypt.verify(password, password_hash):
            doctor = Doctor.query.get(id)
            if doctor:
                db.session.delete(doctor)
                db.session.commit()
            return redirect(url_for('users'))
        else:
            flash('Неправильний пароль. Видалення скасовано.')
            return redirect(url_for('users'))


@app.route('/promote_to_doctor/<id>', methods=['POST'])
def promote_to_doctor(id):
    if request.method == 'POST':
        user = User.query.get(id)
        if user:
            # Get the selected hospital from the form
            hospital_id = request.form.get('hospital_id')
            hospital = Hospital.query.get(hospital_id)

            # Create a new Doctor object using the user's data and assign the hospital
            doctor = Doctor(
                name=user.name,
                surname=user.surname,
                patronymic=user.patronymic,
                gender=user.gender,
                email=user.email,
                phone_number=user.phone_number,
                password=user.password,
                hospital=hospital  # Assign the hospital
            )
            db.session.add(doctor)
            db.session.delete(user)  # Remove the user
            db.session.commit()
        return redirect(url_for('users'))
    else:
        flash('Неправильний пароль. Операцію відмінено.')
        return redirect(url_for('users'))


@app.route('/demote_to_user/<id>', methods=['POST'])
def demote_to_user(id):
    if request.method == 'POST':
        admin_obj = Admin.query.filter_by(id=session['user_id']).first()
        password_hash = admin_obj.password
        password = request.form.get('password')
        if sha256_crypt.verify(password, password_hash):
            doctor = Doctor.query.get(id)
            if doctor:
                # Create a new User object using the doctor's data
                user = User(
                    name=doctor.name,
                    surname=doctor.surname,
                    patronymic=doctor.patronymic,
                    gender=doctor.gender,
                    email=doctor.email,
                    phone_number=doctor.phone_number,
                    password=doctor.password
                )
                db.session.add(user)
                db.session.delete(doctor)  # Remove the doctor
                db.session.commit()
            return redirect(url_for('users'))
        else:
            flash('Неправильний пароль. Операцію відмінено.')
            return redirect(url_for('users'))


@app.route('/hospitals', methods=['GET'])
def hospitals():
    search_query = request.args.get('search')
    if search_query:
        hospitals = Hospital.query.filter(Hospital.name.contains(search_query)).all()
        if hospitals:
            return render_template('hospitals.html', hospitals=hospitals)
        else:
            return render_template('hospitals.html', msg='Лікарень не знайдено')
    else:
        hospitals = Hospital.query.all()
        return render_template('hospitals.html', hospitals=hospitals)


class AddHospitalForm(Form):
    name = StringField('Назва', [validators.Length(min=1, max=150)])
    location = StringField('Адреса', [validators.Length(min=1, max=255)])
    contact_number = StringField('Номер телефону', [validators.Length(min=1, max=20)])


@app.route('/add_hospital', methods=['GET', 'POST'])
@is_logged_in
def add_hospital():
    if session['role'] == 'admin':
        form = AddHospitalForm(request.form)
        if request.method == 'POST' and form.validate():
            name = form.name.data
            location = form.location.data
            contact_number = form.contact_number.data
            new_hospital = Hospital(name=name, location=location, contact_number=contact_number)
            db.session.add(new_hospital)
            db.session.commit()
            flash('Лікарня додана', 'success')
            return redirect(url_for('hospitals'))
        return render_template('add_hospital.html', form=form)
    else:
        return redirect(url_for('hospitals'))


@app.route('/delete_hospital/<id>', methods=['POST'])
def delete_hospital(id):
    hospital = Hospital.query.get(id)
    if hospital:
        db.session.delete(hospital)
        db.session.commit()
    return redirect(url_for('hospitals'))


@app.route('/confirm_delete_hospital/<id>', methods=['POST'])
def confirm_delete_hospital(id):
    if request.method == 'POST':
        admin_obj = Admin.query.filter_by(id=session['user_id']).first()
        # Get stored hash
        password_hash = admin_obj.password
        # Verify password here
        password = request.form.get('password')
        if sha256_crypt.verify(password, password_hash):
            hospital = Hospital.query.get(id)
            if hospital:
                db.session.delete(hospital)
                db.session.commit()
            return redirect(url_for('hospitals'))
        else:
            flash('Неправильний пароль. Видалення скасовано.')
            return redirect(url_for('hospitals'))


# profile page
@app.route('/profile')
@is_logged_in
def profile():
    if session['role'] == 'user':
        user = User.query.filter_by(id=session['user_id']).first()
        return render_template('profile.html', user=user, Gender=Gender)
    elif session['role'] == 'doctor':
        doctor = Doctor.query.filter_by(id=session['user_id']).first()
        hospital = Hospital.query.filter_by(id=doctor.hospital_id).first()
        hospital_name = hospital.name if hospital else None
        return render_template('profile.html', user=doctor, Gender=Gender, hospital_name=hospital_name)
    else:
        admin = Admin.query.filter_by(id=session['user_id']).first()
        return render_template('profile.html', user=admin, Gender=Gender)


@app.route('/update_profile', methods=['POST'])
@is_logged_in
def update_profile():
    user_id = session['user_id']
    user_role = session['role']

    if user_role == 'user':
        user = User.query.filter_by(id=user_id).first()
    elif user_role == 'doctor':
        user = Doctor.query.filter_by(id=user_id).first()
    else:
        user = Admin.query.filter_by(id=user_id).first()

    if user:
        # Get the data from the form
        user.name = request.form['name']
        user.surname = request.form['surname']
        user.patronymic = request.form['patronymic']
        user.gender = request.form['gender']
        user.phone_number = request.form['phone_number']
        new_email = request.form['email']

        # Check if the new email is not taken yet
        if user.email != new_email and (User.query.filter_by(email=new_email).first() or Doctor.query.filter_by(email=new_email).first() or Admin.query.filter_by(email=new_email).first()):
            flash('Email is already taken. Please choose a different one.', 'danger')
            return redirect(url_for('profile'))

        user.email = new_email
        db.session.commit()
        flash('Профіль успішно оновлений', 'success')
    else:
        flash('Користувач не знайдений', 'danger')

    return redirect(url_for('profile'))


@app.route('/change_password', methods=['POST'])
@is_logged_in
def change_password():
    user_id = session['user_id']
    user_role = session['role']

    if user_role == 'user':
        user = User.query.filter_by(id=user_id).first()
    elif user_role == 'doctor':
        user = Doctor.query.filter_by(id=user_id).first()
    else:
        user = Admin.query.filter_by(id=user_id).first()

    if user:
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        # Check if current password matches
        if not sha256_crypt.verify(current_password, user.password):
            flash('Неправильний поточний пароль.', 'danger')
            return redirect(url_for('profile'))

        # Check if new password and confirm password match
        if new_password != confirm_password:
            flash('Новий пароль і підтвердження пароля не співпадають.', 'danger')
            return redirect(url_for('profile'))

        # Update the password
        user.password = sha256_crypt.encrypt(new_password)
        db.session.commit()
        flash('Пароль змінено успішно.', 'success')
    else:
        flash('Користувач не знайдений.', 'danger')

    return redirect(url_for('profile'))


# Add appointment route
@app.route('/add_appointment', methods=['GET', 'POST'])
@is_logged_in
def add_appointment():
    search_query = request.args.get('search')
    doctors = Doctor.query.all()
    if search_query:
        hospitals = Hospital.query.filter(Hospital.name.contains(search_query)).all()
        if hospitals:
            return render_template('add_appointment.html', hospitals=hospitals, doctors=doctors)
        else:
            return render_template('add_appointment.html', msg='Лікарень не знайдено')
    else:
        hospitals = Hospital.query.all()
        return render_template('add_appointment.html', hospitals=hospitals, doctors=doctors)


@app.route('/choose_hospital/<id>', methods=['POST'])
def choose_hospital(id):
    if request.method == 'POST':
        hospital = Hospital.query.get(id)
        if hospital:
            # Get the selected hospital from the form
            doctor_id = request.form.get('doctor_id')
            doctor = Doctor.query.get(doctor_id)

            # Create a new Appointment object using the user's data and assign the hospital
            appointment = Appointment(
                location=hospital.location,
                date_time=None,
                status='В очікуванні',
                doctor_id=doctor.id,
                user_id=session['user_id'],
                ecg_id=None
            )

            db.session.add(appointment)
            db.session.commit()
        return redirect(url_for('dashboard'))


# specific appointment route
@app.route('/appointment/<id>')
@is_logged_in
def appointment(id):
    appointment = Appointment.query.filter_by(id=id).first()
    if appointment:
        doctor = Doctor.query.filter_by(id=appointment.doctor_id).first()
        return render_template('appointment.html', appointment=appointment, doctor=doctor)
    else:
        return redirect(url_for('dashboard'))


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(host='0.0.0.0', debug=True)