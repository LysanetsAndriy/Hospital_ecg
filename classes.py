from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime
from globals import *
from enum import Enum


class Gender(Enum):
    MALE = 'чоловік'
    FEMALE = 'жінка'


class Admin(db.Model):
    __tablename__ = 'admin'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String(40), nullable=True)
    surname = db.Column('Surname', db.String(50), nullable=True)
    patronymic = db.Column('Patronymic', db.String(40), nullable=True)
    gender = db.Column('Gender', db.Enum(Gender), nullable=True)
    email = db.Column('Email', db.String(255), nullable=True)
    password = db.Column('Password', db.String(255), nullable=True)
    phone_number = db.Column('PhoneNumber', db.String(20), nullable=True)

    def __init__(self, name, surname, patronymic, gender, email, password, phone_number):
        self.name = name
        self.surname = surname
        self.patronymic = patronymic
        self.gender = gender
        self.email = email
        self.password = password
        self.phone_number = phone_number

    def __repr__(self):
        return '<Admin %r>' % self.name


class Hospital(db.Model):
    __tablename__ = 'hospital'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String(255), nullable=True)
    location = db.Column('Location', db.String(255), nullable=True)
    contact_number = db.Column('ContactNumber', db.String(20), nullable=True)

    def __init__(self, name, location, contact_number):
        self.name = name
        self.location = location
        self.contact_number = contact_number

    def __repr__(self):
        return '<Hospital %r>' % self.name


class Doctor(db.Model):
    __tablename__ = 'doctor'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String(40), nullable=True)
    surname = db.Column('Surname', db.String(50), nullable=True)
    patronymic = db.Column('Patronymic', db.String(40), nullable=True)
    gender = db.Column('Gender', db.Enum(Gender), nullable=True)
    email = db.Column('Email', db.String(255), nullable=True)
    password = db.Column('Password', db.String(255), nullable=True)
    phone_number = db.Column('PhoneNumber', db.String(20), nullable=True)
    hospital_id = db.Column('hospital_ID', db.Integer, db.ForeignKey('hospital_ecg.hospital.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)
    hospital = db.relationship('Hospital', backref=db.backref('doctors', lazy=True))

    def __init__(self, name, surname, patronymic, gender, email, password, phone_number, hospital):
        self.name = name
        self.surname = surname
        self.patronymic = patronymic
        self.gender = gender
        self.email = email
        self.password = password
        self.phone_number = phone_number
        self.hospital = hospital

    def __repr__(self):
        return '<Doctor %r>' % self.name


class User(db.Model):
    __tablename__ = 'user'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    name = db.Column('Name', db.String(40), nullable=True)
    surname = db.Column('Surname', db.String(50), nullable=True)
    patronymic = db.Column('Patronymic', db.String(40), nullable=True)
    gender = db.Column('Gender', db.Enum(Gender), nullable=True)
    email = db.Column('Email', db.String(255), nullable=True)
    password = db.Column('Password', db.String(255), nullable=True)
    phone_number = db.Column('PhoneNumber', db.String(20), nullable=True)

    def __init__(self, name, surname, patronymic, gender, email, password, phone_number):
        self.name = name
        self.surname = surname
        self.patronymic = patronymic
        self.gender = gender
        self.email = email
        self.password = password
        self.phone_number = phone_number

    def __repr__(self):
        return '<User %r>' % self.name


class ECG(db.Model):
    __tablename__ = 'ecg'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    ecg_file = db.Column('ECGFile', db.String(255), nullable=True)
    datetime = db.Column('DateTime', db.DateTime, nullable=True)
    results = db.Column('Results', db.String(255), nullable=True)
    doctor_id = db.Column('doctor_ID', db.Integer, db.ForeignKey('hospital_ecg.doctor.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)
    user_id = db.Column('user_ID', db.Integer, db.ForeignKey('hospital_ecg.user.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)

    doctor = db.relationship('Doctor', backref=db.backref('ecgs', lazy=True))
    user = db.relationship('User', backref=db.backref('ecgs', lazy=True))

    def __init__(self, ecg_file, datetime, results, doctor, user):
        self.ecg_file = ecg_file
        self.datetime = datetime
        self.results = results
        self.doctor = doctor
        self.user = user

    def __repr__(self):
        return '<ECG %r>' % self.id


class Appointment(db.Model):
    __tablename__ = 'appointment'
    __table_args__ = {'schema': 'hospital_ecg'}

    id = db.Column('ID', db.Integer, primary_key=True)
    location = db.Column('Location', db.String(255), nullable=True)
    date_time = db.Column('DateTime', db.DateTime, nullable=True)
    status = db.Column('Status', db.String(20), nullable=True)
    doctor_id = db.Column('doctor_ID', db.Integer, db.ForeignKey('hospital_ecg.doctor.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)
    user_id = db.Column('user_ID', db.Integer, db.ForeignKey('hospital_ecg.user.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)
    ecg_id = db.Column('ecg_ID', db.Integer, db.ForeignKey('hospital_ecg.ecg.ID', ondelete='NO ACTION', onupdate='NO ACTION'), nullable=False)

    doctor = db.relationship('Doctor', backref=db.backref('appointments', lazy=True))
    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    ecg = db.relationship('ECG', backref=db.backref('appointments', lazy=True))

    def __init__(self, location, date_time, status, doctor_id, user_id, ecg_id):
        self.location = location
        self.date_time = date_time
        self.status = status
        self.doctor_id = doctor_id
        self.user_id = user_id
        self.ecg_id = ecg_id

    def __repr__(self):
        return '<Appointment %r>' % self.id


class AdminHasUser(db.Model):
    __tablename__ = 'admin_has_user'
    __table_args__ = {'schema': 'hospital_ecg'}

    admin_id = db.Column('admin_ID', db.Integer, db.ForeignKey('hospital_ecg.admin.ID', ondelete='NO ACTION', onupdate='NO ACTION'), primary_key=True)
    user_id = db.Column('user_ID', db.Integer, db.ForeignKey('hospital_ecg.user.ID', ondelete='NO ACTION', onupdate='NO ACTION'), primary_key=True)

    admin = db.relationship('Admin', backref=db.backref('user_relations', lazy=True))
    user = db.relationship('User', backref=db.backref('admin_relations', lazy=True))


class AdminHasHospital(db.Model):
    __tablename__ = 'admin_has_hospital'
    __table_args__ = {'schema': 'hospital_ecg'}

    admin_id = db.Column('admin_ID', db.Integer, db.ForeignKey('hospital_ecg.admin.ID', ondelete='NO ACTION', onupdate='NO ACTION'), primary_key=True)
    hospital_id = db.Column('hospital_ID', db.Integer, db.ForeignKey('hospital_ecg.hospital.ID', ondelete='NO ACTION', onupdate='NO ACTION'), primary_key=True)

    admin = db.relationship('Admin', backref=db.backref('hospital_relations', lazy=True))
    hospital = db.relationship('Hospital', backref=db.backref('admin_relations', lazy=True))
