from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
db = SQLAlchemy()

# MySQL database URL
database_url = 'mysql://root:password@localhost/hospital_ecg'
app.config['SQLALCHEMY_DATABASE_URI'] = database_url
# Initialize SQLAlchemy
db.init_app(app)
