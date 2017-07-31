# -*- coding:utf-8 -*-
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from .app_factory import db


class RegisterUser(db.Model):
	# 用户注册时作用的临时表
	__tablename__ = 'register_users'
	id = db.Column(db.Integer, primary_key=True)
	phone = db.Column(db.String(16), unique=True, index=True)
	captcha = db.Column(db.String(6), default='')
	invalid_time = db.Column(db.DateTime)

	def __init__(self, phone):
		self.phone = phone


class User(UserMixin, db.Model):
	__tablename__ = 'users'
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True, index=True)
	user_role = db.Column(db.String(20), nullable=False, default='USER')  # USER,SELLER,ADMINISTRATOR
	phone = db.Column(db.String(16), unique=True, index=True)
	password_hash = db.Column(db.String(128))
	created_time = db.Column(db.TIMESTAMP, default=db.func.current_timestamp())

	def __init__(self,phone,password):
		self.phone = phone
		self.password = password

	def to_json(self):
		return {
			'username': self.username,
			'phone': self.phone,
		}

	@property
	def password(self):
		raise AttributeError(u'password不可读')

	@password.setter
	def password(self, password):
		self.password_hash = generate_password_hash(password)

	def verify_password(self, password):
		return check_password_hash(self.password_hash, password)


class UserLoginLog(db.Model):
	__tablename__ = 'user_login_log'
	id = db.Column(db.Integer, primary_key=True)
	phone = db.Column(db.String(16), nullable=False)
	username = db.Column(db.String(20))
	ip = db.Column(db.String(20), nullable=False)
	create_time = db.Column(db.TIMESTAMP, nullable=False, default=db.func.current_timestamp())

	def __int__(self, phone, username, ip):
		self.phone = phone,
		self.username = username
		self.ip = ip

	def to_json(self):
		return {
			'username': self.username,
			'phone': self.phone,
			'ip': self.ip
		}