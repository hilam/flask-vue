# -*- coding:utf-8 -*-
import time
from datetime import datetime, timedelta
from flask import request, jsonify, g
from ..app_factory import db
from ..models import User, RegisterUser
from . import auth_blueprint
from utils.auth_token import token_required, user_loader
from utils.regexp import re_password, re_phone


@auth_blueprint.route('/dispatch_captcha', methods=["POST"])
def dispatch_captcha():
	data = request.get_json()
	phone = data.get('phone', '')

	if not re_phone(phone):
		return jsonify(status=1, message=u"手机号格式错误")

	user = User.query.filter_by(phone=phone).first()
	if user:
		return jsonify(status=1, message=u'此手机号已注册')

	user = RegisterUser.query.filter_by(phone=phone).first()
	if user:
		duration = user.invalid_time - timedelta(minutes=14)
		if duration > datetime.now():
			return jsonify(status=1, message=u"一分钟内只能获取一次验证码")
	if user is None:
		user = RegisterUser(phone=phone)
		db.session.add(user)

	import random
	user.captcha = random.randint(333333, 999999)
	user.invalid_time = datetime.now() + timedelta(minutes=15)

	try:
		db.session.commit()
		return jsonify(status=0)
	except Exception as e:
		print(e)
		db.session.rollback()
		return jsonify(status=1, message=u'系统错误')


@auth_blueprint.route('/register', methods=["POST"])
def confirm_register():
	current_time = datetime.now()
	data = request.get_json()
	phone = data.get('phone', '')
	captcha = data.get('captcha', '')
	password = data.get('password', '')
	print(data)

	'''
	对获取的数据进行校验
	'''
	if not re_password(password):
		return jsonify(status=1, message=u"密码格式错误")

	if not re_phone(phone):
		return jsonify(status=1, message=u"手机号格式错误")

	new_user = User.query.filter_by(phone=phone).first()
	if new_user:
		return jsonify(status=1, message=u"手机号已注册")

	user = RegisterUser.query.filter_by(phone=phone).first()
	if user is None:
		return jsonify(status=1, message=u'手机号不存在')
	if user.invalid_time < current_time:
		return jsonify(status=1, message=u'验证码过期')
	if user.captcha != captcha:
		return jsonify(status=1, message=u'验证码错误')

	try:
		new_user = User(phone=phone, password=password)
		db.session.add(new_user)
		db.session.commit()
		return jsonify(status=0)
	except Exception as e:
		print(e)
		db.session.rollback()
		return jsonify(status=1, message=u"系统错误")


@auth_blueprint.route('/logout', methods=['GET', 'POST'])
@token_required
def logout():
	#todo: 完成用户注销
	pass
	return jsonify(status='0', access_token=g.access_token)


@auth_blueprint.route('/login', methods=['GET', 'POST'])
def login():
	data = request.get_json()
	phone = data.get('phone', '')
	password = data.get('password', '')

	if phone is None or password is None:
		return jsonify(status=1, message=u'请输入帐号和密码')

	'''
	记录用户登录日志
	'''
	from ..models import UserLoginLog

	ip = request.headers.get('X-Real-IP', '')
	log = UserLoginLog(phone=phone, ip=ip)

	try:
		db.session.add(log)
		db.session.commit()
	except Exception as e:
		print(e)
		db.session.rollback()

	user = User.query.filter_by(phone=phone).first()
	if user is not None and user.verify_password(password):

		from utils.auth_token import encode_auth_token

		access_token = encode_auth_token(user.id, user.username, 'access_token')
		refresh_token = encode_auth_token(user.id, user.username, 'refresh_token')
		return jsonify(status=0, access_token=access_token, refresh_token=refresh_token)

	else:
		return jsonify(status=1, message=u'帐号或密码错误')


@auth_blueprint.route('/edit_profile', methods=['POST'])
@token_required
def edit_profile():
	current_user = user_loader()
	data = request.get_json()
	username = data.get('username')
	if username is None:
		return jsonify(status=1, message=u'请输入用户名')
	user = User.query.filter_by(username=username).first()
	if user:
		return jsonify(status=1, message=u"用户名已存在")
	current_user.username = username
	try:
		db.session.add(current_user)
		db.session.commit()
		return jsonify(status=0)
	except Exception as e:
		print(e)
		return jsonify(status=1, message=u'系统错误')


@auth_blueprint.route('/change_password', methods=['POST'])
@token_required
def change_password():
	current_user = user_loader()
	data = request.get_json()
	old_password = data.get('old_password')
	new_password = data.get('new_password')
	if old_password is None or new_password is None:
		return jsonify(status=1, message=u"请输入完整的信息")
	if not re_password(new_password):
		return jsonify(status=1, message=u"密码格式错误")
	if current_user.verify_password(old_password):
		current_user.password = new_password
		try:
			db.session.add(current_user)
			db.session.commit()
			return jsonify(status=0)
		except Exception as e:
			print(e)
			return jsonify(status=1, message=u"系统错误")
	return jsonify(status=1, message=u"密码错误")
