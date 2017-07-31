# -*- coding:utf-8 -*-
import jwt, datetime, time
from functools import wraps
from flask import current_app, request, jsonify

SECRET_KEY = "Hard To Guess"


def encode_auth_token(user_id, timestamp):
	"""
	生成认证Token
	:param user_id: int
	:param login_time: int(timestamp)
	:return: string
	"""
	try:
		payload = {
			'id': user_id,
			'timestamp': timestamp
		}
		return jwt.encode(
			payload,
			SECRET_KEY,
			algorithm='HS256',
		)
	except Exception as e:
		return e


def decode_auth_token(token):
	"""
	验证Token
	:param auth_token:
	:return: integer|string
	try:
		# payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), leeway=datetime.timedelta(seconds=10))
		# 取消过期时间验证
		payload = jwt.decode(token, SECRET_KEY, options={'verify_exp': False}, algorithms=['HS256'])
		print(payload)
		if 'data' in payload and 'id' in payload.get['data']:
			return payload
		else:
			raise jwt.InvalidTokenError
	except jwt.ExpiredSignatureError:
		return 'Token过期'
	except jwt.InvalidTokenError:
		return '无效Token'
		"""
	payload = jwt.decode(token, SECRET_KEY, options={'verify_exp': False}, algorithms=['HS256'])
	return payload


def user_loader():
	from server.models import User
	token = request.headers.get('token')
	id = decode_auth_token(token).get('id','')
	current_user = User.query.filter_by(id=id).first()
	if current_user:
		return current_user
	return None


def token_required(func):
	@wraps(func)
	def wrapper_func(*args, **kwargs):
		token = request.headers.get('token')
		try:
			data = decode_auth_token(token)
			timestamp = int(data['timestamp'])
			print(timestamp)
			auth_date = datetime.datetime.fromtimestamp(timestamp)
			delta = datetime.datetime.now() - auth_date
			if delta > datetime.timedelta(hours=12):
				return jsonify(status=3)
			return func(*args, **kwargs)
		except Exception as e:
			print(e)
			return jsonify(status=3)
	return wrapper_func




