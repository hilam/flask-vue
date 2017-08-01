# -*- coding:utf-8 -*-
import jwt, datetime, time
from functools import wraps
from flask import current_app, request, jsonify, g
from manage import app


def encode_auth_token(user_id, username, token_name='access_token'):
	"""
	生成认证Token
	"""
	delta = datetime.timedelta(days=30) \
		if token_name == 'refresh_token' else datetime.timedelta(minutes=5)
	exp_time = datetime.datetime.utcnow() + delta

	try:
		payload = {
			'exp': exp_time,
			'data': {
				'token_name': token_name,
				'id': user_id,
				'username': username
			}
		}
		return jwt.encode(
			payload,
			app.config['SECRET_KEY'],
			algorithm='HS256',
		).decode('utf-8')  # 将bytes转化为str
	except Exception as e:
		print(e)
		pass


def decode_auth_token(token):
	"""
	验证Token
	:param auth_token:
	:return: integer|string
	try:
		 payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'), leeway=datetime.timedelta(seconds=10))
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
	try:
		payload = jwt.decode(
			token,
			app.config['SECRET_KEY'],
			algorithms=['HS256'])
		return payload.get('data')
	except jwt.ExpiredSignatureError:
		return {'err': 0}          # token过期，自动重发token
	except jwt.InvalidTokenError:
		return {'err': 1}          # token错误, 需要重新登录


def generate_new_token():
	refresh_token = request.headers.get('refresh_token', None)
	data = decode_auth_token(refresh_token)
	if 'id' in data:
		return encode_auth_token(data['id'], data['username'])
	else:
		return None


def user_loader():
	from server.models import User
	token = request.headers.get('token')
	id = decode_auth_token(token).get('id', '')
	current_user = User.query.filter_by(id=id).first()
	if current_user:
		return current_user
	return None


def token_required(func):
	@wraps(func)
	def wrapper_func(*args, **kwargs):
		access_token = request.headers.get('access_token', None)
		try:
			data = decode_auth_token(access_token)
			print(data)
			if 'id' in data:
				g.access_token = None
				return func(*args, **kwargs)
			if 'err' in data and data['err'] == 0:
				g.access_token = generate_new_token()
				if g.access_token == None:
					return jsonify(status=3)
				return func(*args, **kwargs)
			return jsonify(status=3)
		except Exception as e:
			print(e)
			return jsonify(status=3)
	return wrapper_func




