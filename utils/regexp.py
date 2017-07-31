# -*- coding:utf-8 -*-
import re


def re_password(password):
	if re.match(r'^(?=.*[A-Za-z])(?=.*[0-9])\w{6,}$', password):
		return True
	return False


def re_phone(phone):
	if re.match('^\+\d{11,16}$', phone):
		return True
	return False
