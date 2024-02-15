#!/usr/bin/env python3
"""Authentication module for the API.
"""
import re
from typing import List, TypeVar
from flask import request
from os import getenv

class Auth:
	"""Authentication class.
	"""
	def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
		"""Checks if a path requires authentication.
		"""
		if path is not None and excluded_paths is not None:
			for exclusion_path in map(lambda x: x.strip(), excluded_paths):
				pattern = ''
				if exclusion_path[-1] == '*':
					pattern = '{}.*'.format(exclusion_path[0:-1])
				elif exclusion_path[-1] == '/':
					pattern = '{}/*'.format(exclusion_path[0:-1])
				else:
					pattern = '{}/*'.format(exclusion_path)
				if re.match(pattern, path):
					return False
		return True

	def authorization_header(self, request=None) -> str:
		"""Gets the authorization header field from the request.
		"""
		if request is not None:
			return request.headers.get('Authorization', None)
		return None

	def current_user(self, request=None) -> TypeVar('User'):
		"""Gets the current user from the request.
		"""
		return None

	def session_cookie(self, request=None):
		"""Gets the cookie value from the request.
		"""
		if request is None:
			return None
		return request.cookies.get(getenv("SESSION_NAME"))
