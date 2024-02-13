#!/usr/bin/env python3
"""
Route module for the API
"""
from flask import request
from typing import List, TypeVar

class Auth():
	"""Auth class to handle basic user authorization"""
	def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
		"""returns False - path and excluded_paths will be used later"""
		if excluded_paths is None or path is None:
			return True
		elif path + '/' in excluded_paths:
			return False
		elif path not in excluded_paths:
			return True
		else:
			return False
			
	
	def authorization_header(self, request=None) -> str:
		"""returns None - path and excluded_paths will be used later"""
		if request is None:
			return None
		else: 
			return request.headers.get("Authorization", None) 

	def current_user(self, request=None) -> TypeVar('User'):
		"""returns be the Flask request object"""
		return None
