#!/usr/bin/env python3
"""
	Defines BasicAuth class
"""
from .auth import Auth
from flask import request
from typing import List, TypeVar


class BasicAuth(Auth):
	"""Basic auth class to handle basic user authorization"""
	def extract_base64_authorization_header(
		self, authorization_header: str
	) -> str:
		"""returns the Base64 part of the Authorization header
        for a Basic Authentication
        """
		ah = str(authorization_header)
		if ah and ah.startswith('Basic'):
			token = (ah).partition(' ')
			if not token[2] == '':
				return token[2]
		else:
			return None

	def decode_base64_authorization_header(
		self, authorization_header: str
	) -> str:
		"""returns the decoded value of a Base64 string
		base64_authorization_header
        """
		import base64
		
		if isinstance(authorization_header, str):
			try:
				encode = base64.b64decode(authorization_header)
				token = encode.decode('utf-8')
				return token
			except Exception:
				return None
		else:
			return None

	def extract_user_credentials(
		self, decoded_base64_authorization_header: str
	) -> (str, str):
		"""returns the user email and password 
		from the Base64 decoded value
        """		
		if isinstance(decoded_base64_authorization_header, str):
			for char in decoded_base64_authorization_header:
				if char == ":":
					token = decoded_base64_authorization_header.split(':')
					return tuple(token)
			return (None, None) 
		else:
			return (None, None)