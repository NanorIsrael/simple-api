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