#!/usr/bin/env python3
"""
    Defines SessionAuth class
"""
from .auth import Auth
from flask import request
from models.user import User
from typing import List, TypeVar
import uuid
from os import getenv

class SessionAuth(Auth):
	"""Session auth class to handle session authorization"""
	user_id_by_session_id = {}

	def create_session(self, user_id: str = None) -> str:
		"""Session auth class to handle session authorization"""
		if user_id is None or not isinstance(user_id, str):
			return None
		else:
			session_id = str(uuid.uuid4())
			self.user_id_by_session_id[session_id] = user_id
		return session_id
	
	def user_id_for_session_id(self, session_id: str = None) -> str:
		"""Session auth class to handle session authorization"""
		if session_id is None or not isinstance(session_id, str):
			return None
		else:
			return self.user_id_by_session_id.get(session_id)

	def current_user(self, request=None) -> TypeVar("User"):
		"""Session auth class to handle session authorization"""
		if request is None:
			return None
		else:

			session_id = self.session_cookie(request)
			user_id = self.user_id_by_session_id.get(session_id)
			return User.get(user_id)
