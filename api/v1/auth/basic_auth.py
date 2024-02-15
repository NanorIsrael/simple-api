#!/usr/bin/env python3
"""
    Defines BasicAuth class
"""
from .auth import Auth
from flask import request
from models.user import User
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

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
     ) -> str:
        """returns the decoded value of a Base64 string
        base64_authorization_header
        """

        if isinstance(decoded_base64_authorization_header, str):
            for char in decoded_base64_authorization_header:
                if char == ":":
                    token = decoded_base64_authorization_header.split(':')
                    return tuple(token)
            return (None, None)
        else:
            return (None, None)

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

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        """
        if user_email is None or user_pwd is None:
            return None
        elif not isinstance(user_email, str) or not isinstance(user_pwd, str):
            return None
        else:
            try:
                users = [user.to_json() for user in User.all()]
                for user in users:
                    if user['email'] == user_email:
                        user = User.search({"email": user_email})[0]
                        if user.is_valid_password(user_pwd):
                            return user
            except Exception:
                return None
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """overloads Auth and retrieves the User instance for a request.
        """
        if request is None:
            return None
        else:
            auth = Auth()
            request_auth_header = auth.authorization_header(request)
            b64_auth_tokens = self.extract_base64_authorization_header(
                    request_auth_header
            )
            decoded_base64_authorization_header = (
                    self.decode_base64_authorization_header(b64_auth_tokens)
            )
            user_credentials = self.extract_user_credentials(
                decoded_base64_authorization_header
            )
            found_user = self.user_object_from_credentials(
                user_credentials[0], user_credentials[1]
            )

            return found_user