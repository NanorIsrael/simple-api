#!/usr/bin/env python3
"""
    Defines SessionAuth class
"""
from .auth import Auth
from flask import request
from models.user import User
from typing import List, TypeVar

class SessionAuth(Auth):
	pass