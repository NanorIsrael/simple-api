#!/usr/bin/env python3
""" Module of Users views
"""
from api.v1.views import app_views
from flask import abort, jsonify, request, make_response
from models.user import User
import uuid
from os import getenv

@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login_user() -> str:
	""" POST /api/v1/auth_session/login
	Form params
		- email
		- password
	Return:
	  - list of all User objects JSON represented
	"""
	from api.v1.app import auth

	email = request.form.get("email")
	if email is None:
		return jsonify({"error": "email missing"}), 400
	password = request.form.get("password")
	if password is None:
		return jsonify({"error": "password missing"}), 400
	
	try:
		user = User.search({"email": email})
		if len(user) == 0:
			return jsonify({"error": "no user found for this email"}), 404
		if not user[0].is_valid_password(password):
			return jsonify({"error": "wrong password"}), 401

		jsonified_user = user[0].to_json()
		session_id = auth.create_session(jsonified_user.get('id'))
		resp = make_response(jsonify(jsonified_user), 201)
		resp.set_cookie(getenv("SESSION_NAME"), session_id)
		return resp

	except Exception as e:
		print(e)
		return make_response(jsonify({"error": "an error occured"}), 500)
