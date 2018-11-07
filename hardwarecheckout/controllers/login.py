from hardwarecheckout import app
from hardwarecheckout import config
from hardwarecheckout.models.user import *
from hardwarecheckout.utils import verify_token, generate_auth_token
import requests
import datetime
import json
from urlparse import urljoin
from hardwarecheckout.forms.login_form import LoginForm
from oauth import OAuthSignIn
from flask import (
    flash,
    redirect,
    render_template,
    request,
    url_for
)

@app.route('/login')
def login_page():
    oauth = OAuthSignIn()
    return oauth.authorize()

@app.route('/callback/oauth')
def oauth_callback():
    if 'jwt' in request.cookies:
        token = verify_token(request.cookies['jwt'])
        if token is not None:
            return redirect('/inventory')
    oauth = OAuthSignIn()
    id_, email, admin, name, phone = oauth.callback()
    print(phone)
    if id_ is None:
        flash('Authentication failed.')
        return redirect('/inventory')
    if User.query.filter_by(email=email).count() == 0:
        admin = admin or email in config.ADMINS
        user = User(
            email=email,
            is_admin=admin,
            name=name,
            phone=phone,
        )
        db.session.add(user)
        db.session.commit()

    # generate token since we cut out quill
    token = generate_auth_token(email)

    response = app.make_response(redirect('/inventory'))
    response.set_cookie('jwt', token.encode('utf-8'))

    return response

@app.route('/logout')
def logout():
    """Log user out"""
    response = app.make_response(redirect('/'))
    response.set_cookie('jwt', '')
    return response
