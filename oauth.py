import json
from flask import redirect, url_for, request, current_app, session
from rauth import OAuth1Service, OAuth2Service
import requests
from hardwarecheckout import config

class OAuthSignIn(object):
    def __init__(self):
        credentials = config.OAUTH_CREDENTIALS
        self.consumer_id = credentials["id"]
        self.consumer_secret = credentials["secret"]
        self.service = OAuth2Service(
            name="reg",
            client_id = self.consumer_id,
            client_secret = self.consumer_secret,
            authorize_url=config.OAUTH_BASE_URL + '/authorize',
            access_token_url=config.OAUTH_BASE_URL + '/oauth/token',
            base_url=config.OAUTH_BASE_URL,
        )

    def get_callback_url(self):
        return url_for("oauth_callback", _external=True)

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None
        access_token = self.service.get_access_token(
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()},
            decoder=json.loads,
        )
        me = requests.get(config.OAUTH_BASE_URL + '/api/v1/getUserData', params={
            'access_token': access_token,
        }).json()

        name = me.get('firstName') + ' ' + me.get('lastName') if 'firstName' in me else None
        return (
            me.get('userId'),
            me.get('email'),
            me.get('admin'),
            name,
            me.get('phone'),
        )

