import json
import urllib

from docassemble.base.config import daconfig
from docassemble.webapp.backend import url_for
from flask import make_response, request, session, redirect, \
    current_app
from rauth import OAuth1Service, OAuth2Service


def safe_json_loads(data):
    return json.loads(data.decode("utf-8", "strict"))


class OAuthSignIn:
    providers = {}
    providers_obtained = False

    def __init__(self, provider_name):
        self.provider_name = provider_name
        credentials = current_app.config['OAUTH_CREDENTIALS'].get(provider_name, {})
        self.consumer_id = credentials.get('id', None)
        self.consumer_secret = credentials.get('secret', None)
        self.consumer_domain = credentials.get('domain', None)

    def authorize(self):
        pass

    def callback(self):
        pass

    def get_callback_url(self):
        return url_for('auth.oauth_callback', provider=self.provider_name,
                       _external=True)

    @classmethod
    def get_provider(cls, provider_name):
        if not cls.providers_obtained:
            for provider_class in cls.__subclasses__():
                provider = provider_class()
                cls.providers[provider.provider_name] = provider
            cls.providers_obtained = True
        return cls.providers[provider_name]


class GoogleSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('google')
        self.service = OAuth2Service(
            name='google',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url=None,
            access_token_url=None,
            base_url=None
        )

    def authorize(self):
        result = urllib.parse.parse_qs(request.data.decode())
        # logmessage("GoogleSignIn, args: " + str([str(arg) + ": " + str(request.args[arg]) for arg in request.args]))
        # logmessage("GoogleSignIn, request: " + str(request.data))
        # logmessage("GoogleSignIn, result: " + repr(raw_result))
        session['google_id'] = result.get('id', [None])[0]
        session['google_email'] = result.get('email', [None])[0]
        session['google_name'] = result.get('name', [None])[0]
        response = make_response(json.dumps('Successfully connected user.'), 200)
        response.headers['Content-Type'] = 'application/json'
        # oauth_session = self.service.get_auth_session(
        #     data={'code': request.args['code'],
        #           'grant_type': 'authorization_code',
        #           'redirect_uri': self.get_callback_url()}
        # )
        return response

    def callback(self):
        # logmessage("GoogleCallback, args: " + str([str(arg) + ": " + str(request.args[arg]) for arg in request.args]))
        # logmessage("GoogleCallback, request: " + str(request.data))
        email = session.get('google_email', None)
        google_id = session.get('google_id', None)
        google_name = session.get('google_name', None)
        if 'google_id' in session:
            del session['google_id']
        if 'google_email' in session:
            del session['google_email']
        if 'google_name' in session:
            del session['google_name']
        if email is not None and google_id is not None:
            return (
                'google$' + str(google_id),
                email.split('@')[0],
                email,
                {'name': google_name}
            )
        raise Exception("Could not get Google authorization information")


class FacebookSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('facebook')
        self.service = OAuth2Service(
            name='facebook',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://www.facebook.com/v3.0/dialog/oauth',
            access_token_url='https://graph.facebook.com/v3.0/oauth/access_token',
            base_url='https://graph.facebook.com/v3.0'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            scope='public_profile,email',
            response_type='code',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            decoder=safe_json_loads,
            data={'code': request.args['code'],
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get('me',
                               params={'fields': 'id,name,first_name,middle_name,last_name,name_format,email'}).json()
        # logmessage("Facebook: returned " + json.dumps(me))
        return (
            'facebook$' + str(me['id']),
            me.get('email').split('@')[0],
            me.get('email'),
            {'first': me.get('first_name', None),
             'middle': me.get('middle_name', None),
             'last': me.get('last_name', None),
             'name': me.get('name', None),
             'name_format': me.get('name_format', None)}
        )


class AzureSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('azure')
        self.service = OAuth2Service(
            name='azure',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://login.microsoftonline.com/common/oauth2/authorize',
            access_token_url='https://login.microsoftonline.com/common/oauth2/token',
            base_url='https://graph.microsoft.com/v1.0/'
        )

    def authorize(self):
        return redirect(self.service.get_authorize_url(
            response_type='code',
            client_id=self.consumer_id,
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            decoder=safe_json_loads,
            data={'code': request.args['code'],
                  'client_id': self.consumer_id,
                  'client_secret': self.consumer_secret,
                  'resource': 'https://graph.microsoft.com/',
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get('me').json()
        return (
            'azure$' + str(me['id']),
            me.get('mail').split('@')[0],
            me.get('mail'),
            {'first_name': me.get('givenName', None),
             'last_name': me.get('surname', None),
             'name': me.get('displayName', me.get('userPrincipalName', None))}
        )


class Auth0SignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('auth0')
        self.service = OAuth2Service(
            name='auth0',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://' + str(self.consumer_domain) + '/authorize',
            access_token_url='https://' + str(self.consumer_domain) + '/oauth/token',
            base_url='https://' + str(self.consumer_domain)
        )

    def authorize(self):
        if 'oauth' in daconfig and 'auth0' in daconfig['oauth'] and daconfig['oauth']['auth0'].get('enable',
                                                                                                   True) and self.consumer_domain is None:
            raise Exception("To use Auth0, you need to set your domain in the configuration.")
        return redirect(self.service.get_authorize_url(
            response_type='code',
            scope='openid profile email',
            audience='https://' + str(self.consumer_domain) + '/userinfo',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            decoder=safe_json_loads,
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get('userinfo').json()
        # logmessage("Auth0 returned " + json.dumps(me))
        user_id = me.get('sub', me.get('user_id'))
        social_id = 'auth0$' + str(user_id)
        username = me.get('name')
        email = me.get('email')
        if user_id is None or username is None or email is None:
            raise Exception("Error: could not get necessary information from Auth0")
        return social_id, username, email, {'name': me.get('name', None)}


class KeycloakSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('keycloak')
        try:
            realm = daconfig['oauth']['keycloak']['realm']
        except:
            realm = None
        self.service = OAuth2Service(
            name='keycloak',
            client_id=self.consumer_id,
            client_secret=self.consumer_secret,
            authorize_url='https://' + str(self.consumer_domain) + '/auth/realms/' + str(
                realm) + '/protocol/openid-connect/auth',
            access_token_url='https://' + str(self.consumer_domain) + '/auth/realms/' + str(
                realm) + '/protocol/openid-connect/token',
            base_url='https://' + str(self.consumer_domain)
        )

    def authorize(self):
        if 'oauth' in daconfig and 'keycloak' in daconfig['oauth'] and daconfig['oauth']['keycloak'].get('enable',
                                                                                                         True) and self.consumer_domain is None:
            raise Exception("To use keycloak, you need to set your domain in the configuration.")
        return redirect(self.service.get_authorize_url(
            response_type='code',
            scope='openid profile email',
            redirect_uri=self.get_callback_url())
        )

    def callback(self):
        if 'code' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            decoder=safe_json_loads,
            data={'code': request.args['code'],
                  'grant_type': 'authorization_code',
                  'redirect_uri': self.get_callback_url()}
        )
        me = oauth_session.get(
            'auth/realms/' + daconfig['oauth']['keycloak']['realm'] + '/protocol/openid-connect/userinfo').json()
        # logmessage("keycloak returned " + json.dumps(me))
        user_id = me.get('sub')
        social_id = 'keycloak$' + str(user_id)
        username = me.get('preferred_username')
        email = me.get('email')
        if user_id is None or username is None or email is None:
            raise Exception("Error: could not get necessary information from keycloak")
        return social_id, username, email, {'name': me.get('name', None)}


class TwitterSignIn(OAuthSignIn):
    def __init__(self):
        super().__init__('twitter')
        self.service = OAuth1Service(
            name='twitter',
            consumer_key=self.consumer_id,
            consumer_secret=self.consumer_secret,
            request_token_url='https://api.twitter.com/oauth/request_token',
            authorize_url='https://api.twitter.com/oauth/authorize',
            access_token_url='https://api.twitter.com/oauth/access_token',
            base_url='https://api.twitter.com/1.1/'
        )

    def authorize(self):
        request_token = self.service.get_request_token(
            params={'oauth_callback': self.get_callback_url()}
        )
        session['request_token'] = request_token
        return redirect(self.service.get_authorize_url(request_token[0]))

    def callback(self):
        request_token = session.pop('request_token')
        if 'oauth_verifier' not in request.args:
            return None, None, None, None
        oauth_session = self.service.get_auth_session(
            request_token[0],
            request_token[1],
            data={'oauth_verifier': request.args['oauth_verifier']}
        )
        me = oauth_session.get('account/verify_credentials.json',
                               params={'skip_status': 'true', 'include_email': 'true',
                                       'include_entites': 'false'}).json()
        # logmessage("Twitter returned " + json.dumps(me))
        social_id = 'twitter$' + str(me.get('id_str'))
        username = me.get('screen_name')
        email = me.get('email')
        return social_id, username, email, {'name': me.get('name', None)}
