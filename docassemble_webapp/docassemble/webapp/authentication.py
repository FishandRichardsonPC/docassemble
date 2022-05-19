from flask import make_response, request, session, redirect, current_app, flash, jsonify, g
from docassemble.webapp.utils import as_int, get_safe_next_param, endpoint_url, get_base_url, fix_http
from flask_login import logout_user, current_user
from docassemble.webapp.backend import url_for
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from docassemble.webapp.translations import setup_translation
from docassemble.base.functions import word
from docassemble.base.config import daconfig
import docassemble_flask_user.forms
import wtforms
from docassemble.base.generate_key import random_alphanumeric, random_digits
import re
from docassemble.webapp.app_object import app
from docassemble.webapp.db_object import db
from sqlalchemy import select
from docassemble.webapp.users.models import UserModel
from docassemble.webapp.config_server import twilio_config, DEFAULT_LANGUAGE
import datetime
from urllib.parse import quote as urllibquote
from docassemble.webapp.backend import generate_csrf
from docassemble.webapp.daredis import r
import docassemble.base.util
from docassemble_flask_user import UserManager, SQLAlchemyAdapter
from flask_login import LoginManager
from docassemble.webapp.users.models import AnonymousUserModel

the_db_adapter = SQLAlchemyAdapter(db, UserModel, UserAuthClass=UserAuthModel, UserInvitationClass=MyUserInvitation)
the_user_manager = UserManager()
the_user_manager.init_app(app, db_adapter=the_db_adapter, login_form=MySignInForm, register_form=MyRegisterForm, user_profile_view_function=user_profile_page, logout_view_function=logout, unauthorized_view_function=unauthorized, unauthenticated_view_function=unauthenticated, login_view_function=custom_login, register_view_function=custom_register, resend_confirm_email_view_function=custom_resend_confirm_email, resend_confirm_email_form=MyResendConfirmEmailForm, password_validator=password_validator, make_safe_url_function=make_safe_url)
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'custom_login'
lm.anonymous_user = AnonymousUserModel


def _call_or_get(function_or_property):
    return function_or_property() if callable(function_or_property) else function_or_property


def custom_register():
    """Display registration form and create new User."""
    is_json = bool(('json' in request.form and as_int(request.form['json'])) or ('json' in request.args and as_int(request.args['json'])))

    user_manager = current_app.user_manager
    db_adapter = user_manager.db_adapter

    safe_next = get_safe_next_param('next', user_manager.after_login_endpoint)
    safe_reg_next = get_safe_next_param('reg_next', user_manager.after_register_endpoint)
    if _call_or_get(current_user.is_authenticated) and user_manager.auto_login_at_login:
        if safe_next == url_for(user_manager.after_login_endpoint):
            url_parts = list(urlparse(safe_next))
            query = dict(parse_qsl(url_parts[4]))
            query.update(dict(from_login=1))
            url_parts[4] = urlencode(query)
            safe_next = urlunparse(url_parts)
        return add_secret_to(redirect(safe_next))

    setup_translation()

    # Initialize form
    login_form = user_manager.login_form()                      # for login_or_register.html
    register_form = user_manager.register_form(request.form)    # for register.html

    # invite token used to determine validity of registeree
    invite_token = request.values.get("token")

    # require invite without a token should disallow the user from registering
    if user_manager.require_invitation and not invite_token:
        flash(word("Registration is invite only"), "error")
        return redirect(url_for('user.login'))

    user_invite = None
    if invite_token and db_adapter.UserInvitationClass:
        user_invite = db_adapter.find_first_object(db_adapter.UserInvitationClass, token=invite_token)
        if user_invite:
            register_form.invite_token.data = invite_token
        else:
            flash(word("Invalid invitation token"), "error")
            return redirect(url_for('user.login'))

    if request.method != 'POST':
        login_form.next.data     = register_form.next.data     = safe_next
        login_form.reg_next.data = register_form.reg_next.data = safe_reg_next
        if user_invite:
            register_form.email.data = user_invite.email

    # Process valid POST
    if request.method == 'POST' and register_form.validate():
        email_taken = False
        if daconfig.get('confirm registration', False):
            try:
                docassemble_flask_user.forms.unique_email_validator(register_form, register_form.email)
            except wtforms.ValidationError:
                email_taken = True
        if email_taken:
            flash(word('A confirmation email has been sent to %(email)s with instructions to complete your registration.' % {'email': register_form.email.data}), 'success')
            subject, html_message, text_message = docassemble_flask_user.emails._render_email(
                'flask_user/emails/reregistered',
                app_name=app.config['APP_NAME'],
                sign_in_link=url_for('user.login', _external=True))

            # Send email message using Flask-Mail
            user_manager.send_email_function(register_form.email.data, subject, html_message, text_message)
            return redirect(url_for('user.login'))

        # Create a User object using Form fields that have a corresponding User field
        User = db_adapter.UserClass
        user_class_fields = User.__dict__
        user_fields = {}

        # Create a UserEmail object using Form fields that have a corresponding UserEmail field
        if db_adapter.UserEmailClass:
            UserEmail = db_adapter.UserEmailClass
            user_email_class_fields = UserEmail.__dict__
            user_email_fields = {}

        # Create a UserAuth object using Form fields that have a corresponding UserAuth field
        if db_adapter.UserAuthClass:
            UserAuth = db_adapter.UserAuthClass
            user_auth_class_fields = UserAuth.__dict__
            user_auth_fields = {}

        # Enable user account
        if db_adapter.UserProfileClass:
            if hasattr(db_adapter.UserProfileClass, 'active'):
                user_auth_fields['active'] = True
            elif hasattr(db_adapter.UserProfileClass, 'is_enabled'):
                user_auth_fields['is_enabled'] = True
            else:
                user_auth_fields['is_active'] = True
        else:
            if hasattr(db_adapter.UserClass, 'active'):
                user_fields['active'] = True
            elif hasattr(db_adapter.UserClass, 'is_enabled'):
                user_fields['is_enabled'] = True
            else:
                user_fields['is_active'] = True

        # For all form fields
        for field_name, field_value in register_form.data.items():
            # Hash password field
            if field_name == 'password':
                hashed_password = user_manager.hash_password(field_value)
                if db_adapter.UserAuthClass:
                    user_auth_fields['password'] = hashed_password
                else:
                    user_fields['password'] = hashed_password
            # Store corresponding Form fields into the User object and/or UserProfile object
            else:
                if field_name in user_class_fields:
                    user_fields[field_name] = field_value
                if db_adapter.UserEmailClass:
                    if field_name in user_email_class_fields:
                        user_email_fields[field_name] = field_value
                if db_adapter.UserAuthClass:
                    if field_name in user_auth_class_fields:
                        user_auth_fields[field_name] = field_value
        while True:
            new_social = 'local$' + random_alphanumeric(32)
            existing_user = db.session.execute(select(UserModel).filter_by(social_id=new_social)).first()
            if existing_user:
                continue
            break
        user_fields['social_id'] = new_social
        # Add User record using named arguments 'user_fields'
        user = db_adapter.add_object(User, **user_fields)

        # Add UserEmail record using named arguments 'user_email_fields'
        if db_adapter.UserEmailClass:
            user_email = db_adapter.add_object(UserEmail,
                    user=user,
                    is_primary=True,
                    **user_email_fields)
        else:
            user_email = None

        # Add UserAuth record using named arguments 'user_auth_fields'
        if db_adapter.UserAuthClass:
            user_auth = db_adapter.add_object(UserAuth, **user_auth_fields)
            if db_adapter.UserProfileClass:
                user = user_auth
            else:
                user.user_auth = user_auth

        require_email_confirmation = True
        if user_invite:
            if user_invite.email == register_form.email.data:
                require_email_confirmation = False
                db_adapter.update_object(user, confirmed_at=datetime.datetime.utcnow())

        db_adapter.commit()

        # Send 'registered' email and delete new User object if send fails
        if user_manager.send_registered_email:
            try:
                # Send 'registered' email
                docassemble_flask_user.views._send_registered_email(user, user_email, require_email_confirmation)
            except Exception:
                # delete new User object if send fails
                db_adapter.delete_object(user)
                db_adapter.commit()
                raise

        # Send user_registered signal
        docassemble_flask_user.signals.user_registered.send(current_app._get_current_object(),
                                                user=user,
                                                user_invite=user_invite)

        # Redirect if USER_ENABLE_CONFIRM_EMAIL is set
        if user_manager.enable_confirm_email and require_email_confirmation:
            safe_reg_next = user_manager.make_safe_url_function(register_form.reg_next.data)
            return redirect(safe_reg_next)

        # Auto-login after register or redirect to login page
        if 'reg_next' in request.args:
            safe_reg_next = user_manager.make_safe_url_function(register_form.reg_next.data)
        else:
            safe_reg_next = endpoint_url(user_manager.after_confirm_endpoint)

        if user_manager.auto_login_after_register:
            if app.config['USE_MFA']:
                if user.otp_secret is None and len(app.config['MFA_REQUIRED_FOR_ROLE']) and user.has_role(*app.config['MFA_REQUIRED_FOR_ROLE']):
                    session['validated_user'] = user.id
                    session['next'] = safe_reg_next
                    if app.config['MFA_ALLOW_APP'] and (twilio_config is None or not app.config['MFA_ALLOW_SMS']):
                        return redirect(url_for('mfa_setup'))
                    if not app.config['MFA_ALLOW_APP']:
                        return redirect(url_for('mfa_sms_setup'))
                    return redirect(url_for('mfa_choose'))
            return docassemble_flask_user.views._do_login_user(user, safe_reg_next)
        return redirect(url_for('user.login') + '?next=' + urllibquote(safe_reg_next))

    # Process GET or invalid POST
    if is_json:
        return jsonify(action='register', csrf_token=generate_csrf())
    response = make_response(user_manager.render_function(user_manager.register_template,
                                                              form=register_form,
                                                              login_form=login_form,
                                                              register_form=register_form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def custom_login():
    """ Prompt for username/email and password and sign the user in."""

    is_json = bool(('json' in request.form and as_int(request.form['json'])) or ('json' in request.args and as_int(request.args['json'])))
    user_manager = current_app.user_manager
    db_adapter = user_manager.db_adapter

    safe_next = get_safe_next_param('next', user_manager.after_login_endpoint)
    safe_reg_next = get_safe_next_param('reg_next', user_manager.after_register_endpoint)
    if safe_next and '/officeaddin' in safe_next:
        g.embed = True

    if _call_or_get(current_user.is_authenticated) and user_manager.auto_login_at_login:
        if safe_next == url_for(user_manager.after_login_endpoint):
            url_parts = list(urlparse(safe_next))
            query = dict(parse_qsl(url_parts[4]))
            query.update(dict(from_login=1))
            url_parts[4] = urlencode(query)
            safe_next = urlunparse(url_parts)
        return add_secret_to(redirect(safe_next))

    setup_translation()

    login_form = user_manager.login_form(request.form)
    register_form = user_manager.register_form()
    if request.method != 'POST':
        login_form.next.data     = register_form.next.data     = safe_next
        login_form.reg_next.data = register_form.reg_next.data = safe_reg_next
    if request.method == 'GET' and 'validated_user' in session:
        del session['validated_user']
    if request.method=='POST' and login_form.validate():
        user = None
        user_email = None
        if user_manager.enable_username:
            user = user_manager.find_user_by_username(login_form.username.data)
            user_email = None
            if user and db_adapter.UserEmailClass:
                user_email = db_adapter.find_first_object(db_adapter.UserEmailClass,
                        user_id=int(user.get_id()),
                        is_primary=True,
                        )
            if not user and user_manager.enable_email:
                user, user_email = user_manager.find_user_by_email(login_form.username.data)
        else:
            user, user_email = user_manager.find_user_by_email(login_form.email.data)
        #if not user and daconfig['ldap login'].get('enabled', False):
        if user:
            safe_next = user_manager.make_safe_url_function(login_form.next.data)
            #safe_next = login_form.next.data
            #safe_next = url_for('post_login', next=login_form.next.data)
            if app.config['USE_MFA']:
                if user.otp_secret is None and len(app.config['MFA_REQUIRED_FOR_ROLE']) and user.has_role(*app.config['MFA_REQUIRED_FOR_ROLE']):
                    session['validated_user'] = user.id
                    session['next'] = safe_next
                    if app.config['MFA_ALLOW_APP'] and (twilio_config is None or not app.config['MFA_ALLOW_SMS']):
                        return redirect(url_for('mfa_setup'))
                    if not app.config['MFA_ALLOW_APP']:
                        return redirect(url_for('mfa_sms_setup'))
                    return redirect(url_for('mfa_choose'))
                if user.otp_secret is not None:
                    session['validated_user'] = user.id
                    session['next'] = safe_next
                    if user.otp_secret.startswith(':phone:'):
                        phone_number = re.sub(r'^:phone:', '', user.otp_secret)
                        verification_code = random_digits(daconfig['verification code digits'])
                        message = word("Your verification code is") + " " + str(verification_code) + "."
                        key = 'da:mfa:phone:' + str(phone_number) + ':code'
                        pipe = r.pipeline()
                        pipe.set(key, verification_code)
                        pipe.expire(key, daconfig['verification code timeout'])
                        pipe.execute()
                        success = docassemble.base.util.send_sms(to=phone_number, body=message)
                        if not success:
                            flash(word("Unable to send verification code."), 'error')
                            return redirect(url_for('user.login'))
                    return add_secret_to(redirect(url_for('mfa_login')))
            if user_manager.enable_email and user_manager.enable_confirm_email \
               and len(daconfig['email confirmation privileges']) \
               and user.has_role(*daconfig['email confirmation privileges']) \
               and not user.has_confirmed_email():
                url = url_for('user.resend_confirm_email', email=user.email)
                flash(word('You cannot log in until your e-mail address has been confirmed.') + '<br><a href="' + url + '">' + word('Click here to confirm your e-mail') + '</a>.', 'error')
                return redirect(url_for('user.login'))
            return add_secret_to(docassemble_flask_user.views._do_login_user(user, safe_next, login_form.remember_me.data))
    if is_json:
        return jsonify(action='login', csrf_token=generate_csrf())
    # if 'officeaddin' in safe_next:
    #     extra_css = """
    # <script type="text/javascript" src="https://appsforoffice.microsoft.com/lib/1.1/hosted/office.debug.js"></script>"""
    #     extra_js = """
    # <script type="text/javascript" src=""" + '"' + url_for('static', filename='office/fabric.js') + '"' + """></script>
    # <script type="text/javascript" src=""" + '"' + url_for('static', filename='office/polyfill.js') + '"' + """></script>
    # <script type="text/javascript" src=""" + '"' + url_for('static', filename='office/app.js') + '"' + """></script>"""
    #     return render_template(user_manager.login_template,
    #                            form=login_form,
    #                            login_form=login_form,
    #                            register_form=register_form,
    #                            extra_css=Markup(extra_css),
    #                            extra_js=Markup(extra_js))
    # else:
    response = make_response(user_manager.render_function(user_manager.login_template,
                                                          form=login_form,
                                                          login_form=login_form,
                                                          register_form=register_form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def add_secret_to(response):
    if 'newsecret' in session:
        if 'embed' in g:
            response.set_cookie('secret', session['newsecret'], httponly=True, secure=app.config['SESSION_COOKIE_SECURE'], samesite='None')
        else:
            response.set_cookie('secret', session['newsecret'], httponly=True, secure=app.config['SESSION_COOKIE_SECURE'], samesite=app.config['SESSION_COOKIE_SAMESITE'])
        del session['newsecret']
    return response


def logout():
    # secret = request.cookies.get('secret', None)
    # if secret is None:
    #     secret = random_string(16)
    #     set_cookie = True
    # else:
    #     secret = str(secret)
    #     set_cookie = False
    user_manager = current_app.user_manager
    if 'next_arg' in session:
        next_url = session['next_arg']
        del session['next_arg']
    # if 'next' in request.args:
    #     next_url = request.args['next']
    elif session.get('language', None) and session['language'] != DEFAULT_LANGUAGE:
        next_url = endpoint_url(user_manager.after_logout_endpoint, lang=session['language'])
    else:
        next_url = endpoint_url(user_manager.after_logout_endpoint)
    if current_user.is_authenticated:
        if current_user.social_id.startswith('auth0$') and 'oauth' in daconfig and 'auth0' in daconfig['oauth'] and 'domain' in daconfig['oauth']['auth0']:
            if next_url.startswith('/'):
                next_url = get_base_url() + next_url
            next_url = 'https://' + daconfig['oauth']['auth0']['domain'] + '/v2/logout?' + urlencode(dict(returnTo=next_url, client_id=daconfig['oauth']['auth0']['id']))
        if current_user.social_id.startswith('keycloak$') and 'oauth' in daconfig and 'keycloak' in daconfig['oauth'] and 'domain' in daconfig['oauth']['keycloak']:
            if next_url.startswith('/'):
                next_url = get_base_url() + next_url
            next_url = ('https://' + daconfig['oauth']['keycloak']['domain'] + '/auth/realms/' + daconfig['oauth']['keycloak']['realm'] + '/protocol/openid-connect/logout?' + urlencode(dict(post_logout_redirect_uri=next_url))
            )
    else:
        if session.get('language', None) and session['language'] != DEFAULT_LANGUAGE:
            next_url = endpoint_url(user_manager.after_logout_endpoint, lang=session['language'])
        else:
            next_url = endpoint_url(user_manager.after_logout_endpoint)
    docassemble_flask_user.signals.user_logged_out.send(current_app._get_current_object(), user=current_user)
    logout_user()
    delete_session_info()
    session.clear()
    flash(word('You have signed out successfully.'), 'success')
    response = redirect(next_url)
    response.set_cookie('remember_token', '
from docassemble_flask_user import UserManager, SQLAlchemyAdapter', expires=0)
    response.set_cookie('visitor_secret', '', expires=0)
    response.set_cookie('secret', '', expires=0)
    response.set_cookie('session', '', expires=0)
    return response


def unauthenticated():
    if not request.args.get('nm', False):
        flash(word("You need to log in before you can access") + " " + word(request.path), 'error')
    the_url = url_for('user.login', next=fix_http(request.url))
    return redirect(the_url)


def unauthorized():
    flash(word("You are not authorized to access") + " " + word(request.path), 'error')
    return redirect(url_for('interview_list', next=fix_http(request.url)))


def delete_session_info():
    for key in ('i', 'uid', 'key_logged', 'tempuser', 'user_id', 'encrypted', 'chatstatus', 'observer', 'monitor', 'variablefile', 'doing_sms', 'playgroundfile', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources', 'playgroundmodules', 'playgroundpackages', 'taskwait', 'phone_number', 'otp_secret', 'validated_user', 'github_next', 'next', 'sessions'):
        if key in session:
            del session[key]


def custom_resend_confirm_email():
    user_manager = current_app.user_manager
    form = user_manager.resend_confirm_email_form(request.form)
    if request.method=='GET' and 'email' in request.args:
        form.email.data = request.args['email']
    if request.method=='POST' and form.validate():
        email = form.email.data
        user, user_email = user_manager.find_user_by_email(email)
        if user:
            docassemble_flask_user.views._send_confirm_email(user, user_email)
        return redirect(docassemble_flask_user.views._endpoint_url(user_manager.after_resend_confirm_email_endpoint))
    response = make_response(user_manager.render_function(user_manager.resend_confirm_email_template, form=form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response

@lm.user_loader
def load_user(the_id):
    return UserModel.query.options(db.joinedload(UserModel.roles)).get(int(the_id))


def get_user_object(user_id):
    the_user = db.session.execute(select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    return the_user
