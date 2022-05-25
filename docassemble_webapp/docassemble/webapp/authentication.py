import copy
import datetime
import os
import pickle
import re
from urllib.parse import parse_qsl, quote as urllibquote, urlencode, urlparse, urlsplit, urlunparse

import docassemble.base.util
import docassemble_flask_user.forms
import links_from_header
import oauth2client.client
import wtforms
from Crypto.PublicKey import RSA
from backports import zoneinfo
from docassemble.base.config import daconfig
from docassemble.base.error import DAError
from docassemble.base.functions import get_default_timezone, word
from docassemble.base.generate_key import random_alphanumeric, random_digits, random_string
from docassemble.base.logger import logmessage
from docassemble.webapp.app_object import app
from docassemble.webapp.backend import clear_session, clear_specific_session, decrypt_dictionary, decrypt_object, \
    decrypt_phrase, encrypt_dictionary, encrypt_object, encrypt_phrase, fetch_user_dict, generate_csrf, get_person, \
    get_session, nice_date_from_utc, pack_dictionary, pack_phrase, reset_user_dict, unpack_dictionary, unpack_phrase, \
    update_session, url_for
from docassemble.webapp.config_server import DEFAULT_LANGUAGE, PAGINATION_LIMIT, PAGINATION_LIMIT_PLUS_ONE, \
    REQUIRE_IDEMPOTENT, ROOT, STATS, \
    default_yaml_filename, final_default_yaml_filename, twilio_config
from docassemble.webapp.core.models import GlobalObjectStorage, SpeakList, UploadsUserAuth
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.files import SavedFile
from docassemble.webapp.fixpickle import fix_pickle_obj
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.users.forms import MyRegisterForm, MyResendConfirmEmailForm, MySignInForm
from docassemble.webapp.users.models import AnonymousUserModel, ChatLog, MyUserInvitation, TempUser, UserAuthModel, \
    UserDict, UserDictKeys, UserModel
from docassemble.webapp.users.views import user_profile_page
from docassemble.webapp.util import MD5Hash, as_int, endpoint_url, fix_http, fresh_dictionary, get_base_url, \
    get_requester_ip, get_safe_next_param, pad_to_16
from docassemble_flask_user import SQLAlchemyAdapter, UserManager
from flask import current_app, flash, g, jsonify, make_response, redirect, request, session
from flask_login import LoginManager, current_user, logout_user
from sqlalchemy import and_, delete, not_, or_, select, update


class FakeUser:
    pass


class FakeRole:
    pass


def make_safe_url(url):
    parts = urlsplit(url)
    safe_url = parts.path
    if parts.query != '':
        safe_url += '?' + parts.query
    if parts.fragment != '':
        safe_url += '#' + parts.fragment
    return safe_url


def _call_or_get(function_or_property):
    return function_or_property() if callable(function_or_property) else function_or_property


def custom_register():
    """Display registration form and create new User."""
    is_json = bool(('json' in request.form and as_int(request.form['json'])) or (
            'json' in request.args and as_int(request.args['json'])))

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
    login_form = user_manager.login_form()  # for login_or_register.html
    register_form = user_manager.register_form(request.form)  # for register.html

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
        login_form.next.data = register_form.next.data = safe_next
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
            flash(word(
                'A confirmation email has been sent to %(email)s with instructions to complete your registration.' % {
                    'email': register_form.email.data}), 'success')
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
                if user.otp_secret is None and len(app.config['MFA_REQUIRED_FOR_ROLE']) and user.has_role(
                        *app.config['MFA_REQUIRED_FOR_ROLE']):
                    session['validated_user'] = user.id
                    session['next'] = safe_reg_next
                    if app.config['MFA_ALLOW_APP'] and (twilio_config is None or not app.config['MFA_ALLOW_SMS']):
                        return redirect(url_for('mfa.mfa_setup'))
                    if not app.config['MFA_ALLOW_APP']:
                        return redirect(url_for('mfa.mfa_sms_setup'))
                    return redirect(url_for('mfa.mfa_choose'))
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

    is_json = bool(('json' in request.form and as_int(request.form['json'])) or (
            'json' in request.args and as_int(request.args['json'])))
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
        login_form.next.data = register_form.next.data = safe_next
        login_form.reg_next.data = register_form.reg_next.data = safe_reg_next
    if request.method == 'GET' and 'validated_user' in session:
        del session['validated_user']
    if request.method == 'POST' and login_form.validate():
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
        if user:
            safe_next = user_manager.make_safe_url_function(login_form.next.data)
            if app.config['USE_MFA']:
                if user.otp_secret is None and len(app.config['MFA_REQUIRED_FOR_ROLE']) and user.has_role(
                        *app.config['MFA_REQUIRED_FOR_ROLE']):
                    session['validated_user'] = user.id
                    session['next'] = safe_next
                    if app.config['MFA_ALLOW_APP'] and (twilio_config is None or not app.config['MFA_ALLOW_SMS']):
                        return redirect(url_for('mfa.mfa_setup'))
                    if not app.config['MFA_ALLOW_APP']:
                        return redirect(url_for('mfa.mfa_sms_setup'))
                    return redirect(url_for('mfa.mfa_choose'))
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
                    return add_secret_to(redirect(url_for('mfa.mfa_login')))
            if user_manager.enable_email and user_manager.enable_confirm_email \
                    and len(daconfig['email confirmation privileges']) \
                    and user.has_role(*daconfig['email confirmation privileges']) \
                    and not user.has_confirmed_email():
                url = url_for('user.resend_confirm_email', email=user.email)
                flash(word(
                    'You cannot log in until your e-mail address has been confirmed.') + '<br><a href="' + url + '">' + word(
                    'Click here to confirm your e-mail') + '</a>.', 'error')
                return redirect(url_for('user.login'))
            return add_secret_to(
                docassemble_flask_user.views._do_login_user(user, safe_next, login_form.remember_me.data))
    if is_json:
        return jsonify(action='login', csrf_token=generate_csrf())
    response = make_response(user_manager.render_function(user_manager.login_template,
                                                          form=login_form,
                                                          login_form=login_form,
                                                          register_form=register_form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def add_secret_to(response):
    if 'newsecret' in session:
        if 'embed' in g:
            response.set_cookie('secret', session['newsecret'], httponly=True,
                                secure=app.config['SESSION_COOKIE_SECURE'], samesite='None')
        else:
            response.set_cookie('secret', session['newsecret'], httponly=True,
                                secure=app.config['SESSION_COOKIE_SECURE'],
                                samesite=app.config['SESSION_COOKIE_SAMESITE'])
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
        if current_user.social_id.startswith('auth0$') and 'oauth' in daconfig and 'auth0' in daconfig[
            'oauth'] and 'domain' in daconfig['oauth']['auth0']:
            if next_url.startswith('/'):
                next_url = get_base_url() + next_url
            next_url = 'https://' + daconfig['oauth']['auth0']['domain'] + '/v2/logout?' + urlencode(
                dict(returnTo=next_url, client_id=daconfig['oauth']['auth0']['id']))
        if current_user.social_id.startswith('keycloak$') and 'oauth' in daconfig and 'keycloak' in daconfig[
            'oauth'] and 'domain' in daconfig['oauth']['keycloak']:
            if next_url.startswith('/'):
                next_url = get_base_url() + next_url
            next_url = ('https://' + daconfig['oauth']['keycloak']['domain'] + '/auth/realms/' +
                        daconfig['oauth']['keycloak']['realm'] + '/protocol/openid-connect/logout?' + urlencode(
                        dict(post_logout_redirect_uri=next_url))
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
    response.set_cookie('remember_token', '', expires=0)
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
    return redirect(url_for('interview.interview_list', next=fix_http(request.url)))


def delete_session_info():
    for key in (
            'i', 'uid', 'key_logged', 'tempuser', 'user_id', 'encrypted', 'chatstatus', 'observer', 'monitor',
            'variablefile',
            'doing_sms', 'playgroundfile', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources',
            'playgroundmodules',
            'playgroundpackages', 'taskwait', 'phone_number', 'otp_secret', 'validated_user', 'github_next', 'next',
            'sessions'):
        if key in session:
            del session[key]


def custom_resend_confirm_email():
    user_manager = current_app.user_manager
    form = user_manager.resend_confirm_email_form(request.form)
    if request.method == 'GET' and 'email' in request.args:
        form.email.data = request.args['email']
    if request.method == 'POST' and form.validate():
        email = form.email.data
        user, user_email = user_manager.find_user_by_email(email)
        if user:
            docassemble_flask_user.views._send_confirm_email(user, user_email)
        return redirect(docassemble_flask_user.views._endpoint_url(user_manager.after_resend_confirm_email_endpoint))
    response = make_response(user_manager.render_function(user_manager.resend_confirm_email_template, form=form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def get_user_object(user_id):
    the_user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    return the_user


def password_validator(form, field):
    password = list(field.data)
    password_length = len(password)

    lowers = uppers = digits = punct = 0
    for ch in password:
        if ch.islower():
            lowers += 1
        if ch.isupper():
            uppers += 1
        if ch.isdigit():
            digits += 1
        if not (ch.islower() or ch.isupper() or ch.isdigit()):
            punct += 1

    rules = daconfig.get('password complexity', {})
    is_valid = password_length >= rules.get('length', 6) and lowers >= rules.get('lowercase',
                                                                                 1) and uppers >= rules.get('uppercase',
                                                                                                            1) and digits >= rules.get(
        'digits', 1) and punct >= rules.get('punctuation', 0)
    if not is_valid:
        if 'error message' in rules:
            error_message = str(rules['error message'])
        else:
            # word("Password must be at least six characters long with at least one lowercase letter, at least one uppercase letter, and at least one number.")
            error_message = 'Password must be at least ' + docassemble.base.functions.quantity_noun(
                rules.get('length', 6), 'character', language='en') + ' long'
            standards = []
            if rules.get('lowercase', 1) > 0:
                standards.append('at least ' + docassemble.base.functions.quantity_noun(rules.get('lowercase', 1),
                                                                                        'lowercase letter',
                                                                                        language='en'))
            if rules.get('uppercase', 1) > 0:
                standards.append('at least ' + docassemble.base.functions.quantity_noun(rules.get('uppercase', 1),
                                                                                        'uppercase letter',
                                                                                        language='en'))
            if rules.get('digits', 1) > 0:
                standards.append(
                    'at least ' + docassemble.base.functions.quantity_noun(rules.get('digits', 1), 'number',
                                                                           language='en'))
            if rules.get('punctuation', 0) > 0:
                standards.append('at least ' + docassemble.base.functions.quantity_noun(rules.get('punctuation', 1),
                                                                                        'punctuation character',
                                                                                        language='en'))
            if len(standards) > 0:
                error_message += ' with ' + docassemble.base.functions.comma_and_list_en(standards)
            error_message += '.'
        raise wtforms.ValidationError(word(error_message))


def login_as_admin(url, url_root):
    found = False
    for admin_user in db.session.execute(
            select(UserModel).filter_by(nickname='admin').order_by(UserModel.id)).scalars():
        if not found:
            found = True
            current_app.login_manager._update_request_context_with_user(admin_user)
            docassemble.base.functions.this_thread.current_info = dict(
                user=dict(is_anonymous=False, is_authenticated=True, email=admin_user.email, theid=admin_user.id,
                          the_user_id=admin_user.id, roles=['admin'], firstname=admin_user.first_name,
                          lastname=admin_user.last_name, nickname=admin_user.nickname, country=admin_user.country,
                          subdivisionfirst=admin_user.subdivisionfirst, subdivisionsecond=admin_user.subdivisionsecond,
                          subdivisionthird=admin_user.subdivisionthird, organization=admin_user.organization,
                          location=None, session_uid='admin', device_id='admin'), session=None, secret=None,
                yaml_filename=final_default_yaml_filename, url=url, url_root=url_root, encrypted=False, action=None,
                interface='initialization', arguments={})


def get_sms_session(phone_number, config='default'):
    sess_info = None
    if twilio_config is None:
        raise DAError("get_sms_session: Twilio not enabled")
    if config not in twilio_config['name']:
        raise DAError("get_sms_session: Invalid twilio configuration")
    tconfig = twilio_config['name'][config]
    phone_number = docassemble.base.functions.phone_number_in_e164(phone_number)
    if phone_number is None:
        raise DAError("terminate_sms_session: phone_number " + str(phone_number) + " is invalid")
    sess_contents = r.get('da:sms:client:' + phone_number + ':server:' + tconfig['number'])
    if sess_contents is not None:
        try:
            sess_info = fix_pickle_obj(sess_contents)
        except:
            logmessage("get_sms_session: unable to decode session information")
    sess_info['email'] = None
    if 'user_id' in sess_info and sess_info['user_id'] is not None:
        user = load_user(sess_info['user_id'])
        if user is not None:
            sess_info['email'] = user.email
    return sess_info


def get_unique_name(filename, secret):
    nowtime = datetime.datetime.utcnow()
    while True:
        newname = random_alphanumeric(32)
        obtain_lock(newname, filename)
        existing_key = db.session.execute(select(UserDict).filter_by(key=newname)).first()
        if existing_key:
            release_lock(newname, filename)
            continue
        new_user_dict = UserDict(modtime=nowtime, key=newname, filename=filename,
                                 dictionary=encrypt_dictionary(fresh_dictionary(), secret))
        db.session.add(new_user_dict)
        db.session.commit()
        return newname


def initiate_sms_session(phone_number, yaml_filename=None, uid=None, secret=None, encrypted=None, user_id=None,
                         email=None, new=False, config='default'):
    phone_number = docassemble.base.functions.phone_number_in_e164(phone_number)
    if phone_number is None:
        raise DAError("initiate_sms_session: phone_number " + str(phone_number) + " is invalid")
    if config not in twilio_config['name']:
        raise DAError("get_sms_session: Invalid twilio configuration")
    tconfig = twilio_config['name'][config]
    the_current_info = docassemble.base.functions.get_current_info()
    if yaml_filename is None:
        yaml_filename = the_current_info.get('yaml_filename', None)
        if yaml_filename is None:
            yaml_filename = default_yaml_filename
    temp_user_id = None
    if user_id is None and email is not None:
        user = db.session.execute(
            select(UserModel).where(and_(UserModel.email.ilike(email), UserModel.active == True))).scalar()
        if user is not None:
            user_id = user.id
    if user_id is None:
        if not new:
            if 'user' in the_current_info:
                if 'theid' in the_current_info['user']:
                    if the_current_info['user'].get('is_authenticated', False):
                        user_id = the_current_info['user']['theid']
                    else:
                        temp_user_idand_ = the_current_info['user']['theid']
        if user_id is None and temp_user_id is None:
            new_temp_user = TempUser()
            db.session.add(new_temp_user)
            db.session.commit()
            temp_user_id = new_temp_user.id
    if secret is None:
        if not new:
            secret = the_current_info['secret']
        if secret is None:
            secret = random_string(16)
    if uid is None:
        if new:
            uid = get_unique_name(yaml_filename, secret)
        else:
            uid = the_current_info.get('session', None)
            if uid is None:
                uid = get_unique_name(yaml_filename, secret)
    if encrypted is None:
        if new:
            encrypted = True
        else:
            encrypted = the_current_info['encrypted']
    sess_info = dict(yaml_filename=yaml_filename, uid=uid, secret=secret, number=phone_number, encrypted=encrypted,
                     tempuser=temp_user_id, user_id=user_id)
    # logmessage("initiate_sms_session: setting da:sms:client:" + phone_number + ':server:' + tconfig['number'] + " to " + str(sess_info))
    r.set('da:sms:client:' + phone_number + ':server:' + tconfig['number'], pickle.dumps(sess_info))
    return True


def terminate_sms_session(phone_number, config='default'):
    if config not in twilio_config['name']:
        raise DAError("get_sms_session: Invalid twilio configuration")
    tconfig = twilio_config['name'][config]
    phone_number = docassemble.base.functions.phone_number_in_e164(phone_number)
    r.delete('da:sms:client:' + phone_number + ':server:' + tconfig['number'])


def reset_session(yaml_filename, secret):
    user_dict = fresh_dictionary()
    user_code = get_unique_name(yaml_filename, secret)
    if STATS:
        r.incr('da:stats:sessions')
    update_session(yaml_filename, uid=user_code)
    return (user_code, user_dict)


def user_id_dict():
    output = {}
    for user in db.session.execute(select(UserModel).options(db.joinedload(UserModel.roles))).unique().scalars():
        output[user.id] = user
    anon = FakeUser()
    anon_role = FakeRole()
    anon_role.name = 'anonymous'
    anon.roles = [anon_role]
    anon.id = -1
    anon.firstname = 'Anonymous'
    anon.lastname = 'User'
    output[-1] = anon
    return output


def decrypt_session(secret, user_code=None, filename=None):
    # logmessage("decrypt_session: user_code is " + str(user_code) + " and filename is " + str(filename))
    nowtime = datetime.datetime.utcnow()
    if user_code is None or filename is None or secret is None:
        return
    for record in db.session.execute(
            select(SpeakList).filter_by(key=user_code, filename=filename, encrypted=True).with_for_update()).scalars():
        phrase = decrypt_phrase(record.phrase, secret)
        record.phrase = pack_phrase(phrase)
        record.encrypted = False
    db.session.commit()
    for record in db.session.execute(
            select(UserDict).filter_by(key=user_code, filename=filename, encrypted=True).order_by(
                UserDict.indexno).with_for_update()).scalars():
        the_dict = decrypt_dictionary(record.dictionary, secret)
        record.dictionary = pack_dictionary(the_dict)
        record.encrypted = False
        record.modtime = nowtime
    db.session.commit()
    for record in db.session.execute(
            select(ChatLog).filter_by(key=user_code, filename=filename, encrypted=True).with_for_update()).scalars():
        phrase = decrypt_phrase(record.message, secret)
        record.message = pack_phrase(phrase)
        record.encrypted = False
    db.session.commit()


def sub_temp_other(user):
    if 'tempuser' in session:
        device_id = request.cookies.get('ds', None)
        if device_id is None:
            device_id = random_string(16)
        url_root = daconfig.get('url root', 'http://localhost') + daconfig.get('root', '/')
        url = url_root + 'interview'
        role_list = [role.name for role in user.roles]
        if len(role_list) == 0:
            role_list = ['user']
        the_current_info = dict(
            user=dict(email=user.email, roles=role_list, the_user_id=user.id, theid=user.id, firstname=user.first_name,
                      lastname=user.last_name, nickname=user.nickname, country=user.country,
                      subdivisionfirst=user.subdivisionfirst, subdivisionsecond=user.subdivisionsecond,
                      subdivisionthird=user.subdivisionthird, organization=user.organization, timezone=user.timezone,
                      language=user.language, location=None, session_uid='admin', device_id=device_id), session=None,
            secret=None, yaml_filename=None, url=url, url_root=url_root, encrypted=False, action=None, interface='web',
            arguments={})
        docassemble.base.functions.this_thread.current_info = the_current_info
        for chat_entry in db.session.execute(
                select(ChatLog).filter_by(temp_user_id=int(session['tempuser'])).with_for_update()).scalars():
            chat_entry.user_id = user.id
            chat_entry.temp_user_id = None
        db.session.commit()
        for chat_entry in db.session.execute(
                select(ChatLog).filter_by(temp_owner_id=int(session['tempuser'])).with_for_update()).scalars():
            chat_entry.owner_id = user.id
            chat_entry.temp_owner_id = None
        db.session.commit()
        keys_in_use = {}
        for object_entry in db.session.execute(select(GlobalObjectStorage.id, GlobalObjectStorage.key).filter(
                or_(GlobalObjectStorage.key.like('da:userid:{:d}:%'.format(user.id)),
                    GlobalObjectStorage.key.like('da:daglobal:userid:{:d}:%'.format(user.id))))).all():
            if object_entry.key not in keys_in_use:
                keys_in_use[object_entry.key] = []
            keys_in_use[object_entry.key].append(object_entry.id)
        ids_to_delete = []
        for object_entry in db.session.execute(select(GlobalObjectStorage).filter_by(
                temp_user_id=int(session['tempuser'])).with_for_update()).scalars():
            object_entry.user_id = user.id
            object_entry.temp_user_id = None
            if object_entry.key.startswith('da:userid:t{:d}:'.format(session['tempuser'])):
                new_key = re.sub(r'^da:userid:t{:d}:'.format(session['tempuser']), 'da:userid:{:d}:'.format(user.id),
                                 object_entry.key)
                object_entry.key = new_key
                if new_key in keys_in_use:
                    ids_to_delete.extend(keys_in_use[new_key])
            if object_entry.encrypted and 'newsecret' in session:
                try:
                    object_entry.value = encrypt_object(
                        decrypt_object(object_entry.value, str(request.cookies.get('secret', None))),
                        session['newsecret'])
                except Exception as err:
                    logmessage("Failure to change encryption of object " + object_entry.key + ": " + str(err))
        for object_entry in db.session.execute(select(GlobalObjectStorage).filter(
                and_(GlobalObjectStorage.temp_user_id == None, GlobalObjectStorage.user_id == None,
                     GlobalObjectStorage.key.like(
                         'da:daglobal:userid:t{:d}:%'.format(session['tempuser'])))).with_for_update()).scalars():
            new_key = re.sub(r'^da:daglobal:userid:t{:d}:'.format(session['tempuser']),
                             'da:daglobal:userid:{:d}:'.format(user.id), object_entry.key)
            object_entry.key = new_key
            if new_key in keys_in_use:
                ids_to_delete.extend(keys_in_use[new_key])
        for the_id in ids_to_delete:
            db.session.execute(delete(GlobalObjectStorage).filter_by(id=the_id))
        db.session.commit()
        db.session.execute(
            update(UploadsUserAuth).where(UploadsUserAuth.temp_user_id == int(session['tempuser'])).values(
                user_id=user.id, temp_user_id=None))
        db.session.commit()
        del session['tempuser']


def current_info(yaml=None, req=None, action=None, location=None, interface='web', session_info=None, secret=None,
                 device_id=None, session_uid=None):
    if current_user.is_authenticated and not current_user.is_anonymous:
        role_list = [str(role.name) for role in current_user.roles]
        if len(role_list) == 0:
            role_list = ['user']
        ext = dict(email=current_user.email, roles=role_list, the_user_id=current_user.id, theid=current_user.id,
                   firstname=current_user.first_name, lastname=current_user.last_name, nickname=current_user.nickname,
                   country=current_user.country, subdivisionfirst=current_user.subdivisionfirst,
                   subdivisionsecond=current_user.subdivisionsecond, subdivisionthird=current_user.subdivisionthird,
                   organization=current_user.organization, timezone=current_user.timezone,
                   language=current_user.language)
    else:
        ext = dict(email=None, the_user_id='t' + str(session.get('tempuser', None)),
                   theid=session.get('tempuser', None), roles=[])
    headers = {}
    if req is None:
        url_root = daconfig.get('url root', 'http://localhost') + ROOT
        url = url_root + 'interview'
        clientip = None
        method = None
        session_uid = '0'
    else:
        url_root = url_for('rootindex', _external=True)
        url = url_root + 'interview'
        if secret is None:
            secret = req.cookies.get('secret', None)
        for key, value in req.headers.items():
            headers[key] = value
        clientip = get_requester_ip(req)
        method = req.method
        if session_uid is None:
            if 'session' in req.cookies:
                session_uid = str(req.cookies.get('session'))[5:15]
            else:
                session_uid = ''
            if session_uid == '':
                session_uid = app.session_interface.manual_save_session(app, session).decode()[5:15]
    if device_id is None:
        device_id = random_string(16)
    if secret is not None:
        secret = str(secret)
    if session_info is None and yaml is not None:
        session_info = get_session(yaml)
    if session_info is not None:
        user_code = session_info['uid']
        encrypted = session_info['encrypted']
    else:
        user_code = None
        encrypted = True
    return_val = {'session': user_code, 'secret': secret, 'yaml_filename': yaml, 'interface': interface, 'url': url,
                  'url_root': url_root, 'encrypted': encrypted,
                  'user': {'is_anonymous': bool(current_user.is_anonymous),
                           'is_authenticated': bool(current_user.is_authenticated), 'session_uid': session_uid,
                           'device_id': device_id}, 'headers': headers, 'clientip': clientip, 'method': method}
    if action is not None:
        return_val.update(action)
    if location is not None:
        ext['location'] = location
    else:
        ext['location'] = None
    return_val['user'].update(ext)
    return return_val


def substitute_secret(oldsecret, newsecret, user=None, to_convert=None):
    if user is None:
        user = current_user
    device_id = request.cookies.get('ds', None)
    if device_id is None:
        device_id = random_string(16)
    the_current_info = current_info(yaml=None, req=request, action=None, session_info=None, secret=oldsecret,
                                    device_id=device_id)
    docassemble.base.functions.this_thread.current_info = the_current_info
    temp_user = session.get('tempuser', None)
    if oldsecret in ('None', newsecret):
        return newsecret
    if temp_user is not None:
        temp_user_info = dict(email=None, the_user_id='t' + str(temp_user), theid=temp_user, roles=[])
        the_current_info['user'] = temp_user_info
        for object_entry in db.session.execute(
                select(GlobalObjectStorage).filter_by(user_id=user.id, encrypted=True).with_for_update()).scalars():
            try:
                object_entry.value = encrypt_object(decrypt_object(object_entry.value, oldsecret), newsecret)
            except Exception as err:
                logmessage("Failure to change encryption of object " + object_entry.key + ": " + str(err))
        db.session.commit()
    if to_convert is None:
        to_do = set()
        if 'i' in session and 'uid' in session:  # TEMPORARY
            get_session(session['i'])
        if 'sessions' in session:
            for filename, info in session['sessions'].items():
                to_do.add((filename, info['uid']))
        for the_record in db.session.execute(
                select(UserDict.filename, UserDict.key).filter_by(user_id=user.id).group_by(UserDict.filename,
                                                                                            UserDict.key)):
            to_do.add((the_record.filename, the_record.key))
        for the_record in db.session.execute(select(UserDictKeys.filename, UserDictKeys.key).join(UserDict,
                                                                                                  and_(
                                                                                                      UserDictKeys.filename == UserDict.filename,
                                                                                                      UserDictKeys.key == UserDict.key)).where(
            and_(UserDictKeys.user_id == user.id)).group_by(UserDictKeys.filename, UserDictKeys.key)):
            to_do.add((the_record.filename, the_record.key))
    else:
        to_do = set(to_convert)
    for (filename, user_code) in to_do:
        the_current_info['yaml_filename'] = filename
        the_current_info['session'] = user_code
        the_current_info['encrypted'] = True
        for record in db.session.execute(select(SpeakList).filter_by(key=user_code, filename=filename,
                                                                     encrypted=True).with_for_update()).scalars():
            try:
                phrase = decrypt_phrase(record.phrase, oldsecret)
                record.phrase = encrypt_phrase(phrase, newsecret)
            except:
                pass
        db.session.commit()
        for object_entry in db.session.execute(select(GlobalObjectStorage).where(
                and_(GlobalObjectStorage.key.like('da:uid:' + user_code + ':i:' + filename + ':%'),
                     GlobalObjectStorage.encrypted == True)).with_for_update()).scalars():
            try:
                object_entry.value = encrypt_object(decrypt_object(object_entry.value, oldsecret), newsecret)
            except:
                pass
        db.session.commit()
        for record in db.session.execute(
                select(UserDict).filter_by(key=user_code, filename=filename, encrypted=True).order_by(
                    UserDict.indexno).with_for_update()).scalars():
            try:
                the_dict = decrypt_dictionary(record.dictionary, oldsecret)
            except Exception:
                logmessage(
                    "substitute_secret: error decrypting dictionary for filename " + filename + " and uid " + user_code)
                continue
            if not isinstance(the_dict, dict):
                logmessage(
                    "substitute_secret: dictionary was not a dict for filename " + filename + " and uid " + user_code)
                continue
            if temp_user:
                try:
                    old_entry = the_dict['_internal']['user_local']['t' + str(temp_user)]
                    del the_dict['_internal']['user_local']['t' + str(temp_user)]
                    the_dict['_internal']['user_local'][str(user.id)] = old_entry
                except:
                    pass
            record.dictionary = encrypt_dictionary(the_dict, newsecret)
        db.session.commit()
        if temp_user:
            for record in db.session.execute(
                    select(UserDict).filter_by(key=user_code, filename=filename, encrypted=False).order_by(
                        UserDict.indexno).with_for_update()).scalars():
                try:
                    the_dict = unpack_dictionary(record.dictionary)
                except Exception:
                    logmessage(
                        "substitute_secret: error unpacking dictionary for filename " + filename + " and uid " + user_code)
                    continue
                if not isinstance(the_dict, dict):
                    logmessage(
                        "substitute_secret: dictionary was not a dict for filename " + filename + " and uid " + user_code)
                    continue
                try:
                    old_entry = the_dict['_internal']['user_local']['t' + str(temp_user)]
                    del the_dict['_internal']['user_local']['t' + str(temp_user)]
                    the_dict['_internal']['user_local'][str(user.id)] = old_entry
                except:
                    pass
                record.dictionary = pack_dictionary(the_dict)
            db.session.commit()
        for record in db.session.execute(select(ChatLog).filter_by(key=user_code, filename=filename,
                                                                   encrypted=True).with_for_update()).scalars():
            try:
                phrase = decrypt_phrase(record.message, oldsecret)
            except Exception as e:
                logmessage(
                    "substitute_secret: error decrypting phrase for filename " + filename + " and uid " + user_code)
                continue
            record.message = encrypt_phrase(phrase, newsecret)
        db.session.commit()
        # release_lock(user_code, filename)
    return newsecret


def fix_secret(user=None, to_convert=None):
    if user is None:
        user = current_user
    password = str(request.form.get('password', request.form.get('new_password', None)))
    if password is not None:
        secret = str(request.cookies.get('secret', None))
        newsecret = pad_to_16(MD5Hash(data=password).hexdigest())
        if secret == 'None' or secret != newsecret:
            session['newsecret'] = substitute_secret(str(secret), newsecret, user=user, to_convert=to_convert)
    else:
        logmessage("fix_secret: password not in request")


def save_user_dict_key(session_id, filename, priors=False, user=None):
    if user is not None:
        user_id = user.id
        is_auth = True
    else:
        if current_user.is_authenticated and not current_user.is_anonymous:
            is_auth = True
            user_id = current_user.id
        else:
            is_auth = False
            user_id = session.get('tempuser', None)
            if user_id is None:
                logmessage("save_user_dict_key: no user ID available for saving")
                return
    the_interview_list = set([filename])
    found = set()
    if priors:
        for the_record in db.session.execute(
                select(UserDict.filename).filter_by(key=session_id).group_by(UserDict.filename)):
            the_interview_list.add(the_record.filename)
    for filename_to_search in the_interview_list:
        if is_auth:
            for the_record in db.session.execute(
                    select(UserDictKeys).filter_by(key=session_id, filename=filename_to_search, user_id=user_id)):
                found.add(filename_to_search)
        else:
            for the_record in db.session.execute(
                    select(UserDictKeys).filter_by(key=session_id, filename=filename_to_search, temp_user_id=user_id)):
                found.add(filename_to_search)
    for filename_to_save in (the_interview_list - found):
        if is_auth:
            new_record = UserDictKeys(key=session_id, filename=filename_to_save, user_id=user_id)
        else:
            new_record = UserDictKeys(key=session_id, filename=filename_to_save, temp_user_id=user_id)
        db.session.add(new_record)
        db.session.commit()


def update_last_login(user):
    user.last_login = datetime.datetime.utcnow()
    db.session.commit()


def sub_temp_user_dict_key(temp_user_id, user_id):
    temp_interviews = []
    for record in db.session.execute(
            select(UserDictKeys).filter_by(temp_user_id=temp_user_id).with_for_update()).scalars():
        record.temp_user_id = None
        record.user_id = user_id
        temp_interviews.append((record.filename, record.key))
    db.session.commit()
    return temp_interviews


def login_or_register(sender, user, source, **extra):
    # logmessage("login or register!")
    if 'i' in session:  # TEMPORARY
        get_session(session['i'])
    to_convert = []
    if 'tempuser' in session:
        to_convert.extend(sub_temp_user_dict_key(session['tempuser'], user.id))
    if 'sessions' in session:
        for filename, info in session['sessions'].items():
            if (filename, info['uid']) not in to_convert:
                to_convert.append((filename, info['uid']))
                save_user_dict_key(info['uid'], filename, priors=True, user=user)
                update_session(filename, key_logged=True)
    fix_secret(user=user, to_convert=to_convert)
    sub_temp_other(user)
    if not (source == 'register' and daconfig.get('confirm registration', False)):
        session['user_id'] = user.id
    if user.language:
        session['language'] = user.language
        docassemble.base.functions.set_language(user.language)


def encrypt_session(secret, user_code=None, filename=None):
    # logmessage("encrypt_session: user_code is " + str(user_code) + " and filename is " + str(filename))
    nowtime = datetime.datetime.utcnow()
    if user_code is None or filename is None or secret is None:
        return
    for record in db.session.execute(
            select(SpeakList).filter_by(key=user_code, filename=filename, encrypted=False).with_for_update()).scalars():
        phrase = unpack_phrase(record.phrase)
        record.phrase = encrypt_phrase(phrase, secret)
        record.encrypted = True
    db.session.commit()
    for record in db.session.execute(
            select(UserDict).filter_by(key=user_code, filename=filename, encrypted=False).order_by(
                UserDict.indexno).with_for_update()).scalars():
        the_dict = unpack_dictionary(record.dictionary)
        record.dictionary = encrypt_dictionary(the_dict, secret)
        record.encrypted = True
        record.modtime = nowtime
    db.session.commit()
    for record in db.session.execute(
            select(ChatLog).filter_by(key=user_code, filename=filename, encrypted=False).with_for_update()).scalars():
        phrase = unpack_phrase(record.message)
        record.message = encrypt_phrase(phrase, secret)
        record.encrypted = True
    db.session.commit()


def user_interviews_filter(obj):
    if isinstance(obj, docassemble.base.DA.Condition):
        leftside = user_interviews_filter(obj.leftside)
        rightside = user_interviews_filter(obj.rightside)
        if obj.operator == 'and':
            return leftside & rightside
        if obj.operator == 'xor':
            return leftside ^ rightside
        if obj.operator == 'or':
            return leftside | rightside
        if obj.operator == 'not':
            return not_(leftside)
        if obj.operator == 'le':
            return leftside <= rightside
        if obj.operator == 'ge':
            return leftside >= rightside
        if obj.operator == 'gt':
            return leftside > rightside
        if obj.operator == 'lt':
            return leftside < rightside
        if obj.operator == 'eq':
            return leftside == rightside
        if obj.operator == 'ne':
            return leftside != rightside
        if obj.operator == 'like':
            return leftside.like(rightside)
        if obj.operator == 'in':
            return leftside.in_(rightside)
        raise Exception("Operator not recognized")
    if isinstance(obj, docassemble.base.DA.Group):
        items = [user_interviews_filter(item) for item in obj.items]
        if obj.group_type == 'and':
            return and_(*items)
        if obj.group_type == 'or':
            return or_(*items)
        raise Exception("Group type not recognized")
    if isinstance(obj, docassemble.base.DA.Column):
        if obj.name == 'indexno':
            return UserDict.indexno
        if obj.name == 'modtime':
            return UserDict.modtime
        if obj.name == 'filename':
            return UserDictKeys.filename
        if obj.name == 'key':
            return UserDictKeys.key
        if obj.name == 'encrypted':
            return UserDict.encrypted
        if obj.name == 'user_id':
            return UserDictKeys.user_id
        if obj.name == 'email':
            return UserModel.email
        if obj.name == 'first_name':
            return UserModel.first_name
        if obj.name == 'last_name':
            return UserModel.last_name
        if obj.name == 'country':
            return UserModel.country
        if obj.name == 'subdivisionfirst':
            return UserModel.subdivisionfirst
        if obj.name == 'subdivisionsecond':
            return UserModel.subdivisionsecond
        if obj.name == 'subdivisionthird':
            return UserModel.subdivisionthird
        if obj.name == 'organization':
            return UserModel.organization
        if obj.name == 'timezone':
            return UserModel.timezone
        if obj.name == 'language':
            return UserModel.language
        if obj.name == 'last_login':
            return UserModel.last_login
        raise Exception("Column " + repr(obj.name) + " not available")
    return obj


def manual_checkout(manual_session_id=None, manual_filename=None, user_id=None, delete_session=False,
                    temp_user_id=None):
    if manual_filename is not None:
        yaml_filename = manual_filename
    else:
        yaml_filename = docassemble.base.functions.this_thread.current_info.get('yaml_filename', None)
    if yaml_filename is None:
        return
    if manual_session_id is not None:
        session_id = manual_session_id
    else:
        session_info = get_session(yaml_filename)
        if session_info is not None:
            session_id = session_info['uid']
        else:
            session_id = None
    if session_id is None:
        return
    if user_id is None:
        if temp_user_id is not None:
            the_user_id = 't' + str(temp_user_id)
        else:
            if current_user.is_anonymous:
                the_user_id = 't' + str(session.get('tempuser', None))
            else:
                the_user_id = current_user.id
    else:
        the_user_id = user_id
    if delete_session:
        if not (not current_user.is_anonymous and user_id != current_user.id):
            clear_specific_session(yaml_filename, session_id)
    endpart = ':uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
    pipe = r.pipeline()
    pipe.expire('da:session' + endpart, 12)
    pipe.expire('da:html' + endpart, 12)
    pipe.expire('da:interviewsession' + endpart, 12)
    pipe.expire('da:ready' + endpart, 12)
    pipe.expire('da:block' + endpart, 12)
    pipe.execute()


def user_interviews(user_id=None, secret=None, exclude_invalid=True, action=None, filename=None, session=None, tag=None,
                    include_dict=True, delete_shared=False, admin=False, start_id=None, temp_user_id=None, query=None):
    if session is not None and user_id is None and temp_user_id is None and current_user.is_authenticated and not current_user.has_role_or_permission(
            'admin', 'advocate', permissions=['access_sessions']):
        user_id = current_user.id
    elif user_id is None and (current_user.is_anonymous or not current_user.has_role_or_permission('admin', 'advocate',
                                                                                                   permissions=[
                                                                                                       'access_sessions'])):
        raise Exception(
            'user_interviews: you do not have sufficient privileges to access information about other users')
    if user_id is not None and admin is False and not (current_user.is_authenticated and (
            current_user.same_as(user_id) or current_user.has_role_or_permission('admin', 'advocate',
                                                                                 permissions=['access_sessions']))):
        raise Exception(
            'user_interviews: you do not have sufficient privileges to access information about other users')
    if action is not None and admin is False and not current_user.has_role_or_permission('admin', 'advocate',
                                                                                         permissions=['edit_sessions']):
        if user_id is None:
            raise Exception("user_interviews: no user_id provided")
        the_user = get_person(int(user_id), {})
        if the_user is None:
            raise Exception("user_interviews: user_id " + str(user_id) + " not valid")
    if query is not None:
        the_query = user_interviews_filter(query)
    if action == 'delete_all':
        sessions_to_delete = set()
        if tag or query is not None:
            start_id = None
            while True:
                (the_list, start_id) = user_interviews(user_id=user_id, secret=secret, filename=filename,
                                                       session=session, tag=tag, include_dict=False, start_id=start_id,
                                                       temp_user_id=temp_user_id, query=query)
                for interview_info in the_list:
                    sessions_to_delete.add((interview_info['session'], interview_info['filename'],
                                            interview_info['user_id'], interview_info['temp_user_id']))
                if start_id is None:
                    break
        else:
            where_clause = []
            if temp_user_id is not None:
                where_clause.append(UserDictKeys.temp_user_id == temp_user_id)
            elif user_id is not None:
                where_clause.append(UserDictKeys.user_id == user_id)
            if filename is not None:
                where_clause.append(UserDictKeys.filename == filename)
            if session is not None:
                where_clause.append(UserDictKeys.key == session)
            interview_query = db.session.execute(
                select(UserDictKeys.filename, UserDictKeys.key, UserDictKeys.user_id, UserDictKeys.temp_user_id).where(
                    *where_clause).group_by(UserDictKeys.filename, UserDictKeys.key, UserDictKeys.user_id,
                                            UserDictKeys.temp_user_id))
            for interview_info in interview_query:
                sessions_to_delete.add(
                    (interview_info.key, interview_info.filename, interview_info.user_id, interview_info.temp_user_id))
            if user_id is not None:
                if filename is None:
                    interview_query = db.session.execute(
                        select(UserDict.filename, UserDict.key).where(UserDict.user_id == user_id).group_by(
                            UserDict.filename, UserDict.key))
                else:
                    interview_query = db.session.execute(
                        select(UserDict.filename, UserDict.key).where(UserDict.user_id == user_id,
                                                                      UserDict.filename == filename).group_by(
                            UserDict.filename, UserDict.key))
                for interview_info in interview_query:
                    sessions_to_delete.add((interview_info.key, interview_info.filename, user_id, None))
        logmessage("Deleting " + str(len(sessions_to_delete)) + " interviews")
        if len(sessions_to_delete) > 0:
            for session_id, yaml_filename, the_user_id, the_temp_user_id in sessions_to_delete:
                manual_checkout(manual_session_id=session_id, manual_filename=yaml_filename, user_id=the_user_id,
                                delete_session=True, temp_user_id=the_temp_user_id)
                # obtain_lock(session_id, yaml_filename)
                if the_user_id is None or delete_shared:
                    reset_user_dict(session_id, yaml_filename, user_id=the_user_id, temp_user_id=the_temp_user_id,
                                    force=True)
                else:
                    reset_user_dict(session_id, yaml_filename, user_id=the_user_id, temp_user_id=the_temp_user_id)
                # release_lock(session_id, yaml_filename)
        return len(sessions_to_delete)
    if action == 'delete':
        if filename is None or session is None:
            raise Exception("user_interviews: filename and session must be provided in order to delete interview")
        manual_checkout(manual_session_id=session, manual_filename=filename, user_id=user_id, temp_user_id=temp_user_id,
                        delete_session=True)
        # obtain_lock(session, filename)
        reset_user_dict(session, filename, user_id=user_id, temp_user_id=temp_user_id, force=delete_shared)
        # release_lock(session, filename)
        return True
    if admin is False and current_user and current_user.is_authenticated and current_user.timezone:
        the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
    else:
        the_timezone = zoneinfo.ZoneInfo(get_default_timezone())

    interviews_length = 0
    interviews = []

    while True:
        there_are_more = False
        if temp_user_id is not None:
            query_elements = [UserDict.indexno, UserDictKeys.user_id, UserDictKeys.temp_user_id, UserDictKeys.filename,
                              UserDictKeys.key, UserModel.email]
            subq_filter_elements = [UserDictKeys.temp_user_id == temp_user_id]
            if include_dict:
                query_elements.extend([UserDict.dictionary, UserDict.encrypted])
            else:
                query_elements.append(UserDict.modtime)
            if filename is not None:
                subq_filter_elements.append(UserDictKeys.filename == filename)
            if session is not None:
                subq_filter_elements.append(UserDictKeys.key == session)
            if start_id is not None:
                subq_filter_elements.append(UserDict.indexno > start_id)
            subq = select(UserDictKeys.filename, UserDictKeys.key, db.func.max(UserDict.indexno).label('indexno')).join(
                UserDict, and_(UserDictKeys.filename == UserDict.filename, UserDictKeys.key == UserDict.key))
            if len(subq_filter_elements) > 0:
                subq = subq.where(and_(*subq_filter_elements))
            subq = subq.group_by(UserDictKeys.filename, UserDictKeys.key).subquery()
            interview_query = select(*query_elements).select_from(
                subq.join(UserDict, subq.c.indexno == UserDict.indexno).join(UserDictKeys, and_(
                    UserDict.filename == UserDictKeys.filename, UserDict.key == UserDictKeys.key,
                    UserDictKeys.temp_user_id == temp_user_id)).outerjoin(UserModel, 0 == 1))
            if query is not None:
                interview_query = interview_query.where(the_query)
            interview_query = interview_query.order_by(UserDict.indexno)
        elif user_id is not None:
            query_elements = [UserDict.indexno, UserDictKeys.user_id, UserDictKeys.temp_user_id, UserDictKeys.filename,
                              UserDictKeys.key, UserModel.email]
            subq_filter_elements = [UserDictKeys.user_id == user_id]
            if include_dict:
                query_elements.extend([UserDict.dictionary, UserDict.encrypted])
            else:
                query_elements.append(UserDict.modtime)
            if filename is not None:
                subq_filter_elements.append(UserDictKeys.filename == filename)
            if session is not None:
                subq_filter_elements.append(UserDictKeys.key == session)
            if start_id is not None:
                subq_filter_elements.append(UserDict.indexno > start_id)
            subq = select(UserDictKeys.filename, UserDictKeys.key, db.func.max(UserDict.indexno).label('indexno')).join(
                UserDict, and_(UserDictKeys.filename == UserDict.filename, UserDictKeys.key == UserDict.key))
            if len(subq_filter_elements) > 0:
                subq = subq.where(and_(*subq_filter_elements))
            subq = subq.group_by(UserDictKeys.filename, UserDictKeys.key).subquery()
            interview_query = select(*query_elements).select_from(
                subq.join(UserDict, subq.c.indexno == UserDict.indexno).join(UserDictKeys, and_(
                    UserDict.filename == UserDictKeys.filename, UserDict.key == UserDictKeys.key,
                    UserDictKeys.user_id == user_id)).join(UserModel, UserDictKeys.user_id == UserModel.id))
            if query is not None:
                interview_query = interview_query.where(the_query)
            interview_query = interview_query.order_by(UserDict.indexno)
        else:
            query_elements = [UserDict.indexno, UserDictKeys.user_id, UserDictKeys.temp_user_id, UserDict.filename,
                              UserDict.key, UserModel.email]
            subq_filter_elements = []
            if include_dict:
                query_elements.extend([UserDict.dictionary, UserDict.encrypted])
            else:
                query_elements.append(UserDict.modtime)
            if filename is not None:
                subq_filter_elements.append(UserDict.filename == filename)
            if session is not None:
                subq_filter_elements.append(UserDict.key == session)
            if start_id is not None:
                subq_filter_elements.append(UserDict.indexno > start_id)
            subq = select(UserDict.filename, UserDict.key, db.func.max(UserDict.indexno).label('indexno'))
            if len(subq_filter_elements) > 0:
                subq = subq.where(and_(*subq_filter_elements))
            subq = subq.group_by(UserDict.filename, UserDict.key).subquery()
            interview_query = select(*query_elements).select_from(
                subq.join(UserDict, subq.c.indexno == UserDict.indexno).join(UserDictKeys, and_(
                    UserDict.filename == UserDictKeys.filename, UserDict.key == UserDictKeys.key)).outerjoin(UserModel,
                                                                                                             and_(
                                                                                                                 UserDictKeys.user_id == UserModel.id,
                                                                                                                 UserModel.active == True)))
            if query is not None:
                interview_query = interview_query.where(the_query)
            interview_query = interview_query.order_by(UserDict.indexno)
        interview_query = interview_query.limit(PAGINATION_LIMIT_PLUS_ONE)
        stored_info = []
        results_in_query = 0
        for interview_info in db.session.execute(interview_query):
            results_in_query += 1
            if results_in_query == PAGINATION_LIMIT_PLUS_ONE:
                there_are_more = True
                break
            # logmessage("filename is " + str(interview_info.filename) + " " + str(interview_info.key))
            if session is not None and interview_info.key != session:
                continue
            if include_dict and interview_info.dictionary is None:
                continue
            if include_dict:
                stored_info.append(dict(filename=interview_info.filename,
                                        encrypted=interview_info.encrypted,
                                        dictionary=interview_info.dictionary,
                                        key=interview_info.key,
                                        email=interview_info.email,
                                        user_id=interview_info.user_id,
                                        temp_user_id=interview_info.temp_user_id,
                                        indexno=interview_info.indexno))
            else:
                stored_info.append(dict(filename=interview_info.filename,
                                        modtime=interview_info.modtime,
                                        key=interview_info.key,
                                        email=interview_info.email,
                                        user_id=interview_info.user_id,
                                        temp_user_id=interview_info.temp_user_id,
                                        indexno=interview_info.indexno))
        for interview_info in stored_info:
            if interviews_length == PAGINATION_LIMIT:
                there_are_more = True
                break
            start_id = interview_info['indexno']
            interview_title = {}
            is_valid = True
            interview_valid = True
            try:
                interview = docassemble.base.interview_cache.get_interview(interview_info['filename'])
            except Exception as the_err:
                if exclude_invalid:
                    continue
                logmessage("user_interviews: unable to load interview file " + interview_info['filename'])
                interview_title['full'] = word('Error: interview not found')
                interview_valid = False
                is_valid = False
            # logmessage("Found old interview with title " + interview_title)
            if include_dict:
                if interview_info['encrypted']:
                    try:
                        dictionary = decrypt_dictionary(interview_info['dictionary'], secret)
                    except Exception as the_err:
                        if exclude_invalid:
                            continue
                        try:
                            logmessage("user_interviews: unable to decrypt dictionary.  " + str(
                                the_err.__class__.__name__) + ": " + str(the_err))
                        except:
                            logmessage(
                                "user_interviews: unable to decrypt dictionary.  " + str(the_err.__class__.__name__))
                        dictionary = fresh_dictionary()
                        dictionary['_internal']['starttime'] = None
                        dictionary['_internal']['modtime'] = None
                        is_valid = False
                else:
                    try:
                        dictionary = unpack_dictionary(interview_info['dictionary'])
                    except Exception as the_err:
                        if exclude_invalid:
                            continue
                        try:
                            logmessage("user_interviews: unable to unpack dictionary.  " + str(
                                the_err.__class__.__name__) + ": " + str(the_err))
                        except:
                            logmessage(
                                "user_interviews: unable to unpack dictionary.  " + str(the_err.__class__.__name__))
                        dictionary = fresh_dictionary()
                        dictionary['_internal']['starttime'] = None
                        dictionary['_internal']['modtime'] = None
                        is_valid = False
                if not isinstance(dictionary, dict):
                    logmessage("user_interviews: found a dictionary that was not a dictionary")
                    continue
            if is_valid:
                if include_dict:
                    interview_title = interview.get_title(dictionary)
                    tags = interview.get_tags(dictionary)
                else:
                    interview_title = interview.get_title(dict(_internal={}))
                    tags = interview.get_tags(dict(_internal={}))
                metadata = copy.deepcopy(interview.consolidated_metadata)
            elif interview_valid:
                interview_title = interview.get_title(dict(_internal={}))
                metadata = copy.deepcopy(interview.consolidated_metadata)
                if include_dict:
                    tags = interview.get_tags(dictionary)
                    if 'full' not in interview_title:
                        interview_title['full'] = word("Interview answers cannot be decrypted")
                    else:
                        interview_title['full'] += ' - ' + word('interview answers cannot be decrypted')
                else:
                    tags = interview.get_tags(dict(_internal={}))
                    if 'full' not in interview_title:
                        interview_title['full'] = word('Unknown')
            else:
                interview_title['full'] = word('Error: interview not found and answers could not be decrypted')
                metadata = {}
                tags = set()
            if include_dict:
                if dictionary['_internal']['starttime']:
                    utc_starttime = dictionary['_internal']['starttime']
                    starttime = nice_date_from_utc(dictionary['_internal']['starttime'], timezone=the_timezone)
                else:
                    utc_starttime = None
                    starttime = ''
                if dictionary['_internal']['modtime']:
                    utc_modtime = dictionary['_internal']['modtime']
                    modtime = nice_date_from_utc(dictionary['_internal']['modtime'], timezone=the_timezone)
                else:
                    utc_modtime = None
                    modtime = ''
            else:
                utc_starttime = None
                starttime = ''
                utc_modtime = interview_info['modtime']
                modtime = nice_date_from_utc(interview_info['modtime'], timezone=the_timezone)
            if tag is not None and tag not in tags:
                continue
            out = {'filename': interview_info['filename'], 'session': interview_info['key'], 'modtime': modtime,
                   'starttime': starttime, 'utc_modtime': utc_modtime, 'utc_starttime': utc_starttime,
                   'title': interview_title.get('full', word('Untitled')), 'subtitle': interview_title.get('sub', None),
                   'valid': is_valid, 'metadata': metadata, 'tags': tags, 'email': interview_info['email'],
                   'user_id': interview_info['user_id'], 'temp_user_id': interview_info['temp_user_id']}
            if include_dict:
                out['dict'] = dictionary
                out['encrypted'] = interview_info['encrypted']
            interviews.append(out)
            interviews_length += 1
        if interviews_length == PAGINATION_LIMIT or results_in_query < PAGINATION_LIMIT_PLUS_ONE:
            break
    if there_are_more:
        return (interviews, start_id)
    else:
        return (interviews, None)


def get_github_flow():
    app_credentials = current_app.config['OAUTH_CREDENTIALS'].get('github', {})
    client_id = app_credentials.get('id', None)
    client_secret = app_credentials.get('secret', None)
    if client_id is None or client_secret is None:
        raise DAError('GitHub integration is not configured')
    flow = oauth2client.client.OAuth2WebServerFlow(
        client_id=client_id,
        client_secret=client_secret,
        scope='repo admin:public_key read:user user:email read:org',
        redirect_uri=url_for('auth.github_oauth_callback', _external=True),
        auth_uri='http://github.com/login/oauth/authorize',
        token_uri='https://github.com/login/oauth/access_token',
        access_type='offline',
        prompt='consent')
    return flow


def get_next_link(resp):
    if 'link' in resp and resp['link']:
        link_info = links_from_header.extract(resp['link'])
        if 'next' in link_info:
            return link_info['next']
    return None


def get_ssh_keys(email):
    area = SavedFile(current_user.id, fix=True, section='playgroundpackages')
    private_key_file = os.path.join(area.directory, '.ssh-private')
    public_key_file = os.path.join(area.directory, '.ssh-public')
    if (not (os.path.isfile(private_key_file) and os.path.isfile(private_key_file))) or (
            not (os.path.isfile(public_key_file) and os.path.isfile(public_key_file))):
        key = RSA.generate(4096)
        pubkey = key.publickey()
        area.write_content(key.exportKey('PEM').decode(), filename=private_key_file, save=False)
        pubkey_text = pubkey.exportKey('OpenSSH').decode() + " " + str(email) + "\n"
        area.write_content(pubkey_text, filename=public_key_file, save=False)
        area.finalize()
    return (private_key_file, public_key_file)


def delete_ssh_keys():
    area = SavedFile(current_user.id, fix=True, section='playgroundpackages')
    area.delete_file('.ssh-private')
    area.delete_file('.ssh-public')
    area.finalize()


the_db_adapter = SQLAlchemyAdapter(db, UserModel, UserAuthClass=UserAuthModel, UserInvitationClass=MyUserInvitation)
the_user_manager = UserManager()
the_user_manager.init_app(app, db_adapter=the_db_adapter, login_form=MySignInForm, register_form=MyRegisterForm,
                          user_profile_view_function=user_profile_page, logout_view_function=logout,
                          unauthorized_view_function=unauthorized, unauthenticated_view_function=unauthenticated,
                          login_view_function=custom_login, register_view_function=custom_register,
                          resend_confirm_email_view_function=custom_resend_confirm_email,
                          resend_confirm_email_form=MyResendConfirmEmailForm, password_validator=password_validator,
                          make_safe_url_function=make_safe_url)
lm = LoginManager()
lm.init_app(app)
lm.login_view = 'custom_login'
lm.anonymous_user = AnonymousUserModel


@lm.user_loader
def load_user(the_id):
    return UserModel.query.options(db.joinedload(UserModel.roles)).get(int(the_id))


def delete_session_for_interview(i=None):
    if i is not None:
        clear_session(i)
    for key in ('i', 'uid', 'key_logged', 'encrypted', 'chatstatus', 'observer', 'monitor', 'doing_sms'):
        if key in session:
            del session[key]


def delete_session_sessions():
    if 'sessions' in session:
        del session['sessions']


def backup_session():
    backup = {}
    for key in (
            'i', 'uid', 'key_logged', 'tempuser', 'user_id', 'encrypted', 'chatstatus', 'observer', 'monitor',
            'variablefile',
            'doing_sms', 'taskwait', 'phone_number', 'otp_secret', 'validated_user', 'github_next', 'next', 'sessions'):
        if key in session:
            backup[key] = session[key]
    return backup


def restore_session(backup):
    for key in (
            'i', 'uid', 'key_logged', 'tempuser', 'user_id', 'encrypted', 'google_id', 'google_email', 'chatstatus',
            'observer',
            'monitor', 'variablefile', 'doing_sms', 'taskwait', 'phone_number', 'otp_secret', 'validated_user',
            'github_next',
            'next', 'sessions'):
        if key in backup:
            session[key] = backup[key]


def get_existing_session(yaml_filename, secret):
    keys = [result.key for result in db.session.execute(select(UserDictKeys.filename, UserDictKeys.key).where(
        and_(UserDictKeys.user_id == current_user.id, UserDictKeys.filename == yaml_filename)).order_by(
        UserDictKeys.indexno))]
    for key in keys:
        try:
            steps, user_dict, is_encrypted = fetch_user_dict(key, yaml_filename, secret=secret)
        except:
            logmessage("get_existing_session: unable to decrypt existing interview session " + key)
            continue
        update_session(yaml_filename, uid=key, key_logged=True, encrypted=is_encrypted)
        return key, is_encrypted
    return None, True


def save_user_dict(user_code, user_dict, filename, secret=None, changed=False, encrypt=True, manual_user_id=None,
                   steps=None, max_indexno=None):
    if REQUIRE_IDEMPOTENT:
        for var_name in ('x', 'i', 'j', 'k', 'l', 'm', 'n'):
            if var_name in user_dict:
                del user_dict[var_name]
        user_dict['_internal']['objselections'] = {}
    if 'session_local' in user_dict:
        del user_dict['session_local']
    if 'device_local' in user_dict:
        del user_dict['device_local']
    if 'user_local' in user_dict:
        del user_dict['user_local']
    nowtime = datetime.datetime.utcnow()
    if steps is not None:
        user_dict['_internal']['steps'] = steps
    user_dict['_internal']['modtime'] = nowtime
    if manual_user_id is not None or (current_user and current_user.is_authenticated and not current_user.is_anonymous):
        if manual_user_id is not None:
            the_user_id = manual_user_id
        else:
            the_user_id = current_user.id
        user_dict['_internal']['accesstime'][the_user_id] = nowtime
    else:
        user_dict['_internal']['accesstime'][-1] = nowtime
        the_user_id = None
    if changed is True:
        if encrypt:
            new_record = UserDict(modtime=nowtime, key=user_code, dictionary=encrypt_dictionary(user_dict, secret),
                                  filename=filename, user_id=the_user_id, encrypted=True)
        else:
            new_record = UserDict(modtime=nowtime, key=user_code, dictionary=pack_dictionary(user_dict),
                                  filename=filename, user_id=the_user_id, encrypted=False)
        db.session.add(new_record)
        db.session.commit()
    else:
        if max_indexno is None:
            max_indexno = db.session.execute(select(db.func.max(UserDict.indexno)).where(
                and_(UserDict.key == user_code, UserDict.filename == filename))).scalar()
        if max_indexno is None:
            if encrypt:
                new_record = UserDict(modtime=nowtime, key=user_code, dictionary=encrypt_dictionary(user_dict, secret),
                                      filename=filename, user_id=the_user_id, encrypted=True)
            else:
                new_record = UserDict(modtime=nowtime, key=user_code, dictionary=pack_dictionary(user_dict),
                                      filename=filename, user_id=the_user_id, encrypted=False)
            db.session.add(new_record)
            db.session.commit()
        else:
            for record in db.session.execute(select(UserDict).filter_by(key=user_code, filename=filename,
                                                                        indexno=max_indexno).with_for_update()).scalars():
                if encrypt:
                    record.dictionary = encrypt_dictionary(user_dict, secret)
                    record.modtime = nowtime
                    record.encrypted = True
                else:
                    record.dictionary = pack_dictionary(user_dict)
                    record.modtime = nowtime
                    record.encrypted = False
            db.session.commit()


def needs_to_change_password():
    if not current_user.has_role('admin'):
        return False
    if not (current_user.social_id and current_user.social_id.startswith('local')):
        return False
    if app.user_manager.verify_password('password', current_user):
        session.pop('_flashes', None)
        flash(word("Your password is insecure and needs to be changed"), "warning")
        return True
    return False