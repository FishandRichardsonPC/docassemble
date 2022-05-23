import json
import re

import docassemble.base.functions
from docassemble.base.config import daconfig
from docassemble.base.functions import word
from docassemble.base.generate_key import random_digits
from docassemble.base.logger import logmessage
from docassemble.webapp.app_object import csrf
from docassemble.webapp.authentication import current_info, get_github_flow, manual_checkout, save_user_dict_key, \
    sub_temp_other, \
    sub_temp_user_dict_key, \
    substitute_secret, update_last_login
from docassemble.webapp.backend import decrypt_dictionary, fetch_user_dict, get_session, update_session, url_for
from docassemble.webapp.config_server import detect_mobile
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.oauth import OAuthSignIn
from docassemble.webapp.package import get_url_from_file_reference
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.users.forms import PhoneLoginForm, \
    PhoneLoginVerifyForm
from docassemble.webapp.users.models import UserModel
from docassemble.webapp.util import MD5Hash, RedisCredStorage, get_requester_ip, pad_to_16
from docassemble_flask_user import login_required, roles_required
from flask import Blueprint, abort, current_app, flash, jsonify, redirect, render_template, render_template_string, \
    request, session
from flask_login import current_user, login_user
from sqlalchemy import select
from user_agents import parse as ua_parse

auth = Blueprint('auth', __name__)


@auth.route('/authorize/<provider>', methods=['POST', 'GET'])
@csrf.exempt
def oauth_authorize(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('interview_list', from_login='1'))
    oauth = OAuthSignIn.get_provider(provider)
    next_url = current_app.user_manager.make_safe_url_function(request.args.get('next', ''))
    if next_url:
        session['next'] = next_url
    return oauth.authorize()


@auth.route('/callback/<provider>')
@csrf.exempt
def oauth_callback(provider):
    if not current_user.is_anonymous:
        return redirect(url_for('interview_list', from_login='1'))
    oauth = OAuthSignIn.get_provider(provider)
    social_id, username, email, name_data = oauth.callback()
    if social_id is None:
        flash(word('Authentication failed.'), 'error')
        return redirect(url_for('interview_list', from_login='1'))
    user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(social_id=social_id)).scalar()
    if not user:
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(email=email)).scalar()
    if user and user.social_id is not None and user.social_id.startswith('local'):
        flash(word('There is already a username and password on this system with the e-mail address') + " " + str(
            email) + ".  " + word("Please log in."), 'error')
        return redirect(url_for('user.login'))
    if not user:
        user = UserModel(social_id=social_id, nickname=username, email=email, active=True)
        if 'first_name' in name_data and 'last_name' in name_data and name_data['first_name'] is not None and name_data[
            'last_name'] is not None:
            user.first_name = name_data['first_name']
            user.last_name = name_data['last_name']
        elif 'name' in name_data and name_data['name'] is not None and ' ' in name_data['name']:
            user.first_name = re.sub(r' .*', '', name_data['name'])
            user.last_name = re.sub(r'.* ', '', name_data['name'])
        db.session.add(user)
        db.session.commit()
    login_user(user, remember=False)
    update_last_login(user)
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
    # logmessage("oauth_callback: calling substitute_secret")
    secret = substitute_secret(str(request.cookies.get('secret', None)), pad_to_16(MD5Hash(data=social_id).hexdigest()),
                               to_convert=to_convert)
    sub_temp_other(user)
    if 'next' in session:
        the_url = session['next']
        del session['next']
        response = redirect(the_url)
    else:
        response = redirect(url_for('interview_list', from_login='1'))
    response.set_cookie('secret', secret, httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                        samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
    return response


@auth.route('/phone_login', methods=['POST', 'GET'])
def phone_login():
    if not current_app.config['USE_PHONE_LOGIN']:
        return ('File not found', 404)
    form = PhoneLoginForm(request.form)
    # next = request.args.get('next', url_for('interview_list'))
    if request.method == 'POST' and form.submit.data:
        ok = True
        if form.validate():
            phone_number = form.phone_number.data
            if docassemble.base.functions.phone_number_is_valid(phone_number):
                phone_number = docassemble.base.functions.phone_number_in_e164(phone_number)
            else:
                ok = False
        else:
            ok = False
        if ok:
            verification_code = random_digits(daconfig['verification code digits'])
            message = word("Your verification code is") + " " + str(verification_code) + "."
            user_agent = request.headers.get('User-Agent', '')
            if detect_mobile.search(user_agent):
                message += '  ' + word("You can also follow this link: ") + url_for('phone_login_verify',
                                                                                    _external=True, p=phone_number,
                                                                                    c=verification_code)
            tracker_prefix = 'da:phonelogin:ip:' + str(get_requester_ip(request)) + ':phone:'
            tracker_key = tracker_prefix + str(phone_number)
            pipe = r.pipeline()
            pipe.incr(tracker_key)
            pipe.expire(tracker_key, daconfig['ban period'])
            pipe.execute()
            total_attempts = 0
            for key in r.keys(tracker_prefix + '*'):
                val = r.get(key.decode())
                total_attempts += int(val)
            if total_attempts > daconfig['attempt limit']:
                logmessage("IP address " + str(get_requester_ip(request)) + " attempted to log in too many times.")
                flash(word("You have made too many login attempts."), 'error')
                return redirect(url_for('user.login'))
            total_attempts = 0
            for key in r.keys('da:phonelogin:ip:*:phone:' + phone_number):
                val = r.get(key.decode())
                total_attempts += int(val)
            if total_attempts > daconfig['attempt limit']:
                logmessage("Too many attempts were made to log in to phone number " + str(phone_number))
                flash(word("You have made too many login attempts."), 'error')
                return redirect(url_for('user.login'))
            key = 'da:phonelogin:' + str(phone_number) + ':code'
            pipe = r.pipeline()
            pipe.set(key, verification_code)
            pipe.expire(key, daconfig['verification code timeout'])
            pipe.execute()
            # logmessage("Writing code " + str(verification_code) + " to " + key)
            docassemble.base.functions.this_thread.current_info = current_info(req=request)
            success = docassemble.base.util.send_sms(to=phone_number, body=message)
            if success:
                session['phone_number'] = phone_number
                return redirect(url_for('phone_login_verify'))
            flash(word("There was a problem sending you a text message.  Please log in another way."), 'error')
            return redirect(url_for('user.login'))
        flash(word("Please enter a valid phone number"), 'error')
    return render_template('flask_user/phone_login.html', form=form, version_warning=None,
                           title=word("Sign in with your mobile phone"), tab_title=word("Sign In"),
                           page_title=word("Sign in"))


@auth.route('/pv', methods=['POST', 'GET'])
def phone_login_verify():
    if not current_app.config['USE_PHONE_LOGIN']:
        return ('File not found', 404)
    phone_number = session.get('phone_number', request.args.get('p', None))
    if phone_number is None:
        return ('File not found', 404)
    form = PhoneLoginVerifyForm(request.form)
    form.phone_number.data = phone_number
    if 'c' in request.args and 'p' in request.args:
        submitted = True
        form.verification_code.data = request.args.get('c', None)
    else:
        submitted = False
    if submitted or (request.method == 'POST' and form.submit.data):
        if form.validate():
            social_id = 'phone$' + str(phone_number)
            user = db.session.execute(
                select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(social_id=social_id)).scalar()
            if user and user.active is False:
                flash(word("Your account has been disabled."), 'error')
                return redirect(url_for('user.login'))
            if not user:
                user = UserModel(social_id=social_id, nickname=phone_number, active=True)
                db.session.add(user)
                db.session.commit()
            login_user(user, remember=False)
            update_last_login(user)
            r.delete('da:phonelogin:ip:' + str(get_requester_ip(request)) + ':phone:' + phone_number)
            to_convert = []
            if 'i' in session:  # TEMPORARY
                get_session(session['i'])
            if 'tempuser' in session:
                to_convert.extend(sub_temp_user_dict_key(session['tempuser'], user.id))
            if 'sessions' in session:
                for filename, info in session['sessions'].items():
                    if (filename, info['uid']) not in to_convert:
                        to_convert.append((filename, info['uid']))
                        save_user_dict_key(info['uid'], filename, priors=True, user=user)
                        update_session(filename, key_logged=True)
            secret = substitute_secret(str(request.cookies.get('secret', None)),
                                       pad_to_16(MD5Hash(data=social_id).hexdigest()), user=user, to_convert=to_convert)
            response = redirect(url_for('interview_list', from_login='1'))
            response.set_cookie('secret', secret, httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                                samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
            return response
        logmessage(
            "IP address " + str(get_requester_ip(request)) + " made a failed login attempt using phone number " + str(
                phone_number) + ".")
        flash(word("Your verification code is invalid or expired.  Please try again."), 'error')
        return redirect(url_for('user.login'))
    return render_template('flask_user/phone_login_verify.html', form=form, version_warning=None,
                           title=word("Verify your phone"), tab_title=word("Enter code"), page_title=word("Enter code"),
                           description=word(
                               "We just sent you a text message with a verification code.  Enter the verification code to proceed."))


@auth.route('/user/autologin', methods=['GET'])
def auto_login():
    ua_string = request.headers.get('User-Agent', None)
    if ua_string is not None:
        response = ua_parse(ua_string)
        if response.device.brand == 'Spider':
            return render_template_string('')
    if 'key' not in request.args or len(request.args['key']) != 40:
        abort(403)
    code = str(request.args['key'][16:40])
    decryption_key = str(request.args['key'][0:16])
    the_key = 'da:auto_login:' + code
    info_text = r.get(the_key)
    if info_text is None:
        abort(403)
    r.delete(the_key)
    info_text = info_text.decode()
    try:
        info = decrypt_dictionary(info_text, decryption_key)
    except:
        abort(403)
    user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == info['user_id'])).scalar()
    if (not user) or user.social_id.startswith('disabled$'):
        abort(403)
    login_user(user, remember=False)
    update_last_login(user)
    if 'i' in info:
        url_info = dict(i=info['i'])
        if 'url_args' in info:
            url_info.update(info['url_args'])
        next_url = url_for('index', **url_info)
        if 'session' in info:
            update_session(info['i'], uid=info['session'], encrypted=info['encrypted'])
    elif 'next' in info:
        url_info = info.get('url_args', {})
        next_url = get_url_from_file_reference(info['next'], **url_info)
    else:
        next_url = url_for('interview_list', from_login='1')
    response = redirect(next_url)
    response.set_cookie('secret', info['secret'], httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                        samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
    return response


@auth.route('/github_oauth_callback', methods=['POST', 'GET'])
@login_required
@roles_required(['admin', 'developer'])
def github_oauth_callback():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    failed = False
    if not current_app.config['USE_GITHUB']:
        logmessage('github_oauth_callback: server does not use github')
        failed = True
    elif 'github_next' not in session:
        logmessage('github_oauth_callback: next not in session')
        failed = True
    if failed is False:
        github_next = json.loads(session['github_next'])
        del session['github_next']
        if 'code' not in request.args or 'state' not in request.args:
            logmessage('github_oauth_callback: code and state not in args')
            failed = True
        elif request.args['state'] != github_next['state']:
            logmessage('github_oauth_callback: state did not match')
            failed = True
    if failed:
        r.delete('da:github:userid:' + str(current_user.id))
        r.delete('da:using_github:userid:' + str(current_user.id))
        return ('File not found', 404)
    flow = get_github_flow()
    credentials = flow.step2_exchange(request.args['code'])
    storage = RedisCredStorage(app='github')
    storage.put(credentials)
    return redirect(github_next['path'], **github_next['arguments'])


@auth.route('/user/google-sign-in')
def google_page():
    return render_template('flask_user/google_login.html', version_warning=None, title=word("Sign In"),
                           tab_title=word("Sign In"), page_title=word("Sign in"))


@auth.route("/user/post-sign-in", methods=['GET'])
def post_sign_in():
    return redirect(url_for('interview_list', from_login='1'))


@auth.route("/restart_session", methods=['GET'])
def restart_session():
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        return redirect(url_for('index'))
    session_info = get_session(yaml_filename)
    if session_info is None:
        return redirect(url_for('index'))
    session_id = session_info['uid']
    manual_checkout(manual_filename=yaml_filename)
    if 'visitor_secret' in request.cookies:
        secret = request.cookies['visitor_secret']
    else:
        secret = request.cookies.get('secret', None)
    if secret is not None:
        secret = str(secret)
    docassemble.base.functions.this_thread.current_info = current_info(yaml=yaml_filename, req=request,
                                                                       interface='vars',
                                                                       device_id=request.cookies.get('ds', None),
                                                                       session_uid=current_user.email)
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
    except:
        return redirect(url_for('index', i=yaml_filename))
    url_args = user_dict['url_args']
    url_args['reset'] = '1'
    url_args['i'] = yaml_filename
    return redirect(url_for('index', **url_args))


@auth.route("/new_session", methods=['GET'])
def new_session():
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        return redirect(url_for('index'))
    manual_checkout(manual_filename=yaml_filename)
    url_args = dict(i=yaml_filename, new_session='1')
    return redirect(url_for('index', **url_args))


@auth.route("/checkout", methods=['POST'])
def checkout():
    try:
        manual_checkout(manual_filename=request.args['i'])
    except:
        return jsonify(success=False)
    return jsonify(success=True)
