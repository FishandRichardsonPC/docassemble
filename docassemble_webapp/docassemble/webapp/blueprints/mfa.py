import re
from io import BytesIO

import docassemble.base.functions
import docassemble_flask_user.views
import pyotp
import qrcode
import qrcode.image.svg
from docassemble.base.config import daconfig
from docassemble.base.functions import pickleable_objects, word
from docassemble.base.generate_key import random_digits
from docassemble.base.logger import logmessage
from docassemble.webapp.authentication import load_user
from docassemble.webapp.backend import url_for
from docassemble.webapp.config_server import twilio_config
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.users.forms import MFASetupForm, MFAReconfigureForm, MFALoginForm, MFAChooseForm, \
    MFASMSSetupForm, \
    MFAVerifySMSSetupForm
from docassemble.webapp.util import get_safe_next_param, get_requester_ip
from docassemble_flask_user import login_required
from flask import Blueprint
from flask import render_template, request, session, redirect, current_app, flash, Markup
from flask_login import current_user

mfa = Blueprint('mfa', __name__)


@mfa.route('/mfa_setup', methods=['POST', 'GET'])
def mfa_setup():
    in_login = False
    if current_user.is_authenticated:
        user = current_user
    elif 'validated_user' in session:
        in_login = True
        user = load_user(session['validated_user'])
    else:
        return ('File not found', 404)
    if not current_app.config['USE_MFA'] or not user.has_role(
            *current_app.config['MFA_ROLES']) or not user.social_id.startswith('local'):
        return ('File not found', 404)
    form = MFASetupForm(request.form)
    if request.method == 'POST' and form.submit.data:
        if 'otp_secret' not in session:
            return ('File not found', 404)
        otp_secret = session['otp_secret']
        del session['otp_secret']
        supplied_verification_code = re.sub(r'[^0-9]', '', form.verification_code.data)
        totp = pyotp.TOTP(otp_secret)
        if not totp.verify(supplied_verification_code):
            flash(word("Your verification code was invalid."), 'error')
            if in_login:
                del session['validated_user']
                if 'next' in session:
                    del session['next']
                return redirect(url_for('user.login'))
            return redirect(url_for('user_profile_page'))
        user = load_user(user.id)
        user.otp_secret = otp_secret
        db.session.commit()
        if in_login:
            if 'next' in session:
                next_url = session['next']
                del session['next']
            else:
                next_url = url_for('interview.interview_list', from_login='1')
            return docassemble_flask_user.views._do_login_user(user, next_url, False)
        flash(word("You are now set up with two factor authentication."), 'success')
        return redirect(url_for('user_profile_page'))
    otp_secret = pyotp.random_base32()
    if user.email:
        the_name = user.email
    else:
        the_name = re.sub(r'.*\$', '', user.social_id)
    the_url = pyotp.totp.TOTP(otp_secret).provisioning_uri(the_name, issuer_name=current_app.config['APP_NAME'])
    im = qrcode.make(the_url, image_factory=qrcode.image.svg.SvgPathImage)
    output = BytesIO()
    im.save(output)
    the_qrcode = output.getvalue().decode()
    the_qrcode = re.sub(r"<\?xml version='1.0' encoding='UTF-8'\?>\n", '', the_qrcode)
    the_qrcode = re.sub(r'height="[0-9]+mm" ', '', the_qrcode)
    the_qrcode = re.sub(r'width="[0-9]+mm" ', '', the_qrcode)
    m = re.search(r'(viewBox="[^"]+")', the_qrcode)
    if m:
        viewbox = ' ' + m.group(1)
    else:
        viewbox = ''
    the_qrcode = '<svg class="damfasvg"' + viewbox + '><g transform="scale(1.0)">' + the_qrcode + '</g></svg>'
    session['otp_secret'] = otp_secret
    return render_template('flask_user/mfa_setup.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"), description=word(
            "Scan the barcode with your phone's authenticator app and enter the verification code."),
                           the_qrcode=Markup(the_qrcode))


@login_required
@mfa.route('/mfa_reconfigure', methods=['POST', 'GET'])
def mfa_reconfigure():
    setup_translation()
    if not current_app.config['USE_MFA'] or not current_user.has_role(
            *current_app.config['MFA_ROLES']) or not current_user.social_id.startswith('local'):
        return ('File not found', 404)
    user = load_user(current_user.id)
    if user.otp_secret is None:
        if current_app.config['MFA_ALLOW_APP'] and (twilio_config is None or not current_app.config['MFA_ALLOW_SMS']):
            return redirect(url_for('mfa.mfa_setup'))
        if not current_app.config['MFA_ALLOW_APP']:
            return redirect(url_for('mfa.mfa_sms_setup'))
        return redirect(url_for('mfa.mfa_choose'))
    form = MFAReconfigureForm(request.form)
    if request.method == 'POST':
        if form.reconfigure.data:
            if current_app.config['MFA_ALLOW_APP'] and (
                    twilio_config is None or not current_app.config['MFA_ALLOW_SMS']):
                return redirect(url_for('mfa.mfa_setup'))
            if not current_app.config['MFA_ALLOW_APP']:
                return redirect(url_for('mfa.mfa_sms_setup'))
            return redirect(url_for('mfa.mfa_choose'))
        if form.disable.data and not (len(current_app.config['MFA_REQUIRED_FOR_ROLE']) and current_user.has_role(
                *current_app.config['MFA_REQUIRED_FOR_ROLE'])):
            user.otp_secret = None
            db.session.commit()
            flash(word("Your account no longer uses two-factor authentication."), 'success')
            return redirect(url_for('user_profile_page'))
        if form.cancel.data:
            return redirect(url_for('user_profile_page'))
    if len(current_app.config['MFA_REQUIRED_FOR_ROLE']) > 0 and current_user.has_role(
            *current_app.config['MFA_REQUIRED_FOR_ROLE']):
        return render_template('flask_user/mfa_reconfigure.html', form=form, version_warning=None,
                               title=word("Two-factor authentication"), tab_title=word("Authentication"),
                               page_title=word("Authentication"), allow_disable=False,
                               description=word("Would you like to reconfigure two-factor authentication?"))
    return render_template('flask_user/mfa_reconfigure.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"), allow_disable=True, description=word(
            "Your account already has two-factor authentication enabled.  Would you like to reconfigure or disable two-factor authentication?"))


@mfa.route('/mfa_choose', methods=['POST', 'GET'])
def mfa_choose():
    in_login = False
    if current_user.is_authenticated:
        user = current_user
    elif 'validated_user' in session:
        in_login = True
        user = load_user(session['validated_user'])
    else:
        return ('File not found', 404)
    if not current_app.config['USE_MFA'] or user.is_anonymous or not user.has_role(
            *current_app.config['MFA_ROLES']) or not user.social_id.startswith('local'):
        return ('File not found', 404)
    if current_app.config['MFA_ALLOW_APP'] and (twilio_config is None or not current_app.config['MFA_ALLOW_SMS']):
        return redirect(url_for('mfa.mfa_setup'))
    if not current_app.config['MFA_ALLOW_APP']:
        return redirect(url_for('mfa.mfa_sms_setup'))
    user = load_user(user.id)
    form = MFAChooseForm(request.form)
    if request.method == 'POST':
        if form.sms.data:
            return redirect(url_for('mfa.mfa_sms_setup'))
        if form.auth.data:
            return redirect(url_for('mfa.mfa_setup'))
        if in_login:
            del session['validated_user']
            if 'next' in session:
                del session['next']
            return redirect(url_for('user.login'))
        return redirect(url_for('user_profile_page'))
    return render_template('flask_user/mfa_choose.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"), description=Markup(word(
            """Which type of two-factor authentication would you like to use?  The first option is to use an authentication app like <a target="_blank" href="https://en.wikipedia.org/wiki/Google_Authenticator">Google Authenticator</a> or <a target="_blank" href="https://authy.com/">Authy</a>.  The second option is to receive a text (SMS) message containing a verification code.""")))


@mfa.route('/mfa_sms_setup', methods=['POST', 'GET'])
def mfa_sms_setup():
    in_login = False
    if current_user.is_authenticated:
        user = current_user
    elif 'validated_user' in session:
        in_login = True
        user = load_user(session['validated_user'])
    else:
        return ('File not found', 404)
    if twilio_config is None or not current_app.config['USE_MFA'] or not user.has_role(
            *current_app.config['MFA_ROLES']) or not user.social_id.startswith('local'):
        return ('File not found', 404)
    form = MFASMSSetupForm(request.form)
    user = load_user(user.id)
    if request.method == 'GET' and user.otp_secret is not None and user.otp_secret.startswith(':phone:'):
        form.phone_number.data = re.sub(r'^:phone:', '', user.otp_secret)
    if request.method == 'POST' and form.submit.data:
        phone_number = form.phone_number.data
        if docassemble.base.functions.phone_number_is_valid(phone_number):
            phone_number = docassemble.base.functions.phone_number_in_e164(phone_number)
            verification_code = random_digits(daconfig['verification code digits'])
            message = word("Your verification code is") + " " + str(verification_code) + "."
            success = docassemble.base.util.send_sms(to=phone_number, body=message)
            if success:
                session['phone_number'] = phone_number
                key = 'da:mfa:phone:' + str(phone_number) + ':code'
                pipe = r.pipeline()
                pipe.set(key, verification_code)
                pipe.expire(key, daconfig['verification code timeout'])
                pipe.execute()
                return redirect(url_for('mfa.mfa_verify_sms_setup'))
            flash(word("There was a problem sending the text message."), 'error')
            if in_login:
                del session['validated_user']
                if 'next' in session:
                    del session['next']
                return redirect(url_for('user.login'))
            return redirect(url_for('user_profile_page'))
        flash(word("Invalid phone number."), 'error')
    return render_template('flask_user/mfa_sms_setup.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"),
                           description=word("""Enter your phone number.  A confirmation code will be sent to you."""))


@mfa.route('/mfa_verify_sms_setup', methods=['POST', 'GET'])
def mfa_verify_sms_setup():
    in_login = False
    if current_user.is_authenticated:
        user = current_user
    elif 'validated_user' in session:
        in_login = True
        user = load_user(session['validated_user'])
    else:
        return ('File not found', 404)
    if 'phone_number' not in session or twilio_config is None or not current_app.config['USE_MFA'] or not user.has_role(
            *current_app.config['MFA_ROLES']) or not user.social_id.startswith('local'):
        return ('File not found', 404)
    form = MFAVerifySMSSetupForm(request.form)
    if request.method == 'POST' and form.submit.data:
        phone_number = session['phone_number']
        del session['phone_number']
        key = 'da:mfa:phone:' + str(phone_number) + ':code'
        verification_code = r.get(key)
        r.delete(key)
        supplied_verification_code = re.sub(r'[^0-9]', '', form.verification_code.data)
        if verification_code is None:
            flash(word('Your verification code was missing or expired'), 'error')
            return redirect(url_for('user_profile_page'))
        if verification_code.decode() == supplied_verification_code:
            user = load_user(user.id)
            user.otp_secret = ':phone:' + phone_number
            db.session.commit()
            if in_login:
                if 'next' in session:
                    next_url = session['next']
                    del session['next']
                else:
                    next_url = url_for('interview.interview_list', from_login='1')
                return docassemble_flask_user.views._do_login_user(user, next_url, False)
            flash(word("You are now set up with two factor authentication."), 'success')
            return redirect(url_for('user_profile_page'))
    return render_template('flask_user/mfa_verify_sms_setup.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"), description=word(
            'We just sent you a text message with a verification code.  Enter the verification code to proceed.'))


@mfa.route('/mfa_login', methods=['POST', 'GET'])
def mfa_login():
    if not current_app.config['USE_MFA']:
        logmessage("mfa_login: two factor authentication not configured")
        return ('File not found', 404)
    if 'validated_user' not in session:
        logmessage("mfa_login: validated_user not in session")
        return ('File not found', 404)
    user = load_user(session['validated_user'])
    if current_user.is_authenticated and current_user.id != user.id:
        del session['validated_user']
        return ('File not found', 404)
    if user is None or user.otp_secret is None or not user.social_id.startswith('local'):
        logmessage("mfa_login: user not setup for MFA where validated_user was " + str(session['validated_user']))
        return ('File not found', 404)
    form = MFALoginForm(request.form)
    if not form.next.data:
        form.next.data = get_safe_next_param('next', url_for('interview.interview_list', from_login='1'))
    if request.method == 'POST' and form.submit.data:
        del session['validated_user']
        if 'next' in session:
            safe_next = session['next']
            del session['next']
        else:
            safe_next = form.next.data
        fail_key = 'da:failedlogin:ip:' + str(get_requester_ip(request))
        failed_attempts = r.get(fail_key)
        if failed_attempts is not None and int(failed_attempts) > daconfig['attempt limit']:
            return ('File not found', 404)
        supplied_verification_code = re.sub(r'[^0-9]', '', form.verification_code.data)
        if user.otp_secret.startswith(':phone:'):
            phone_number = re.sub(r'^:phone:', '', user.otp_secret)
            key = 'da:mfa:phone:' + str(phone_number) + ':code'
            verification_code = r.get(key)
            r.delete(key)
            if verification_code is None or supplied_verification_code != verification_code.decode():
                r.incr(fail_key)
                r.expire(fail_key, 86400)
                flash(word("Your verification code was invalid or expired."), 'error')
                return redirect(url_for('user.login'))
            if failed_attempts is not None:
                r.delete(fail_key)
        else:
            totp = pyotp.TOTP(user.otp_secret)
            if not totp.verify(supplied_verification_code):
                r.incr(fail_key)
                r.expire(fail_key, 86400)
                flash(word("Your verification code was invalid."), 'error')
                if 'validated_user' in session:
                    del session['validated_user']
                if 'next' in session:
                    return redirect(url_for('user.login', next=session['next']))
                return redirect(url_for('user.login'))
            if failed_attempts is not None:
                r.delete(fail_key)
        return docassemble_flask_user.views._do_login_user(user, safe_next, False)
    description = word("This account uses two-factor authentication.")
    if user.otp_secret.startswith(':phone:'):
        description += "  " + word("Please enter the verification code from the text message we just sent you.")
    else:
        description += "  " + word("Please enter the verification code from your authentication app.")
    return render_template('flask_user/mfa_login.html', form=form, version_warning=None,
                           title=word("Two-factor authentication"), tab_title=word("Authentication"),
                           page_title=word("Authentication"), description=description)
