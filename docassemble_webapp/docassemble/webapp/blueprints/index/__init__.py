import base64
import codecs
import copy
import datetime
import json
import os
import pickle
import re
import tempfile
from urllib.parse import quote as urllibquote

import dateutil
import dateutil.parser
import docassemble.base.DA
import docassemble.base.astparser
import docassemble.base.core
import docassemble.base.functions
import docassemble.base.interview_cache
import docassemble.base.parse
import docassemble.base.pdftk
import docassemble.base.util
import docassemble.webapp.backend
import docassemble.webapp.clicksend
import docassemble.webapp.machinelearning
import docassemble.webapp.setup
import docassemble.webapp.telnyx
import docassemble_flask_user.emails
import docassemble_flask_user.forms
import docassemble_flask_user.signals
import docassemble_flask_user.views
from PIL import Image
from bs4 import BeautifulSoup
from docassemble.base.config import daconfig
from docassemble.base.error import DAError, DAValidationError
from docassemble.base.functions import word
from docassemble.base.generate_key import random_string
from docassemble.base.logger import logmessage
from docassemble.base.standardformatter import as_html
from docassemble.webapp.authentication import current_info, decrypt_session, delete_session_for_interview, \
    delete_session_info, delete_session_sessions, encrypt_session, get_existing_session, manual_checkout, reset_session, \
    save_user_dict, save_user_dict_key
from docassemble.webapp.backend import advance_progress, clear_session, decrypt_phrase, encrypt_phrase, \
    fetch_previous_user_dict, fetch_user_dict, file_privilege_access, file_set_attributes, file_user_access, \
    generate_csrf, get_new_file_number, get_session, guess_yaml_filename, pack_phrase, reset_user_dict, unpack_phrase, \
    update_session, url_for
from docassemble.webapp.config_server import ALLOW_REGISTRATION, BUTTON_COLOR_NAV_LOGIN, CHECKIN_INTERVAL, \
    DEFAULT_DIALECT, DEFAULT_LANGUAGE, NOTIFICATION_CONTAINER, NOTIFICATION_MESSAGE, PREVENT_DEMO, REQUIRE_IDEMPOTENT, \
    ROOT, SHOW_LOGIN, STRICT_MODE, analytics_configured, audio_mimetype_table, default_short_title, default_title, \
    exit_page, final_default_yaml_filename, ga_configured, google_config, index_path, is_integer, \
    key_requires_preassembly, main_page_parts, match_brackets, match_inside_and_outside_brackets, match_inside_brackets, \
    reserved_argnames, valid_voicerss_dialects, voicerss_config
from docassemble.webapp.core.models import MachineLearning, SpeakList
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.package import get_url_from_file_reference
from docassemble.webapp.page_values import additional_css, additional_scripts, exit_href, navigation_bar, \
    standard_html_start, standard_scripts
from docassemble.webapp.screenreader import to_text
from docassemble.webapp.users.models import TempUser
from docassemble.webapp.util import MD5Hash, add_referer, as_int, do_redirect, fresh_dictionary, from_safeid, \
    get_history, get_part, illegal_variable_name, indent_by, is_mobile_or_tablet, \
    myb64unquote, process_bracket_expression, process_file, process_set_variable, refresh_or_continue, safeid, \
    secure_filename, sub_indices, tidy_action, title_converter, update_current_info_with_session_info
from docassemble_textstat.textstat import textstat
from flask import Blueprint, current_app, flash, get_flashed_messages, jsonify, make_response, redirect, \
    render_template, request, send_file, session
from flask_login import current_user, logout_user
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import YamlLexer
from sqlalchemy import select

indexBp = Blueprint('index', __name__, template_folder='templates')

def _call_or_get(function_or_property):
    return function_or_property() if callable(function_or_property) else function_or_property

def populate_social(social, metadata):
    for key in ('image', 'description'):
        if key in metadata:
            if metadata[key] is None:
                if key in social:
                    del social[key]
            elif isinstance(metadata[key], str):
                social[key] = metadata[key].replace('\n', ' ').replace('"', '&quot;').strip()
    for key in ('og', 'fb', 'twitter'):
        if key in metadata and isinstance(metadata[key], dict):
            for subkey, val in metadata[key].items():
                if val is None:
                    if subkey in social[key]:
                        del social[key][subkey]
                elif isinstance(val, str):
                    social[key][subkey] = val.replace('\n', ' ').replace('"', '&quot;').strip()


def progress_bar(progress, interview):
    if progress is None:
        return ''
    progress = float(progress)
    if progress <= 0:
        return ''
    return render_template(
        "progress_bar.html",
        progress=min(progress, 100),
        show_progress_bar_percentage=(
                hasattr(interview, 'show_progress_bar_percentage') and
                interview.show_progress_bar_percentage
        )
    )


def do_refresh(is_ajax, yaml_filename):
    if is_ajax:
        return jsonify(action='refresh', csrf_token=generate_csrf())
    return redirect(url_for('index.index', i=yaml_filename))


def add_action_to_stack(interview_status, user_dict, action, arguments):
    unique_id = interview_status.current_info['user']['session_uid']
    if 'event_stack' not in user_dict['_internal']:
        user_dict['_internal']['event_stack'] = {}
    if unique_id not in user_dict['_internal']['event_stack']:
        user_dict['_internal']['event_stack'][unique_id] = []
    if len(user_dict['_internal']['event_stack'][unique_id]) > 0 and \
            user_dict['_internal']['event_stack'][unique_id][0]['action'] == action and \
            user_dict['_internal']['event_stack'][unique_id][0]['arguments'] == arguments:
        user_dict['_internal']['event_stack'][unique_id].pop(0)
    user_dict['_internal']['event_stack'][unique_id].insert(0, {'action': action, 'arguments': arguments})


def make_navbar(status, steps, show_login, chat_info, debug_mode, index_params, extra_class=None):
    if 'inverse navbar' in status.question.interview.options:
        if status.question.interview.options['inverse navbar']:
            inverse = 'navbar-dark bg-dark '
        else:
            inverse = 'navbar-light bg-light '
    elif daconfig.get('inverse navbar', True):
        inverse = 'navbar-dark bg-dark '
    else:
        inverse = 'navbar-light bg-light '
    fixed_top = ''
    if 'jsembed' in docassemble.base.functions.this_thread.misc:
        fixed_top = ''
    else:
        fixed_top = ' fixed-top'
    if extra_class is not None:
        fixed_top += ' ' + extra_class
    if status.question.interview.question_help_button:
        the_sections = status.interviewHelpText
    else:
        the_sections = status.helpText + status.interviewHelpText
    help_label = None
    for help_section in the_sections:
        if help_section['label']:
            help_label = help_section['label']
            break
    if help_label is None:
        help_label = status.extras.get('help label text', None)
    if help_label is None:
        help_label = status.question.help()

    if 'menu_items' in status.extras:
        if not isinstance(status.extras['menu_items'], list):
            custom_menu = '<a tabindex="-1" class="dropdown-item">' + word(
                "Error: menu_items is not a Python list") + '</a>'
        elif len(status.extras['menu_items']) > 0:
            custom_menu = ""
            for menu_item in status.extras['menu_items']:
                if not (isinstance(menu_item, dict) and 'url' in menu_item and 'label' in menu_item):
                    custom_menu += '<a tabindex="-1" class="dropdown-item">' + word(
                        "Error: menu item is not a Python dict with keys of url and label") + '</li>'
                else:
                    screen_size = menu_item.get('screen_size', '')
                    if screen_size == 'small':
                        menu_item_classes = ' d-block d-md-none'
                    elif screen_size == 'large':
                        menu_item_classes = ' d-none d-md-block'
                    else:
                        menu_item_classes = ''
                    match_action = re.search(r'^\?action=([^&]+)', menu_item['url'])
                    if match_action:
                        custom_menu += '<a class="dropdown-item' + menu_item_classes + '" data-embaction="' + match_action.group(
                            1) + '" href="' + menu_item['url'] + '">' + menu_item['label'] + '</a>'
                    else:
                        custom_menu += '<a class="dropdown-item' + menu_item_classes + '" href="' + menu_item[
                            'url'] + '">' + menu_item['label'] + '</a>'
        else:
            custom_menu = False
    else:
        custom_menu = False
    if daconfig.get('resume interview after login', False):
        login_url = url_for('user.login', next=url_for('index.index', **index_params))
    else:
        login_url = url_for('user.login')

    if ALLOW_REGISTRATION:
        sign_in_text = word('Sign in or sign up to save answers')
    else:
        sign_in_text = word('Sign in to save answers')
    navbar = render_template(
        "navbar.html",
        fixed_top=fixed_top,
        inverse=inverse,
        navigation_back_button=status.question.interview.navigation_back_button,
        exit_label=status.exit_label,
        can_go_back=status.question.can_go_back,
        steps=steps,
        index_url=url_for('index.index', **index_params),
        csrf_token=generate_csrf(),
        corner_back=status.cornerback,
        title_url=status.title_url,
        title_url_opens_in_other_window=not (str(status.title_url_opens_in_other_window) == 'False'),
        display_title=status.display_title,
        display_short_title=status.display_short_title,
        interview_help_text=status.interviewHelpText,
        help_text=status.helpText,
        help_label=help_label,
        question_help_button=status.question.interview.question_help_button,
        question_help_text=status.question.helptext,
        debug_mode=debug_mode,
        nav_item=status.nav_item,
        current_user=current_user,
        show_login=show_login,
        custom_menu=custom_menu,
        login_url=login_url,
        sign_in_text=sign_in_text,
        resume_after_login=daconfig.get('resume interview after login', False),
        login_style=daconfig.get('login link style', 'normal'),
        ALLOW_REGISTRATION=ALLOW_REGISTRATION,
        hide_standard_menu=status.question.interview.options.get('hide standard menu', False),
        user_link_text=(current_user.email if current_user.email else re.sub(r'.*\$', '', current_user.social_id)) if _call_or_get(current_user.is_authenticated) else "",
        ENABLE_MONITOR=current_app.config['ENABLE_MONITOR'],
        ALLOW_UPDATES=current_app.config['ALLOW_UPDATES'],
        SHOW_DISPATCH=current_app.config['SHOW_DISPATCH'],
        ADMIN_INTERVIEWS=current_app.config['ADMIN_INTERVIEWS'],
        yaml_filename=docassemble.base.functions.this_thread.current_info.get('yaml_filename', ''),
        language=docassemble.base.functions.get_language(),
        SHOW_MY_INTERVIEWS=current_app.config['SHOW_MY_INTERVIEWS'],
        BUTTON_COLOR_NAV_LOGIN=BUTTON_COLOR_NAV_LOGIN,
        exit_href=exit_href(status)
    )



    return navbar


def add_permissions_for_field(the_field, interview_status, files_to_process):
    if hasattr(the_field, 'permissions'):
        if the_field.number in interview_status.extras['permissions']:
            permissions = interview_status.extras['permissions'][the_field.number]
            if 'private' in permissions or 'persistent' in permissions:
                for (filename, file_number, mimetype, extension) in files_to_process:
                    attribute_args = {}
                    if 'private' in permissions:
                        attribute_args['private'] = permissions['private']
                    if 'persistent' in permissions:
                        attribute_args['persistent'] = permissions['persistent']
                    file_set_attributes(file_number, **attribute_args)
            if 'allow_users' in permissions:
                for (filename, file_number, mimetype, extension) in files_to_process:
                    allow_user_id = []
                    allow_email = []
                    for item in permissions['allow_users']:
                        if isinstance(item, int):
                            allow_user_id.append(item)
                        else:
                            allow_email.append(item)
                    file_user_access(file_number, allow_user_id=allow_user_id, allow_email=allow_email)
            if 'allow_privileges' in permissions:
                for (filename, file_number, mimetype, extension) in files_to_process:
                    file_privilege_access(file_number, allow=permissions['allow_privileges'])


def ensure_training_loaded(interview):
    source_filename = interview.get_ml_store()
    parts = source_filename.split(':')
    if len(parts) == 3 and parts[0].startswith('docassemble.') and re.match(r'data/sources/.*\.json$', parts[1]):
        the_file = docassemble.base.functions.package_data_filename(source_filename)
        if the_file is not None:
            record = db.session.execute(
                select(MachineLearning.group_id).where(MachineLearning.group_id.like(source_filename + ':%'))).first()
            if record is None:
                if os.path.isfile(the_file):
                    with open(the_file, 'r', encoding='utf-8') as fp:
                        content = fp.read()
                    if len(content) > 0:
                        try:
                            href = json.loads(content)
                            if isinstance(href, dict):
                                nowtime = datetime.datetime.utcnow()
                                for group_id, train_list in href.items():
                                    if isinstance(train_list, list):
                                        for entry in train_list:
                                            if 'independent' in entry:
                                                depend = entry.get('dependent', None)
                                                if depend is not None:
                                                    new_entry = MachineLearning(
                                                        group_id=source_filename + ':' + group_id,
                                                        independent=codecs.encode(pickle.dumps(entry['independent']),
                                                                                  'base64').decode(),
                                                        dependent=codecs.encode(pickle.dumps(depend),
                                                                                'base64').decode(), modtime=nowtime,
                                                        create_time=nowtime, active=True, key=entry.get('key', None))
                                                else:
                                                    new_entry = MachineLearning(
                                                        group_id=source_filename + ':' + group_id,
                                                        independent=codecs.encode(pickle.dumps(entry['independent']),
                                                                                  'base64').decode(), modtime=nowtime,
                                                        create_time=nowtime, active=False, key=entry.get('key', None))
                                                db.session.add(new_entry)
                                db.session.commit()
                            else:
                                logmessage(
                                    "ensure_training_loaded: source filename " + source_filename + " not used because it did not contain a dict")
                        except:
                            logmessage(
                                "ensure_training_loaded: source filename " + source_filename + " not used because it did not contain valid JSON")
                    else:
                        logmessage(
                            "ensure_training_loaded: source filename " + source_filename + " not used because its content was empty")
                else:
                    logmessage(
                        "ensure_training_loaded: source filename " + source_filename + " not used because it did not exist")
            else:
                logmessage(
                    "ensure_training_loaded: source filename " + source_filename + " not used because training data existed")
        else:
            logmessage("ensure_training_loaded: source filename " + source_filename + " did not exist")
    else:
        logmessage("ensure_training_loaded: source filename " + source_filename + " was not part of a package")


def fake_up(response, interview_language):
    response.set_data(
        '<!DOCTYPE html><html lang="' + interview_language + '"><head><meta charset="utf-8"><title>Response</title></head><body><pre>ABCDABOUNDARYSTARTABC' + codecs.encode(
            response.get_data(), 'base64').decode() + 'ABCDABOUNDARYENDABC</pre></body></html>')
    response.headers['Content-type'] = 'text/html; charset=utf-8'


def make_response_wrapper(set_cookie, secret, set_device_id, device_id, expire_visitor_secret):
    def the_wrapper(response):
        if set_cookie:
            response.set_cookie('secret', secret, httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                                samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
        if expire_visitor_secret:
            response.set_cookie('visitor_secret', '', expires=0)
        if set_device_id:
            response.set_cookie('ds', device_id, httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                                samesite=current_app.config['SESSION_COOKIE_SAMESITE'],
                                expires=datetime.datetime.now() + datetime.timedelta(weeks=520))

    return the_wrapper


@indexBp.route(index_path, methods=['POST', 'GET'])
def index(action_argument=None, refer=None):
    is_ajax = bool(request.method == 'POST' and 'ajax' in request.form and int(request.form['ajax']))
    docassemble.base.functions.this_thread.misc['call'] = refer
    return_fake_html = False
    if (request.method == 'POST' and 'json' in request.form and as_int(request.form['json'])) or (
            'json' in request.args and as_int(request.args['json'])):
        the_interface = 'json'
        is_json = True
        is_js = False
        js_target = False
    elif 'js_target' in request.args and request.args['js_target'] != '':
        the_interface = 'web'
        is_json = False
        docassemble.base.functions.this_thread.misc['jsembed'] = request.args['js_target']
        if is_ajax:
            js_target = False
        else:
            js_target = request.args['js_target']
            is_js = True
    else:
        the_interface = 'web'
        is_json = False
        is_js = False
        js_target = False
    if current_user.is_anonymous:
        if 'tempuser' not in session:
            new_temp_user = TempUser()
            db.session.add(new_temp_user)
            db.session.commit()
            session['tempuser'] = new_temp_user.id
    else:
        if 'user_id' not in session:
            session['user_id'] = current_user.id
    expire_visitor_secret = False
    if 'visitor_secret' in request.cookies:
        if 'session' in request.args:
            secret = request.cookies.get('secret', None)
            expire_visitor_secret = True
        else:
            secret = request.cookies['visitor_secret']
    else:
        secret = request.cookies.get('secret', None)
    use_cache = int(request.args.get('cache', 1))
    reset_interview = int(request.args.get('reset', 0))
    new_interview = int(request.args.get('new_session', 0))
    if secret is None:
        secret = random_string(16)
        set_cookie = True
        set_device_id = True
    else:
        secret = str(secret)
        set_cookie = False
        set_device_id = False
    device_id = request.cookies.get('ds', None)
    if device_id is None:
        device_id = random_string(16)
        set_device_id = True
    steps = 1
    need_to_reset = False
    if 'i' not in request.args and 'state' in request.args:
        try:
            yaml_filename = re.sub(r'\^.*', '', from_safeid(request.args['state']))
        except:
            yaml_filename = guess_yaml_filename()
    else:
        yaml_filename = request.args.get('i', guess_yaml_filename())
    if yaml_filename is None:
        if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
            current_app.logger.error(
                "Redirecting to login because no YAML filename provided and no anonymous access is allowed.\n")
            return redirect(url_for('user.login'))
        if len(daconfig['dispatch']) > 0:
            current_app.logger.error("Redirecting to dispatch page because no YAML filename provided.\n")
            return redirect(url_for('interview.interview_start'))
        yaml_filename = final_default_yaml_filename
    action = None
    if '_action' in request.form and 'in error' not in session:
        action = tidy_action(json.loads(myb64unquote(request.form['_action'])))
        no_defs = True
    elif 'action' in request.args and 'in error' not in session:
        action = tidy_action(json.loads(myb64unquote(request.args['action'])))
        no_defs = True
    elif action_argument:
        action = tidy_action(action_argument)
        no_defs = False
    else:
        no_defs = False
    disregard_input = not bool(request.method == 'POST' and not no_defs)
    if disregard_input:
        post_data = {}
    else:
        post_data = request.form.copy()
    if current_user.is_anonymous:
        the_user_id = 't' + str(session['tempuser'])
    else:
        the_user_id = current_user.id
    if '_track_location' in post_data and post_data['_track_location']:
        the_location = json.loads(post_data['_track_location'])
    else:
        the_location = None
    session_info = get_session(yaml_filename)
    session_parameter = request.args.get('session', None)
    the_current_info = current_info(yaml=yaml_filename, req=request, action=None, location=the_location,
                                    interface=the_interface, session_info=session_info, secret=secret,
                                    device_id=device_id)
    docassemble.base.functions.this_thread.current_info = the_current_info
    if session_info is None or reset_interview or new_interview:
        was_new = True
        if (PREVENT_DEMO) and (
                yaml_filename.startswith('docassemble.base:') or yaml_filename.startswith('docassemble.demo:')) and (
                current_user.is_anonymous or not (
                current_user.has_role('admin', 'developer') or current_user.can_do('demo_interviews'))):
            raise DAError(word("Not authorized"), code=403)
        if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
            current_app.logger.error("Redirecting to login because no anonymous access allowed.\n")
            return redirect(url_for('user.login', next=url_for('index.index', **request.args)))
        if yaml_filename.startswith('docassemble.playground'):
            if not current_app.config['ENABLE_PLAYGROUND']:
                raise DAError(word("Not authorized"), code=403)
        else:
            yaml_filename = re.sub(r':([^\/]+)$', r':data/questions/\1', yaml_filename)
            docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
        show_flash = False
        interview = docassemble.base.interview_cache.get_interview(yaml_filename)
        if session_info is None and request.args.get('from_list', None) is None and not yaml_filename.startswith(
                "docassemble.playground") and not yaml_filename.startswith(
            "docassemble.base") and not yaml_filename.startswith(
            "docassemble.demo") and SHOW_LOGIN and not new_interview and len(session['sessions']) > 0:
            show_flash = True
        if current_user.is_authenticated and current_user.has_role('admin', 'developer', 'advocate'):
            show_flash = False
        if session_parameter is None:
            if show_flash:
                if current_user.is_authenticated:
                    message = "Starting a new interview.  To go back to your previous interview, go to My Interviews on the menu."
                else:
                    message = "Starting a new interview.  To go back to your previous interview, log in to see a list of your interviews."
            if reset_interview and session_info is not None:
                reset_user_dict(session_info['uid'], yaml_filename)
            unique_sessions = interview.consolidated_metadata.get('sessions are unique', False)
            if unique_sessions is not False and not current_user.is_authenticated:
                delete_session_for_interview(yaml_filename)
                flash(word("You need to be logged in to access this interview."), "info")
                current_app.logger.error("Redirecting to login because sessions are unique.\n")
                return redirect(url_for('user.login', next=url_for('index.index', **request.args)))
            if interview.consolidated_metadata.get('temporary session', False):
                if session_info is not None:
                    reset_user_dict(session_info['uid'], yaml_filename)
                if current_user.is_authenticated:
                    while True:
                        session_id, encrypted = get_existing_session(yaml_filename, secret)
                        if session_id:
                            reset_user_dict(session_id, yaml_filename)
                        else:
                            break
                        the_current_info['session'] = session_id
                        the_current_info['encrypted'] = encrypted
                    reset_interview = 1
            if current_user.is_anonymous:
                if (not interview.allowed_to_initiate(is_anonymous=True)) or (
                        not interview.allowed_to_access(is_anonymous=True)):
                    delete_session_for_interview(yaml_filename)
                    flash(word("You need to be logged in to access this interview."), "info")
                    current_app.logger.error(
                        "Redirecting to login because anonymous user not allowed to access this interview.\n")
                    return redirect(url_for('user.login', next=url_for('index.index', **request.args)))
            elif not interview.allowed_to_initiate(has_roles=[role.name for role in current_user.roles]):
                delete_session_for_interview(yaml_filename)
                raise DAError(word("You are not allowed to access this interview."), code=403)
            elif not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                raise DAError(word('You are not allowed to access this interview.'), code=403)
            session_id = None
            if reset_interview == 2:
                delete_session_sessions()
            if (not reset_interview) and (unique_sessions is True or (
                    isinstance(unique_sessions, list) and len(unique_sessions) and current_user.has_role(
                *unique_sessions))):
                session_id, encrypted = get_existing_session(yaml_filename, secret)
            if session_id is None:
                user_code, user_dict = reset_session(yaml_filename, secret)
                add_referer(user_dict)
                save_user_dict(user_code, user_dict, yaml_filename, secret=secret)
                release_lock(user_code, yaml_filename)
                need_to_reset = True
            session_info = get_session(yaml_filename)
            update_current_info_with_session_info(the_current_info, session_info)
        else:
            unique_sessions = interview.consolidated_metadata.get('sessions are unique', False)
            if unique_sessions is not False and not current_user.is_authenticated:
                delete_session_for_interview(yaml_filename)
                flash(word("You need to be logged in to access this interview."), "info")
                current_app.logger.error("Redirecting to login because sessions are unique.\n")
                return redirect(url_for('user.login', next=url_for('index.index', **request.args)))
            if current_user.is_anonymous:
                if (not interview.allowed_to_initiate(is_anonymous=True)) or (
                        not interview.allowed_to_access(is_anonymous=True)):
                    delete_session_for_interview(yaml_filename)
                    flash(word("You need to be logged in to access this interview."), "info")
                    current_app.logger.error(
                        "Redirecting to login because anonymous user not allowed to access this interview.\n")
                    return redirect(url_for('user.login', next=url_for('index.index', **request.args)))
            elif not interview.allowed_to_initiate(has_roles=[role.name for role in current_user.roles]):
                delete_session_for_interview(yaml_filename)
                raise DAError(word("You are not allowed to access this interview."), code=403)
            elif not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                raise DAError(word('You are not allowed to access this interview.'), code=403)
            if reset_interview:
                reset_user_dict(session_parameter, yaml_filename)
                if reset_interview == 2:
                    delete_session_sessions()
                user_code, user_dict = reset_session(yaml_filename, secret)
                add_referer(user_dict)
                save_user_dict(user_code, user_dict, yaml_filename, secret=secret)
                release_lock(user_code, yaml_filename)
                session_info = get_session(yaml_filename)
                update_current_info_with_session_info(the_current_info, session_info)
                need_to_reset = True
            else:
                session_info = update_session(yaml_filename, uid=session_parameter)
                update_current_info_with_session_info(the_current_info, session_info)
                need_to_reset = True
            if show_flash:
                if current_user.is_authenticated:
                    message = "Entering a different interview.  To go back to your previous interview, go to My Interviews on the menu."
                else:
                    message = "Entering a different interview.  To go back to your previous interview, log in to see a list of your interviews."
        if show_flash:
            flash(word(message), 'info')
    else:
        was_new = False
        if session_parameter is not None and not need_to_reset:
            session_info = update_session(yaml_filename, uid=session_parameter)
            update_current_info_with_session_info(the_current_info, session_info)
            need_to_reset = True
    user_code = session_info['uid']
    encrypted = session_info['encrypted']
    obtain_lock(user_code, yaml_filename)
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(user_code, yaml_filename, secret=secret)
    except Exception as the_err:
        try:
            current_app.logger.error("index: there was an exception " + str(the_err.__class__.__name__) + ": " + str(
                the_err) + " after fetch_user_dict with %s and %s, so we need to reset\n" % (user_code, yaml_filename))
        except:
            current_app.logger.error("index: there was an exception " + str(
                the_err.__class__.__name__) + " after fetch_user_dict with %s and %s, so we need to reset\n" % (
                                         user_code, yaml_filename))
        release_lock(user_code, yaml_filename)
        logmessage("index: dictionary fetch failed")
        clear_session(yaml_filename)
        if session_parameter is not None:
            redirect_url = daconfig.get('session error redirect url', None)
            if isinstance(redirect_url, str) and redirect_url:
                redirect_url = redirect_url.format(i=urllibquote(yaml_filename),
                                                   error=urllibquote('answers_fetch_fail'))
                current_app.logger.error("Session error because failure to get user dictionary.\n")
                return do_redirect(redirect_url, is_ajax, is_json, js_target)
        current_app.logger.error("Redirecting back to index because of failure to get user dictionary.\n")
        response = do_redirect(url_for('index.index', i=yaml_filename), is_ajax, is_json, js_target)
        if session_parameter is not None:
            flash(word("Unable to retrieve interview session.  Starting a new session instead."), "error")
        return response
    if user_dict is None:
        current_app.logger.error(
            "index: no user_dict found after fetch_user_dict with %s and %s, so we need to reset\n" % (
                user_code, yaml_filename))
        release_lock(user_code, yaml_filename)
        logmessage("index: dictionary fetch returned no results")
        clear_session(yaml_filename)
        redirect_url = daconfig.get('session error redirect url', None)
        if isinstance(redirect_url, str) and redirect_url:
            redirect_url = redirect_url.format(i=urllibquote(yaml_filename), error=urllibquote('answers_missing'))
            current_app.logger.error("Session error because user dictionary was None.\n")
            return do_redirect(redirect_url, is_ajax, is_json, js_target)
        current_app.logger.error("Redirecting back to index because user dictionary was None.\n")
        response = do_redirect(url_for('index.index', i=yaml_filename), is_ajax, is_json, js_target)
        flash(word("Unable to locate interview session.  Starting a new session instead."), "error")
        return response
    if encrypted != is_encrypted:
        update_session(yaml_filename, encrypted=is_encrypted)
        encrypted = is_encrypted
    if user_dict.get('multi_user', False) is True and encrypted is True:
        encrypted = False
        update_session(yaml_filename, encrypted=encrypted)
        decrypt_session(secret, user_code=user_code, filename=yaml_filename)
    if user_dict.get('multi_user', False) is False and encrypted is False:
        encrypt_session(secret, user_code=user_code, filename=yaml_filename)
        encrypted = True
        update_session(yaml_filename, encrypted=encrypted)
    the_current_info['encrypted'] = encrypted
    if not session_info['key_logged']:
        save_user_dict_key(user_code, yaml_filename)
        update_session(yaml_filename, key_logged=True)
    url_args_changed = False
    if len(request.args) > 0:
        for argname in request.args:
            if argname in reserved_argnames:
                continue
            if not url_args_changed:
                old_url_args = copy.deepcopy(user_dict['url_args'])
                url_args_changed = True
            exec("url_args[" + repr(argname) + "] = " + repr(request.args.get(argname)), user_dict)
        if url_args_changed:
            if old_url_args == user_dict['url_args']:
                url_args_changed = False
    index_params = dict(i=yaml_filename)
    if analytics_configured:
        for argname in request.args:
            if argname in ('utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content'):
                index_params[argname] = request.args[argname]
    if need_to_reset or set_device_id:
        if use_cache == 0:
            docassemble.base.parse.interview_source_from_string(yaml_filename).update_index()
        response_wrapper = make_response_wrapper(set_cookie, secret, set_device_id, device_id, expire_visitor_secret)
    else:
        response_wrapper = None
    interview = docassemble.base.interview_cache.get_interview(yaml_filename)
    interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info,
                                                              tracker=user_dict['_internal']['tracker'])
    old_user_dict = None
    if '_back_one' in post_data and steps > 1:
        ok_to_go_back = True
        if STRICT_MODE:
            interview.assemble(user_dict, interview_status=interview_status)
            if not interview_status.question.can_go_back:
                ok_to_go_back = False
        if ok_to_go_back:
            action = None
            the_current_info = current_info(yaml=yaml_filename, req=request, action=action, location=the_location,
                                            interface=the_interface, session_info=session_info, secret=secret,
                                            device_id=device_id)
            docassemble.base.functions.this_thread.current_info = the_current_info
            old_user_dict = user_dict
            steps, user_dict, is_encrypted = fetch_previous_user_dict(user_code, yaml_filename, secret)
            if encrypted != is_encrypted:
                encrypted = is_encrypted
                update_session(yaml_filename, encrypted=encrypted)
            the_current_info['encrypted'] = encrypted
            interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info,
                                                                      tracker=user_dict['_internal']['tracker'])
            post_data = {}
            disregard_input = True
    known_varnames = {}
    if '_varnames' in post_data:
        known_varnames = json.loads(myb64unquote(post_data['_varnames']))
    if '_visible' in post_data and post_data['_visible'] != "":
        visible_field_names = json.loads(myb64unquote(post_data['_visible']))
    else:
        visible_field_names = []
    known_varnames_visible = {}
    for key, val in known_varnames.items():
        if key in visible_field_names:
            known_varnames_visible[key] = val
    all_field_numbers = {}
    field_numbers = {}
    numbered_fields = {}
    visible_fields = set()
    raw_visible_fields = set()
    for field_name in visible_field_names:
        try:
            m = re.search(r'(.*)(\[[^\]]+\])$', from_safeid(field_name))
            if m:
                if safeid(m.group(1)) in known_varnames:
                    visible_fields.add(safeid(from_safeid(known_varnames[safeid(m.group(1))]) + m.group(2)))
        except Exception as the_err:
            pass
        raw_visible_fields.add(field_name)
        if field_name in known_varnames:
            visible_fields.add(known_varnames[field_name])
        else:
            visible_fields.add(field_name)
    for kv_key, kv_var in known_varnames.items():
        try:
            field_identifier = myb64unquote(kv_key)
            m = re.search(r'_field(?:_[0-9]+)?_([0-9]+)', field_identifier)
            if m:
                numbered_fields[kv_var] = kv_key
                if kv_key in raw_visible_fields or kv_var in raw_visible_fields:
                    field_numbers[kv_var] = int(m.group(1))
            m = re.search(r'_field_((?:[0-9]+_)?[0-9]+)', field_identifier)
            if m:
                if kv_var not in all_field_numbers:
                    all_field_numbers[kv_var] = set()
                if '_' in m.group(1):
                    all_field_numbers[kv_var].add(m.group(1))
                else:
                    all_field_numbers[kv_var].add(int(m.group(1)))
        except:
            logmessage("index: error where kv_key is " + str(kv_key) + " and kv_var is " + str(kv_var))
    list_collect_list = None
    if not STRICT_MODE:
        if '_list_collect_list' in post_data:
            the_list = json.loads(myb64unquote(post_data['_list_collect_list']))
            if not illegal_variable_name(the_list):
                list_collect_list = the_list
                exec(list_collect_list + '._allow_appending()', user_dict)
        if '_checkboxes' in post_data:
            checkbox_fields = json.loads(myb64unquote(post_data['_checkboxes']))  # post_data['_checkboxes'].split(",")
            for checkbox_field, checkbox_value in checkbox_fields.items():
                if checkbox_field in visible_fields and checkbox_field not in post_data and not (
                        checkbox_field in numbered_fields and numbered_fields[checkbox_field] in post_data):
                    post_data.add(checkbox_field, checkbox_value)
        if '_empties' in post_data:
            empty_fields = json.loads(myb64unquote(post_data['_empties']))
            for empty_field in empty_fields:
                if empty_field not in post_data:
                    post_data.add(empty_field, 'None')
        else:
            empty_fields = {}
        if '_ml_info' in post_data:
            ml_info = json.loads(myb64unquote(post_data['_ml_info']))
        else:
            ml_info = {}
    something_changed = False
    if '_tracker' in post_data and re.search(r'^-?[0-9]+$', post_data['_tracker']) and user_dict['_internal'][
        'tracker'] != int(post_data['_tracker']):
        if user_dict['_internal']['tracker'] > int(post_data['_tracker']):
            logmessage("index: the assemble function has been run since the question was posed.")
        else:
            logmessage("index: the tracker in the dictionary is behind the tracker in the question.")
        something_changed = True
        user_dict['_internal']['tracker'] = max(int(post_data['_tracker']), user_dict['_internal']['tracker'])
        interview_status.tracker = user_dict['_internal']['tracker']
    should_assemble = False
    known_datatypes = {}
    if not STRICT_MODE:
        if '_datatypes' in post_data:
            known_datatypes = json.loads(myb64unquote(post_data['_datatypes']))
            for data_type in known_datatypes.values():
                if data_type.startswith('object'):
                    should_assemble = True
    if not should_assemble:
        for key in post_data:
            if key.startswith('_') or key in ('csrf_token', 'ajax', 'json', 'informed'):
                continue
            try:
                the_key = from_safeid(key)
                if the_key.startswith('_field_'):
                    if key in known_varnames:
                        if not (known_varnames[key] in post_data and post_data[known_varnames[key]] != '' and post_data[
                            key] == ''):
                            the_key = from_safeid(known_varnames[key])
                    else:
                        m = re.search(r'^(_field(?:_[0-9]+)?_[0-9]+)(\[.*\])', key)
                        if m:
                            base_orig_key = safeid(m.group(1))
                            if base_orig_key in known_varnames:
                                the_key = myb64unquote(known_varnames[base_orig_key]) + m.group(2)
                if key_requires_preassembly.search(the_key):
                    if the_key == '_multiple_choice' and '_question_name' in post_data:
                        if refresh_or_continue(interview, post_data):
                            continue
                    should_assemble = True
                    break
            except Exception as the_err:
                logmessage("index: bad key was " + str(key) + " and error was " + the_err.__class__.__name__)
                try:
                    logmessage("index: bad key error message was " + str(the_err))
                except:
                    pass
    if not interview.from_cache and len(interview.mlfields):
        ensure_training_loaded(interview)
    debug_mode = interview.debug
    vars_set = set()
    old_values = {}
    new_values = {}
    if (
            '_email_attachments' in post_data and '_attachment_email_address' in post_data) or '_download_attachments' in post_data:
        should_assemble = True
    error_messages = []
    already_assembled = False
    if (STRICT_MODE and not disregard_input) or should_assemble or something_changed:
        interview.assemble(user_dict, interview_status=interview_status)
        already_assembled = True
        if STRICT_MODE and (
                '_question_name' not in post_data or post_data['_question_name'] != interview_status.question.name):
            if refresh_or_continue(interview, post_data) is False and action is None and len(
                    [key for key in post_data if
                     not (key.startswith('_') or key in ('csrf_token', 'ajax', 'json', 'informed'))]) > 0:
                error_messages.append(("success", word("Input not processed.  Please try again.")))
            post_data = {}
            disregard_input = True
        elif should_assemble and '_question_name' in post_data and post_data[
            '_question_name'] != interview_status.question.name:
            logmessage("index: not the same question name: " + str(post_data['_question_name']) + " versus " + str(
                interview_status.question.name))
            if REQUIRE_IDEMPOTENT:
                error_messages.append(
                    ("success", word("Input not processed because the question changed.  Please continue.")))
                post_data = {}
                disregard_input = True
    if STRICT_MODE and not disregard_input:
        field_info = interview_status.get_field_info()
        known_datatypes = field_info['datatypes']
        list_collect_list = field_info['list_collect_list']
        if list_collect_list is not None:
            exec(list_collect_list + '._allow_appending()', user_dict)
        for checkbox_field, checkbox_value in field_info['checkboxes'].items():
            if checkbox_field in visible_fields and checkbox_field not in post_data and not (
                    checkbox_field in numbered_fields and numbered_fields[checkbox_field] in post_data):
                post_data.add(checkbox_field, checkbox_value)
        empty_fields = field_info['hiddens']
        for empty_field in empty_fields:
            if empty_field not in post_data:
                post_data.add(empty_field, 'None')
        ml_info = field_info['ml_info']
        authorized_fields = [from_safeid(field.saveas) for field in
                             interview_status.get_fields_and_sub_fields_and_collect_fields(user_dict) if
                             hasattr(field, 'saveas')]
        if 'allowed_to_set' in interview_status.extras:
            authorized_fields.extend(interview_status.extras['allowed_to_set'])
        if interview_status.question.question_type == "multiple_choice":
            authorized_fields.append('_multiple_choice')
        authorized_fields = set(authorized_fields).union(interview_status.get_all_fields_used(user_dict))
        if interview_status.extras.get('list_collect_is_final', False) and interview_status.extras[
            'list_collect'].auto_gather:
            if interview_status.extras['list_collect'].ask_number:
                authorized_fields.add(interview_status.extras['list_collect'].instanceName + ".target_number")
            else:
                authorized_fields.add(interview_status.extras['list_collect'].instanceName + ".there_is_another")
    else:
        if STRICT_MODE:
            empty_fields = []
        authorized_fields = set()
    changed = False
    if '_null_question' in post_data:
        changed = True
    if '_email_attachments' in post_data and '_attachment_email_address' in post_data:
        success = False
        attachment_email_address = post_data['_attachment_email_address'].strip()
        if '_attachment_include_editable' in post_data:
            include_editable = bool(post_data['_attachment_include_editable'] == 'True')
            del post_data['_attachment_include_editable']
        else:
            include_editable = False
        del post_data['_email_attachments']
        del post_data['_attachment_email_address']
        if len(interview_status.attachments) > 0:
            attached_file_count = 0
            attachment_info = []
            for the_attachment in interview_status.attachments:
                file_formats = []
                if 'pdf' in the_attachment['valid_formats'] or '*' in the_attachment['valid_formats']:
                    file_formats.append('pdf')
                if include_editable or 'pdf' not in file_formats:
                    if 'rtf' in the_attachment['valid_formats'] or '*' in the_attachment['valid_formats']:
                        file_formats.append('rtf')
                    if 'docx' in the_attachment['valid_formats']:
                        file_formats.append('docx')
                    if 'rtf to docx' in the_attachment['valid_formats']:
                        file_formats.append('rtf to docx')
                    if 'md' in the_attachment['valid_formats']:
                        file_formats.append('md')
                if 'raw' in the_attachment['valid_formats']:
                    file_formats.append('raw')
                for the_format in file_formats:
                    if the_format == 'raw':
                        attachment_info.append({'filename': str(the_attachment['filename']) + the_attachment['raw'],
                                                'number': the_attachment['file'][the_format],
                                                'mimetype': the_attachment['mimetype'][the_format],
                                                'attachment': the_attachment})
                    else:
                        attachment_info.append({'filename': str(the_attachment['filename']) + '.' + str(
                            docassemble.base.parse.extension_of_doc_format[the_format]),
                                                'number': the_attachment['file'][the_format],
                                                'mimetype': the_attachment['mimetype'][the_format],
                                                'attachment': the_attachment})
                    attached_file_count += 1
            worker_key = 'da:worker:uid:' + str(user_code) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
            for email_address in re.split(r' *[,;] *', attachment_email_address):
                try:
                    result = docassemble.webapp.worker.email_attachments.delay(user_code, email_address,
                                                                               attachment_info,
                                                                               docassemble.base.functions.get_language(),
                                                                               subject=interview_status.extras.get(
                                                                                   'email_subject', None),
                                                                               body=interview_status.extras.get(
                                                                                   'email_body', None),
                                                                               html=interview_status.extras.get(
                                                                                   'email_html', None))
                    r.rpush(worker_key, result.id)
                    success = True
                except Exception as errmess:
                    success = False
                    logmessage("index: failed with " + str(errmess))
                    break
            if success:
                flash(word("Your documents will be e-mailed to") + " " + str(attachment_email_address) + ".", 'success')
            else:
                flash(word("Unable to e-mail your documents to") + " " + str(attachment_email_address) + ".", 'error')
        else:
            flash(word("Unable to find documents to e-mail."), 'error')
    if '_download_attachments' in post_data:
        success = False
        if '_attachment_include_editable' in post_data:
            include_editable = bool(post_data['_attachment_include_editable'] == 'True')
            del post_data['_attachment_include_editable']
        else:
            include_editable = False
        del post_data['_download_attachments']
        if len(interview_status.attachments) > 0:
            attached_file_count = 0
            files_to_zip = []
            if 'zip_filename' in interview_status.extras and interview_status.extras['zip_filename']:
                zip_file_name = interview_status.extras['zip_filename']
            else:
                zip_file_name = 'file.zip'
            for the_attachment in interview_status.attachments:
                file_formats = []
                if 'pdf' in the_attachment['valid_formats'] or '*' in the_attachment['valid_formats']:
                    file_formats.append('pdf')
                if include_editable or 'pdf' not in file_formats:
                    if 'rtf' in the_attachment['valid_formats'] or '*' in the_attachment['valid_formats']:
                        file_formats.append('rtf')
                    if 'docx' in the_attachment['valid_formats']:
                        file_formats.append('docx')
                    if 'rtf to docx' in the_attachment['valid_formats']:
                        file_formats.append('rtf to docx')
                for the_format in file_formats:
                    files_to_zip.append(str(the_attachment['file'][the_format]))
                    attached_file_count += 1
            the_zip_file = docassemble.base.util.zip_file(*files_to_zip, filename=zip_file_name)
            response = send_file(the_zip_file.path(), mimetype='application/zip', as_attachment=True,
                                 attachment_filename=zip_file_name)
            response.headers[
                'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            if response_wrapper:
                response_wrapper(response)
            return response
    if '_the_image' in post_data and (STRICT_MODE is False or interview_status.question.question_type == 'signature'):
        if STRICT_MODE:
            file_field = from_safeid(field_info['signature_saveas'])
        else:
            file_field = from_safeid(post_data['_save_as'])
        if illegal_variable_name(file_field):
            error_messages.append(("error", "Error: Invalid character in file_field: " + str(file_field)))
        else:
            if not already_assembled:
                interview.assemble(user_dict, interview_status)
                already_assembled = True
            initial_string = 'import docassemble.base.util'
            try:
                exec(initial_string, user_dict)
            except Exception as errMess:
                error_messages.append(("error", "Error: " + str(errMess)))
            file_field_tr = sub_indices(file_field, user_dict)
            if '_success' in post_data and post_data['_success']:
                theImage = base64.b64decode(re.search(r'base64,(.*)', post_data['_the_image']).group(1) + '==')
                filename = secure_filename('canvas.png')
                file_number = get_new_file_number(user_code, filename, yaml_file_name=yaml_filename)
                extension, mimetype = get_ext_and_mimetype(filename)
                new_file = SavedFile(file_number, extension=extension, fix=True, should_not_exist=True)
                new_file.write_content(theImage, binary=True)
                new_file.finalize()
                the_string = file_field + " = docassemble.base.util.DAFile(" + repr(
                    file_field_tr) + ", filename='" + str(filename) + "', number=" + str(
                    file_number) + ", mimetype='" + str(mimetype) + "', make_pngs=True, extension='" + str(
                    extension) + "')"
            else:
                the_string = file_field + " = docassemble.base.util.DAFile(" + repr(file_field_tr) + ")"
            process_set_variable(file_field, user_dict, vars_set, old_values)
            try:
                exec(the_string, user_dict)
                changed = True
            except Exception as errMess:
                try:
                    current_app.logger.error(
                        errMess.__class__.__name__ + ": " + str(errMess) + " after running " + the_string)
                except:
                    pass
                error_messages.append(("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
    if '_next_action_to_set' in post_data:
        next_action_to_set = json.loads(myb64unquote(post_data['_next_action_to_set']))
    else:
        next_action_to_set = None
    next_action = None
    if '_question_name' in post_data and post_data['_question_name'] in interview.questions_by_name:
        if already_assembled:
            the_question = interview_status.question
        else:
            the_question = interview.questions_by_name[post_data['_question_name']]
        if not already_assembled:
            uses_permissions = False
            for the_field in the_question.fields:
                if hasattr(the_field, 'permissions'):
                    uses_permissions = True
            if uses_permissions or the_question.validation_code is not None:
                interview.assemble(user_dict, interview_status)
            else:
                for the_field in the_question.fields:
                    if hasattr(the_field, 'validate'):
                        interview.assemble(user_dict, interview_status)
                        break
    elif already_assembled:
        the_question = interview_status.question
    else:
        the_question = None
    key_to_orig_key = {}
    for orig_key in copy.deepcopy(post_data):
        if orig_key in (
                '_checkboxes', '_empties', '_ml_info', '_back_one', '_files', '_files_inline', '_question_name',
                '_the_image',
                '_save_as', '_success', '_datatypes', '_event', '_visible', '_tracker', '_track_location', '_varnames',
                '_next_action', '_next_action_to_set', 'ajax', 'json', 'informed', 'csrf_token', '_action',
                '_order_changes',
                '_collect', '_collect_delete', '_list_collect_list', '_null_question') or orig_key.startswith(
            '_ignore'):
            continue
        try:
            key = myb64unquote(orig_key)
        except:
            continue
        if key.startswith('_field_'):
            if orig_key in known_varnames:
                if not (known_varnames[orig_key] in post_data and post_data[known_varnames[orig_key]] != '' and
                        post_data[orig_key] == ''):
                    post_data[known_varnames[orig_key]] = post_data[orig_key]
                    key_to_orig_key[from_safeid(known_varnames[orig_key])] = orig_key
            else:
                m = re.search(r'^(_field(?:_[0-9]+)?_[0-9]+)(\[.*\])', key)
                if m:
                    base_orig_key = safeid(m.group(1))
                    if base_orig_key in known_varnames:
                        the_key = myb64unquote(known_varnames[base_orig_key]) + m.group(2)
                        key_to_orig_key[the_key] = orig_key
                        full_key = safeid(the_key)
                        post_data[full_key] = post_data[orig_key]
        if key.endswith('.gathered'):
            if STRICT_MODE and key not in authorized_fields:
                raise DAError("The variable " + repr(key) + " was not in the allowed fields, which were " + repr(
                    authorized_fields))
            objname = re.sub(r'\.gathered$', '', key)
            if illegal_variable_name(objname):
                error_messages.append(("error", "Error: Invalid key " + objname))
                break
            try:
                eval(objname, user_dict)
            except:
                safe_objname = safeid(objname)
                if safe_objname in known_datatypes:
                    if known_datatypes[safe_objname] in ('object_multiselect', 'object_checkboxes'):
                        docassemble.base.parse.ensure_object_exists(objname, 'object_checkboxes', user_dict)
                    elif known_datatypes[safe_objname] in ('multiselect', 'checkboxes'):
                        docassemble.base.parse.ensure_object_exists(objname, known_datatypes[safe_objname], user_dict)
    field_error = {}
    validated = True
    pre_user_dict = user_dict
    imported_core = False
    special_question = None
    for orig_key in post_data:
        if orig_key in (
                '_checkboxes', '_empties', '_ml_info', '_back_one', '_files', '_files_inline', '_question_name',
                '_the_image',
                '_save_as', '_success', '_datatypes', '_event', '_visible', '_tracker', '_track_location', '_varnames',
                '_next_action', '_next_action_to_set', 'ajax', 'json', 'informed', 'csrf_token', '_action',
                '_order_changes',
                '', '_collect', '_collect_delete', '_list_collect_list', '_null_question') or orig_key.startswith(
            '_ignore'):
            continue
        data = post_data[orig_key]
        try:
            key = myb64unquote(orig_key)
        except:
            raise DAError("index: invalid name " + str(orig_key))
        if key.startswith('_field_'):
            continue
        bracket_expression = None
        if orig_key in empty_fields:
            set_to_empty = empty_fields[orig_key]
        else:
            set_to_empty = None
        if match_brackets.search(key):
            match = match_inside_and_outside_brackets.search(key)
            try:
                key = match.group(1)
            except:
                try:
                    error_message = "index: invalid bracket name " + str(match.group(1)) + " in " + repr(key)
                except:
                    error_message = "index: invalid bracket name in " + repr(key)
                raise DAError(error_message)
            real_key = safeid(key)
            b_match = match_inside_brackets.search(match.group(2))
            if b_match:
                if b_match.group(1) in ('B', 'R'):
                    try:
                        bracket_expression = from_safeid(b_match.group(2))
                    except:
                        bracket_expression = b_match.group(2)
                else:
                    bracket_expression = b_match.group(2)
            bracket = match_inside_brackets.sub(process_bracket_expression, match.group(2))
            parse_result = docassemble.base.parse.parse_var_name(key)
            if not parse_result['valid']:
                error_messages.append(("error", "Error: Invalid key " + key + ": " + parse_result['reason']))
                break
            pre_bracket_key = key
            key = key + bracket
            core_key_name = parse_result['final_parts'][0]
            whole_key = core_key_name + parse_result['final_parts'][1]
            real_key = safeid(whole_key)
            if STRICT_MODE and (
                    pre_bracket_key not in authorized_fields or pre_bracket_key + '.gathered' not in authorized_fields) and (
                    key not in authorized_fields):
                raise DAError("The variables " + repr(pre_bracket_key) + " and " + repr(
                    key) + " were not in the allowed fields, which were " + repr(authorized_fields))
            if illegal_variable_name(whole_key) or illegal_variable_name(core_key_name) or illegal_variable_name(key):
                error_messages.append(("error", "Error: Invalid key " + whole_key))
                break
            if whole_key in user_dict:
                it_exists = True
            else:
                try:
                    the_object = eval(whole_key, user_dict)
                    it_exists = True
                except:
                    it_exists = False
            if not it_exists:
                method = None
                commands = []
                if parse_result['final_parts'][1] != '':
                    if parse_result['final_parts'][1][0] == '.':
                        try:
                            core_key = eval(core_key_name, user_dict)
                            if hasattr(core_key, 'instanceName'):
                                method = 'attribute'
                        except:
                            pass
                    elif parse_result['final_parts'][1][0] == '[':
                        try:
                            core_key = eval(core_key_name, user_dict)
                            if hasattr(core_key, 'instanceName'):
                                method = 'index'
                        except:
                            pass
                datatype = known_datatypes.get(real_key, None)
                if not imported_core:
                    commands.append("import docassemble.base.util")
                    imported_core = True
                if method == 'attribute':
                    attribute_name = parse_result['final_parts'][1][1:]
                    if datatype in ('multiselect', 'checkboxes'):
                        commands.append(core_key_name + ".initializeAttribute(" + repr(
                            attribute_name) + ", docassemble.base.util.DADict, auto_gather=False, gathered=True)")
                    elif datatype in ('object_multiselect', 'object_checkboxes'):
                        commands.append(core_key_name + ".initializeAttribute(" + repr(
                            attribute_name) + ", docassemble.base.util.DAList, auto_gather=False, gathered=True)")
                    process_set_variable(core_key_name + '.' + attribute_name, user_dict, vars_set, old_values)
                elif method == 'index':
                    index_name = parse_result['final_parts'][1][1:-1]
                    orig_index_name = index_name
                    if index_name in ('i', 'j', 'k', 'l', 'm', 'n'):
                        index_name = repr(user_dict.get(index_name, index_name))
                    if datatype in ('multiselect', 'checkboxes'):
                        commands.append(
                            core_key_name + ".initializeObject(" + index_name + ", docassemble.base.util.DADict, auto_gather=False, gathered=True)")
                    elif datatype in ('object_multiselect', 'object_checkboxes'):
                        commands.append(
                            core_key_name + ".initializeObject(" + index_name + ", docassemble.base.util.DAList, auto_gather=False, gathered=True)")
                    process_set_variable(core_key_name + '[' + orig_index_name + ']', user_dict, vars_set, old_values)
                else:
                    whole_key_tr = sub_indices(whole_key, user_dict)
                    if datatype in ('multiselect', 'checkboxes'):
                        commands.append(whole_key + ' = docassemble.base.util.DADict(' + repr(
                            whole_key_tr) + ', auto_gather=False, gathered=True)')
                    elif datatype in ('object_multiselect', 'object_checkboxes'):
                        commands.append(whole_key + ' = docassemble.base.util.DAList(' + repr(
                            whole_key_tr) + ', auto_gather=False, gathered=True)')
                    process_set_variable(whole_key, user_dict, vars_set, old_values)
                for command in commands:
                    exec(command, user_dict)
        else:
            real_key = orig_key
            parse_result = docassemble.base.parse.parse_var_name(key)
            if not parse_result['valid']:
                error_messages.append(("error", "Error: Invalid character in key: " + key))
                break
            if STRICT_MODE and key not in authorized_fields:
                raise DAError("The variable " + repr(key) + " was not in the allowed fields, which were " + repr(
                    authorized_fields))
        if illegal_variable_name(key):
            error_messages.append(("error", "Error: Invalid key " + key))
            break
        do_append = False
        do_opposite = False
        is_ml = False
        is_date = False
        is_object = False
        test_data = data
        if real_key in known_datatypes:
            if known_datatypes[real_key] in ('boolean', 'multiselect', 'checkboxes'):
                if data == "True":
                    data = "True"
                    test_data = True
                else:
                    data = "False"
                    test_data = False
            elif known_datatypes[real_key] == 'threestate':
                if data == "True":
                    data = "True"
                    test_data = True
                elif data == "None":
                    data = "None"
                    test_data = None
                else:
                    data = "False"
                    test_data = False
            elif known_datatypes[real_key] in ('date', 'datetime', 'datetime-local'):
                if isinstance(data, str):
                    data = data.strip()
                    if data != '':
                        try:
                            dateutil.parser.parse(data)
                        except:
                            validated = False
                            if known_datatypes[real_key] == 'date':
                                field_error[orig_key] = word("You need to enter a valid date.")
                            else:
                                field_error[orig_key] = word("You need to enter a valid date and time.")
                            new_values[key] = repr(data)
                            continue
                        test_data = data
                        is_date = True
                        data = 'docassemble.base.util.as_datetime(' + repr(data) + ')'
                    else:
                        data = repr('')
                else:
                    data = repr('')
            elif known_datatypes[real_key] == 'time':
                if isinstance(data, str):
                    data = data.strip()
                    if data != '':
                        try:
                            dateutil.parser.parse(data)
                        except:
                            validated = False
                            field_error[orig_key] = word("You need to enter a valid time.")
                            new_values[key] = repr(data)
                            continue
                        test_data = data
                        is_date = True
                        data = 'docassemble.base.util.as_datetime(' + repr(data) + ').time()'
                    else:
                        data = repr('')
                else:
                    data = repr('')
            elif known_datatypes[real_key] == 'integer':
                if data.strip() == '':
                    data = 0
                try:
                    test_data = int(data)
                except:
                    validated = False
                    field_error[orig_key] = word("You need to enter a valid number.")
                    new_values[key] = repr(data)
                    continue
                data = "int(" + repr(data) + ")"
            elif known_datatypes[real_key] in ('ml', 'mlarea'):
                is_ml = True
            elif known_datatypes[real_key] in ('number', 'float', 'currency', 'range'):
                if data == '':
                    data = 0.0
                if isinstance(data, str):
                    data = re.sub(r'[,\%]', '', data)
                try:
                    test_data = float(data)
                except:
                    validated = False
                    field_error[orig_key] = word("You need to enter a valid number.")
                    new_values[key] = repr(data)
                    continue
                data = "float(" + repr(data) + ")"
            elif known_datatypes[real_key] in ('object', 'object_radio'):
                if data == '' or set_to_empty:
                    continue
                data = "_internal['objselections'][" + repr(key) + "][" + repr(data) + "]"
            elif known_datatypes[real_key] in (
                    'object_multiselect', 'object_checkboxes') and bracket_expression is not None:
                if data not in ('True', 'False', 'None') or set_to_empty:
                    continue
                do_append = True
                if data == 'False':
                    do_opposite = True
                data = "_internal['objselections'][" + repr(from_safeid(real_key)) + "][" + repr(
                    bracket_expression) + "]"
            elif set_to_empty in ('object_multiselect', 'object_checkboxes'):
                continue
            elif known_datatypes[real_key] in ('file', 'files', 'camera', 'user', 'environment'):
                continue
            elif known_datatypes[real_key] in docassemble.base.functions.custom_types:
                info = docassemble.base.functions.custom_types[known_datatypes[real_key]]
                if info['is_object']:
                    is_object = True
                if set_to_empty:
                    if info['skip_if_empty']:
                        continue
                    else:
                        test_data = info['class'].empty()
                        if is_object:
                            user_dict['__DANEWOBJECT'] = data
                            data = '__DANEWOBJECT'
                        else:
                            data = repr(test_data)
                else:
                    try:
                        if not info['class'].validate(data):
                            raise DAValidationError(word("You need to enter a valid value."))
                    except DAValidationError as err:
                        validated = False
                        field_error[orig_key] = word(err)
                        new_values[key] = repr(data)
                        continue
                    test_data = info['class'].transform(data)
                    if is_object:
                        user_dict['__DANEWOBJECT'] = test_data
                        data = '__DANEWOBJECT'
                    else:
                        data = repr(test_data)
            elif known_datatypes[real_key] == 'raw':
                if data == "None" and set_to_empty is not None:
                    test_data = None
                    data = "None"
                else:
                    test_data = data
                    data = repr(data)
            else:
                if isinstance(data, str):
                    data = BeautifulSoup(data, "html.parser").get_text('\n')
                if data == "None" and set_to_empty is not None:
                    test_data = None
                    data = "None"
                else:
                    test_data = data
                    data = repr(data)
            if known_datatypes[real_key] in ('object_multiselect', 'object_checkboxes'):
                do_append = True
        elif orig_key in known_datatypes:
            if known_datatypes[orig_key] in ('boolean', 'multiselect', 'checkboxes'):
                if data == "True":
                    data = "True"
                    test_data = True
                else:
                    data = "False"
                    test_data = False
            elif known_datatypes[orig_key] == 'threestate':
                if data == "True":
                    data = "True"
                    test_data = True
                elif data == "None":
                    data = "None"
                    test_data = None
                else:
                    data = "False"
                    test_data = False
            elif known_datatypes[orig_key] in ('date', 'datetime'):
                if isinstance(data, str):
                    data = data.strip()
                    if data != '':
                        try:
                            dateutil.parser.parse(data)
                        except:
                            validated = False
                            if known_datatypes[orig_key] == 'date':
                                field_error[orig_key] = word("You need to enter a valid date.")
                            else:
                                field_error[orig_key] = word("You need to enter a valid date and time.")
                            new_values[key] = repr(data)
                            continue
                        test_data = data
                        is_date = True
                        data = 'docassemble.base.util.as_datetime(' + repr(data) + ')'
                    else:
                        data = repr('')
                else:
                    data = repr('')
            elif known_datatypes[orig_key] == 'time':
                if isinstance(data, str):
                    data = data.strip()
                    if data != '':
                        try:
                            dateutil.parser.parse(data)
                        except:
                            validated = False
                            field_error[orig_key] = word("You need to enter a valid time.")
                            new_values[key] = repr(data)
                            continue
                        test_data = data
                        is_date = True
                        data = 'docassemble.base.util.as_datetime(' + repr(data) + ').time()'
                    else:
                        data = repr('')
                else:
                    data = repr('')
            elif known_datatypes[orig_key] == 'integer':
                if data == '':
                    data = 0
                test_data = int(data)
                data = "int(" + repr(data) + ")"
            elif known_datatypes[orig_key] in ('ml', 'mlarea'):
                is_ml = True
            elif known_datatypes[orig_key] in ('number', 'float', 'currency', 'range'):
                if data == '':
                    data = 0.0
                if isinstance(data, str):
                    data = re.sub(r'[,\%]', '', data)
                test_data = float(data)
                data = "float(" + repr(data) + ")"
            elif known_datatypes[orig_key] in ('object', 'object_radio'):
                if data == '' or set_to_empty:
                    continue
                data = "_internal['objselections'][" + repr(key) + "][" + repr(data) + "]"
            elif set_to_empty in ('object_multiselect', 'object_checkboxes'):
                continue
            elif real_key in known_datatypes and known_datatypes[real_key] in (
                    'file', 'files', 'camera', 'user', 'environment'):
                continue
            elif known_datatypes[orig_key] in docassemble.base.functions.custom_types:
                info = docassemble.base.functions.custom_types[known_datatypes[orig_key]]
                if set_to_empty:
                    if info['skip_if_empty']:
                        continue
                    else:
                        test_data = info['class'].empty()
                        data = repr(test_data)
                else:
                    try:
                        if not info['class'].validate(data):
                            raise DAValidationError(word("You need to enter a valid value."))
                    except DAValidationError as err:
                        validated = False
                        field_error[orig_key] = word(str(err))
                        new_values[key] = repr(data)
                        continue
                    test_data = info['class'].transform(data)
                    data = repr(test_data)
            else:
                if isinstance(data, str):
                    data = data.strip()
                test_data = data
                data = repr(data)
        elif key == "_multiple_choice":
            data = "int(" + repr(data) + ")"
        else:
            data = repr(data)
        if key == "_multiple_choice":
            if '_question_name' in post_data:
                question_name = post_data['_question_name']
                if question_name == 'Question_Temp':
                    key = '_internal["answers"][' + repr(
                        interview_status.question.extended_question_name(user_dict)) + ']'
                else:
                    key = '_internal["answers"][' + repr(
                        interview.questions_by_name[question_name].extended_question_name(user_dict)) + ']'
                    if is_integer.match(str(post_data[orig_key])):
                        the_choice = int(str(post_data[orig_key]))
                        if len(interview.questions_by_name[question_name].fields[0].choices) > the_choice and 'key' in \
                                interview.questions_by_name[question_name].fields[0].choices[the_choice] and hasattr(
                            interview.questions_by_name[question_name].fields[0].choices[the_choice]['key'],
                            'question_type') and \
                                interview.questions_by_name[question_name].fields[0].choices[the_choice][
                                    'key'].question_type in ('restart', 'exit', 'logout', 'exit_logout', 'leave'):
                            special_question = interview.questions_by_name[question_name].fields[0].choices[the_choice][
                                'key']
        if is_date:
            try:
                exec("import docassemble.base.util", user_dict)
            except Exception as errMess:
                error_messages.append(("error", "Error: " + str(errMess)))
        key_tr = sub_indices(key, user_dict)
        if is_ml:
            try:
                exec("import docassemble.base.util", user_dict)
            except Exception as errMess:
                error_messages.append(("error", "Error: " + str(errMess)))
            if orig_key in ml_info and 'train' in ml_info[orig_key]:
                if not ml_info[orig_key]['train']:
                    use_for_training = 'False'
                else:
                    use_for_training = 'True'
            else:
                use_for_training = 'True'
            if orig_key in ml_info and 'group_id' in ml_info[orig_key]:
                data = 'docassemble.base.util.DAModel(' + repr(key_tr) + ', group_id=' + repr(
                    ml_info[orig_key]['group_id']) + ', text=' + repr(data) + ', store=' + repr(
                    interview.get_ml_store()) + ', use_for_training=' + use_for_training + ')'
            else:
                data = 'docassemble.base.util.DAModel(' + repr(key_tr) + ', text=' + repr(data) + ', store=' + repr(
                    interview.get_ml_store()) + ', use_for_training=' + use_for_training + ')'
        if set_to_empty:
            if set_to_empty in ('multiselect', 'checkboxes'):
                try:
                    exec("import docassemble.base.util", user_dict)
                except Exception as errMess:
                    error_messages.append(("error", "Error: " + str(errMess)))
                data = 'docassemble.base.util.DADict(' + repr(key_tr) + ', auto_gather=False, gathered=True)'
            else:
                data = 'None'
        if do_append and not set_to_empty:
            key_to_use = from_safeid(real_key)
            if illegal_variable_name(data):
                logmessage("Received illegal variable name " + str(data))
                continue
            if illegal_variable_name(key_to_use):
                logmessage("Received illegal variable name " + str(key_to_use))
                continue
            if do_opposite:
                the_string = 'if ' + data + ' in ' + key_to_use + '.elements:\n    ' + key_to_use + '.remove(' + data + ')'
            else:
                the_string = 'if ' + data + ' not in ' + key_to_use + '.elements:\n    ' + key_to_use + '.append(' + data + ')'
                if key_to_use not in new_values:
                    new_values[key_to_use] = []
                new_values[key_to_use].append(data)
        else:
            process_set_variable(key, user_dict, vars_set, old_values)
            the_string = key + ' = ' + data
            new_values[key] = data
            if orig_key in field_numbers and the_question is not None and len(the_question.fields) > field_numbers[
                orig_key] and hasattr(the_question.fields[field_numbers[orig_key]], 'validate'):
                field_name = safeid('_field_' + str(field_numbers[orig_key]))
                if field_name in post_data:
                    the_key = field_name
                else:
                    the_key = orig_key
                the_func = eval(the_question.fields[field_numbers[orig_key]].validate['compute'], user_dict)
                try:
                    the_result = the_func(test_data)
                    if not the_result:
                        field_error[the_key] = word("Please enter a valid value.")
                        validated = False
                        continue
                except Exception as errstr:
                    field_error[the_key] = str(errstr)
                    validated = False
                    continue
        try:
            exec(the_string, user_dict)
            changed = True
        except Exception as errMess:
            error_messages.append(("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
            try:
                logmessage(
                    "Tried to run " + the_string + " and got error " + errMess.__class__.__name__ + ": " + str(errMess))
            except:
                pass
        if is_object:
            if '__DANEWOBJECT' in user_dict:
                del user_dict['__DANEWOBJECT']
        if key not in key_to_orig_key:
            key_to_orig_key[key] = orig_key
    if validated and special_question is None and not disregard_input:
        for orig_key in empty_fields:
            key = myb64unquote(orig_key)
            if STRICT_MODE and key not in authorized_fields:
                raise DAError("The variable " + repr(key) + " was not in the allowed fields, which were " + repr(
                    authorized_fields))
            process_set_variable(key + '.gathered', user_dict, vars_set, old_values)
            if illegal_variable_name(key):
                logmessage("Received illegal variable name " + str(key))
                continue
            if empty_fields[orig_key] in ('object_multiselect', 'object_checkboxes'):
                docassemble.base.parse.ensure_object_exists(key, empty_fields[orig_key], user_dict)
                exec(key + '.clear()', user_dict)
                exec(key + '.gathered = True', user_dict)
            elif empty_fields[orig_key] in ('object', 'object_radio'):
                process_set_variable(key, user_dict, vars_set, old_values)
                try:
                    eval(key, user_dict)
                except:
                    exec(key + ' = None', user_dict)
                    new_values[key] = 'None'
    if validated and special_question is None:
        if '_order_changes' in post_data:
            orderChanges = json.loads(post_data['_order_changes'])
            for tableName, changes in orderChanges.items():
                tableName = myb64unquote(tableName)
                # if STRICT_MODE and tableName not in authorized_fields:
                #    raise DAError("The variable " + repr(tableName) + " was not in the allowed fields, which were " + repr(authorized_fields))
                if illegal_variable_name(tableName):
                    error_messages.append(("error", "Error: Invalid character in table reorder: " + str(tableName)))
                    continue
                for item in changes:
                    if not (isinstance(item, list) and len(item) == 2 and isinstance(item[0], int) and isinstance(
                            item[1], int)):
                        error_messages.append(("error", "Error: Invalid row number in table reorder: " + str(
                            tableName) + " " + str(item)))
                        break
                exec(tableName + '._reorder(' + ', '.join([repr(item) for item in changes]) + ')', user_dict)
        inline_files_processed = []
        if '_files_inline' in post_data:
            fileDict = json.loads(myb64unquote(post_data['_files_inline']))
            if not isinstance(fileDict, dict):
                raise DAError("inline files was not a dict")
            file_fields = fileDict['keys']
            has_invalid_fields = False
            should_assemble_now = False
            empty_file_vars = set()
            for orig_file_field in file_fields:
                if orig_file_field in known_varnames:
                    orig_file_field = known_varnames[orig_file_field]
                if orig_file_field not in visible_fields:
                    empty_file_vars.add(orig_file_field)
                try:
                    file_field = from_safeid(orig_file_field)
                except:
                    error_messages.append(("error", "Error: Invalid file_field: " + orig_file_field))
                    break
                if STRICT_MODE and file_field not in authorized_fields:
                    raise DAError(
                        "The variable " + repr(file_field) + " was not in the allowed fields, which were " + repr(
                            authorized_fields))
                if illegal_variable_name(file_field):
                    has_invalid_fields = True
                    error_messages.append(("error", "Error: Invalid character in file_field: " + str(file_field)))
                    break
                if key_requires_preassembly.search(file_field):
                    should_assemble_now = True
            if not has_invalid_fields:
                initial_string = 'import docassemble.base.util'
                try:
                    exec(initial_string, user_dict)
                except Exception as errMess:
                    error_messages.append(("error", "Error: " + str(errMess)))
                if should_assemble_now and not already_assembled:
                    interview.assemble(user_dict, interview_status)
                    already_assembled = True
                for orig_file_field_raw in file_fields:
                    if orig_file_field_raw in known_varnames:
                        orig_file_field_raw = known_varnames[orig_file_field_raw]
                    set_empty = bool(orig_file_field_raw not in visible_fields)
                    if not validated:
                        break
                    orig_file_field = orig_file_field_raw
                    var_to_store = orig_file_field_raw
                    if orig_file_field not in fileDict['values'] and len(known_varnames):
                        for key, val in known_varnames_visible.items():
                            if val == orig_file_field_raw:
                                orig_file_field = key
                                var_to_store = val
                                break
                    if orig_file_field in fileDict['values']:
                        the_files = fileDict['values'][orig_file_field]
                        if the_files:
                            files_to_process = []
                            for the_file in the_files:
                                temp_file = tempfile.NamedTemporaryFile(prefix="datemp", delete=False)
                                start_index = 0
                                char_index = 0
                                for char in the_file['content']:
                                    char_index += 1
                                    if char == ',':
                                        start_index = char_index
                                        break
                                temp_file.write(
                                    codecs.decode(bytearray(the_file['content'][start_index:], encoding='utf-8'),
                                                  'base64'))
                                temp_file.close()
                                filename = secure_filename(the_file['name'])
                                extension, mimetype = get_ext_and_mimetype(filename)
                                try:
                                    img = Image.open(temp_file.name)
                                    the_format = img.format.lower()
                                    the_format = re.sub(r'jpeg', 'jpg', the_format)
                                except:
                                    the_format = extension
                                    logmessage("Could not read file type from file " + str(filename))
                                if the_format != extension:
                                    filename = re.sub(r'\.[^\.]+$', '', filename) + '.' + the_format
                                    extension, mimetype = get_ext_and_mimetype(filename)
                                file_number = get_new_file_number(user_code, filename, yaml_file_name=yaml_filename)
                                saved_file = SavedFile(file_number, extension=extension, fix=True,
                                                       should_not_exist=True)
                                process_file(saved_file, temp_file.name, mimetype, extension)
                                files_to_process.append((filename, file_number, mimetype, extension))
                            try:
                                file_field = from_safeid(var_to_store)
                            except:
                                error_messages.append(("error", "Error: Invalid file_field: " + str(var_to_store)))
                                break
                            if STRICT_MODE and file_field not in authorized_fields:
                                raise DAError("The variable " + repr(
                                    file_field) + " was not in the allowed fields, which were " + repr(
                                    authorized_fields))
                            if illegal_variable_name(file_field):
                                error_messages.append(
                                    ("error", "Error: Invalid character in file_field: " + str(file_field)))
                                break
                            file_field_tr = sub_indices(file_field, user_dict)
                            if len(files_to_process) > 0:
                                elements = []
                                indexno = 0
                                for (filename, file_number, mimetype, extension) in files_to_process:
                                    elements.append("docassemble.base.util.DAFile(" + repr(
                                        file_field_tr + "[" + str(indexno) + "]") + ", filename=" + repr(
                                        filename) + ", number=" + str(
                                        file_number) + ", make_pngs=True, mimetype=" + repr(
                                        mimetype) + ", extension=" + repr(extension) + ")")
                                    indexno += 1
                                the_file_list = "docassemble.base.util.DAFileList(" + repr(
                                    file_field_tr) + ", elements=[" + ", ".join(elements) + "])"
                                if orig_file_field in field_numbers and the_question is not None and len(
                                        the_question.fields) > field_numbers[orig_file_field]:
                                    the_field = the_question.fields[field_numbers[orig_file_field]]
                                    add_permissions_for_field(the_field, interview_status, files_to_process)
                                    if hasattr(the_field, 'validate'):
                                        the_key = orig_file_field
                                        the_func = eval(the_field.validate['compute'], user_dict)
                                        try:
                                            the_result = the_func(eval(the_file_list))
                                            if not the_result:
                                                field_error[the_key] = word("Please enter a valid value.")
                                                validated = False
                                                break
                                        except Exception as errstr:
                                            field_error[the_key] = str(errstr)
                                            validated = False
                                            break
                                the_string = file_field + " = " + the_file_list
                                inline_files_processed.append(file_field)
                            else:
                                the_string = file_field + " = None"
                            key_to_orig_key[file_field] = orig_file_field
                            process_set_variable(file_field, user_dict, vars_set, old_values)
                            try:
                                exec(the_string, user_dict)
                                changed = True
                            except Exception as errMess:
                                try:
                                    current_app.logger.error("Error: " + errMess.__class__.__name__ + ": " + str(
                                        errMess) + " after trying to run " + the_string + "\n")
                                except:
                                    pass
                                error_messages.append(
                                    ("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
                    else:
                        try:
                            file_field = from_safeid(var_to_store)
                        except:
                            error_messages.append(("error", "Error: Invalid file_field: " + str(var_to_store)))
                            break
                        if STRICT_MODE and file_field not in authorized_fields:
                            raise DAError("The variable " + repr(
                                file_field) + " was not in the allowed fields, which were " + repr(authorized_fields))
                        if illegal_variable_name(file_field):
                            error_messages.append(
                                ("error", "Error: Invalid character in file_field: " + str(file_field)))
                            break
                        the_string = file_field + " = None"
                        key_to_orig_key[file_field] = orig_file_field
                        process_set_variable(file_field, user_dict, vars_set, old_values)
                        try:
                            exec(the_string, user_dict)
                            changed = True
                        except Exception as errMess:
                            current_app.logger.error("Error: " + errMess.__class__.__name__ + ": " + str(
                                errMess) + " after running " + the_string + "\n")
                            error_messages.append(
                                ("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
        if '_files' in post_data or (STRICT_MODE and (not disregard_input) and len(field_info['files']) > 0):
            if STRICT_MODE:
                file_fields = field_info['files']
            else:
                file_fields = json.loads(myb64unquote(post_data['_files']))
            has_invalid_fields = False
            should_assemble_now = False
            empty_file_vars = set()
            for orig_file_field in file_fields:
                if orig_file_field not in raw_visible_fields:
                    continue
                if orig_file_field in known_varnames:
                    orig_file_field = known_varnames[orig_file_field]
                if orig_file_field not in visible_fields:
                    empty_file_vars.add(orig_file_field)
                try:
                    file_field = from_safeid(orig_file_field)
                except:
                    error_messages.append(("error", "Error: Invalid file_field: " + str(orig_file_field)))
                    break
                if STRICT_MODE and file_field not in authorized_fields:
                    raise DAError(
                        "The variable " + repr(file_field) + " was not in the allowed fields, which were " + repr(
                            authorized_fields))
                if illegal_variable_name(file_field):
                    has_invalid_fields = True
                    error_messages.append(("error", "Error: Invalid character in file_field: " + str(file_field)))
                    break
                if key_requires_preassembly.search(file_field):
                    should_assemble_now = True
                key_to_orig_key[file_field] = orig_file_field
            if not has_invalid_fields:
                initial_string = 'import docassemble.base.util'
                try:
                    exec(initial_string, user_dict)
                except Exception as errMess:
                    error_messages.append(("error", "Error: " + str(errMess)))
                if not already_assembled:
                    interview.assemble(user_dict, interview_status)
                    already_assembled = True
                for orig_file_field_raw in file_fields:
                    if orig_file_field_raw not in raw_visible_fields:
                        continue
                    if orig_file_field_raw in known_varnames:
                        orig_file_field_raw = known_varnames[orig_file_field_raw]
                    if orig_file_field_raw not in visible_fields:
                        continue
                    if not validated:
                        break
                    orig_file_field = orig_file_field_raw
                    var_to_store = orig_file_field_raw
                    if (orig_file_field not in request.files or request.files[orig_file_field].filename == "") and len(
                            known_varnames):
                        for key, val in known_varnames_visible.items():
                            if val == orig_file_field_raw:
                                orig_file_field = key
                                var_to_store = val
                                break
                    if orig_file_field in request.files and request.files[orig_file_field].filename != "":
                        the_files = request.files.getlist(orig_file_field)
                        if the_files:
                            files_to_process = []
                            for the_file in the_files:
                                if is_ajax:
                                    return_fake_html = True
                                filename = secure_filename(the_file.filename)
                                file_number = get_new_file_number(user_code, filename, yaml_file_name=yaml_filename)
                                extension, mimetype = get_ext_and_mimetype(filename)
                                saved_file = SavedFile(file_number, extension=extension, fix=True,
                                                       should_not_exist=True)
                                temp_file = tempfile.NamedTemporaryFile(prefix="datemp", suffix='.' + extension,
                                                                        delete=False)
                                the_file.save(temp_file.name)
                                process_file(saved_file, temp_file.name, mimetype, extension)
                                files_to_process.append((filename, file_number, mimetype, extension))
                            try:
                                file_field = from_safeid(var_to_store)
                            except:
                                error_messages.append(("error", "Error: Invalid file_field: " + str(var_to_store)))
                                break
                            if STRICT_MODE and file_field not in authorized_fields:
                                raise DAError("The variable " + repr(
                                    file_field) + " was not in the allowed fields, which were " + repr(
                                    authorized_fields))
                            if illegal_variable_name(file_field):
                                error_messages.append(
                                    ("error", "Error: Invalid character in file_field: " + str(file_field)))
                                break
                            file_field_tr = sub_indices(file_field, user_dict)
                            if len(files_to_process) > 0:
                                elements = []
                                indexno = 0
                                for (filename, file_number, mimetype, extension) in files_to_process:
                                    elements.append("docassemble.base.util.DAFile(" + repr(
                                        file_field_tr + '[' + str(indexno) + ']') + ", filename=" + repr(
                                        filename) + ", number=" + str(
                                        file_number) + ", make_pngs=True, mimetype=" + repr(
                                        mimetype) + ", extension=" + repr(extension) + ")")
                                    indexno += 1
                                the_file_list = "docassemble.base.util.DAFileList(" + repr(
                                    file_field_tr) + ", elements=[" + ", ".join(elements) + "])"
                                if orig_file_field in field_numbers and the_question is not None and len(
                                        the_question.fields) > field_numbers[orig_file_field]:
                                    the_field = the_question.fields[field_numbers[orig_file_field]]
                                    add_permissions_for_field(the_field, interview_status, files_to_process)
                                    if hasattr(the_question.fields[field_numbers[orig_file_field]], 'validate'):
                                        the_key = orig_file_field
                                        the_func = eval(
                                            the_question.fields[field_numbers[orig_file_field]].validate['compute'],
                                            user_dict)
                                        try:
                                            the_result = the_func(eval(the_file_list))
                                            if not the_result:
                                                field_error[the_key] = word("Please enter a valid value.")
                                                validated = False
                                                break
                                        except Exception as errstr:
                                            field_error[the_key] = str(errstr)
                                            validated = False
                                            break
                                the_string = file_field + " = " + the_file_list
                            else:
                                the_string = file_field + " = None"
                            process_set_variable(file_field, user_dict, vars_set, old_values)
                            if validated:
                                try:
                                    exec(the_string, user_dict)
                                    changed = True
                                except Exception as errMess:
                                    current_app.logger.error("Error: " + errMess.__class__.__name__ + ": " + str(
                                        errMess) + "after running " + the_string + "\n")
                                    error_messages.append(
                                        ("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
                    else:
                        try:
                            file_field = from_safeid(var_to_store)
                        except:
                            error_messages.append(("error", "Error: Invalid file_field: " + str(var_to_store)))
                            break
                        if file_field in inline_files_processed:
                            continue
                        if STRICT_MODE and file_field not in authorized_fields:
                            raise DAError("The variable " + repr(
                                file_field) + " was not in the allowed fields, which were " + repr(authorized_fields))
                        if illegal_variable_name(file_field):
                            error_messages.append(
                                ("error", "Error: Invalid character in file_field: " + str(file_field)))
                            break
                        the_string = file_field + " = None"
                        process_set_variable(file_field, user_dict, vars_set, old_values)
                        try:
                            exec(the_string, user_dict)
                            changed = True
                        except Exception as errMess:
                            current_app.logger.error("Error: " + errMess.__class__.__name__ + ": " + str(
                                errMess) + "after running " + the_string + "\n")
                            error_messages.append(
                                ("error", "Error: " + errMess.__class__.__name__ + ": " + str(errMess)))
        if validated:
            if 'informed' in request.form:
                user_dict['_internal']['informed'][the_user_id] = {}
                for key in request.form['informed'].split(','):
                    user_dict['_internal']['informed'][the_user_id][key] = 1
            if changed and '_question_name' in post_data and post_data['_question_name'] not in user_dict['_internal'][
                'answers']:
                try:
                    interview.questions_by_name[post_data['_question_name']].mark_as_answered(user_dict)
                except:
                    logmessage("index: question name could not be found")
            if ('_event' in post_data or (STRICT_MODE and (not disregard_input) and field_info[
                'orig_sought'] is not None)) and 'event_stack' in user_dict['_internal']:
                if STRICT_MODE:
                    events_list = [field_info['orig_sought']]
                else:
                    events_list = json.loads(myb64unquote(post_data['_event']))
                if len(events_list) > 0:
                    session_uid = interview_status.current_info['user']['session_uid']
                    if session_uid in user_dict['_internal']['event_stack'] and len(
                            user_dict['_internal']['event_stack'][session_uid]):
                        for event_name in events_list:
                            if user_dict['_internal']['event_stack'][session_uid][0]['action'] == event_name:
                                user_dict['_internal']['event_stack'][session_uid].pop(0)
                                if 'action' in interview_status.current_info and interview_status.current_info[
                                    'action'] == event_name:
                                    del interview_status.current_info['action']
                                    if 'arguments' in interview_status.current_info:
                                        del interview_status.current_info['arguments']
                                break
                            if len(user_dict['_internal']['event_stack'][session_uid]) == 0:
                                break
            for var_name in list(vars_set):
                vars_set.add(sub_indices(var_name, user_dict))
            if len(vars_set) > 0 and 'event_stack' in user_dict['_internal']:
                session_uid = interview_status.current_info['user']['session_uid']
                popped = True
                while popped:
                    popped = False
                    if session_uid in user_dict['_internal']['event_stack'] and len(
                            user_dict['_internal']['event_stack'][session_uid]):
                        for var_name in vars_set:
                            if user_dict['_internal']['event_stack'][session_uid][0]['action'] == var_name:
                                popped = True
                                user_dict['_internal']['event_stack'][session_uid].pop(0)
                            if len(user_dict['_internal']['event_stack'][session_uid]) == 0:
                                break
        else:
            steps, user_dict, is_encrypted = fetch_user_dict(user_code, yaml_filename, secret=secret)
    else:
        steps, user_dict, is_encrypted = fetch_user_dict(user_code, yaml_filename, secret=secret)
    if validated and special_question is None:
        if '_collect_delete' in post_data and list_collect_list is not None:
            to_delete = json.loads(post_data['_collect_delete'])
            is_ok = True
            for item in to_delete:
                if not isinstance(item, int):
                    is_ok = False
            if is_ok:
                if not illegal_variable_name(list_collect_list):
                    exec(list_collect_list + ' ._remove_items_by_number(' + ', '.join(
                        map(lambda y: str(y), to_delete)) + ')', user_dict)
                    changed = True
        if '_collect' in post_data and list_collect_list is not None:
            collect = json.loads(myb64unquote(post_data['_collect']))
            if collect['function'] == 'add':
                add_action_to_stack(interview_status, user_dict, '_da_list_add', {'list': list_collect_list})
        if list_collect_list is not None:
            exec(list_collect_list + '._disallow_appending()', user_dict)
        if the_question is not None and the_question.validation_code:
            try:
                exec(the_question.validation_code, user_dict)
            except Exception as validation_error:
                the_error_message = str(validation_error)
                logmessage("index: exception during validation: " + the_error_message)
                if the_error_message == '':
                    the_error_message = word("Please enter a valid value.")
                if isinstance(validation_error, DAValidationError) and isinstance(validation_error.field,
                                                                                  str) and validation_error.field in key_to_orig_key:
                    field_error[key_to_orig_key[validation_error.field]] = the_error_message
                else:
                    error_messages.append(("error", the_error_message))
                validated = False
                steps, user_dict, is_encrypted = fetch_user_dict(user_code, yaml_filename, secret=secret)
    if validated:
        for var_name in vars_set:
            if var_name in interview.invalidation_todo:
                interview.invalidate_dependencies(var_name, user_dict, old_values)
            elif var_name in interview.onchange_todo:
                if not already_assembled:
                    interview.assemble(user_dict, interview_status)
                    already_assembled = True
                interview.invalidate_dependencies(var_name, user_dict, old_values)
            try:
                del user_dict['_internal']['dirty'][var_name]
            except:
                pass
    if action is not None:
        interview_status.current_info.update(action)
    interview.assemble(user_dict, interview_status, old_user_dict, force_question=special_question)
    current_language = docassemble.base.functions.get_language()
    session['language'] = current_language
    if not interview_status.can_go_back:
        user_dict['_internal']['steps_offset'] = steps
    if was_new:
        docassemble.base.functions.this_thread.misc['save_status'] = 'overwrite'
    if not changed and url_args_changed:
        changed = True
        validated = True
    if interview_status.question.question_type == "restart":
        manual_checkout(manual_filename=yaml_filename)
        url_args = user_dict['url_args']
        referer = user_dict['_internal'].get('referer', None)
        user_dict = fresh_dictionary()
        user_dict['url_args'] = url_args
        user_dict['_internal']['referer'] = referer
        the_current_info = current_info(yaml=yaml_filename, req=request, interface=the_interface,
                                        session_info=session_info, secret=secret, device_id=device_id)
        docassemble.base.functions.this_thread.current_info = the_current_info
        interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
        reset_user_dict(user_code, yaml_filename)
        if 'visitor_secret' not in request.cookies:
            save_user_dict_key(user_code, yaml_filename)
            update_session(yaml_filename, uid=user_code, key_logged=True)
        steps = 1
        changed = False
        interview.assemble(user_dict, interview_status)
    elif interview_status.question.question_type == "new_session":
        manual_checkout(manual_filename=yaml_filename)
        url_args = user_dict['url_args']
        referer = user_dict['_internal'].get('referer', None)
        the_current_info = current_info(yaml=yaml_filename, req=request, interface=the_interface,
                                        session_info=session_info, secret=secret, device_id=device_id)
        docassemble.base.functions.this_thread.current_info = the_current_info
        interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
        release_lock(user_code, yaml_filename)
        user_code, user_dict = reset_session(yaml_filename, secret)
        user_dict['url_args'] = url_args
        user_dict['_internal']['referer'] = referer
        if 'visitor_secret' not in request.cookies:
            save_user_dict_key(user_code, yaml_filename)
            update_session(yaml_filename, uid=user_code, key_logged=True)
        steps = 1
        changed = False
        interview.assemble(user_dict, interview_status)
    title_info = interview.get_title(user_dict, status=interview_status,
                                     converter=lambda content, part: title_converter(content, part, interview_status))
    save_status = docassemble.base.functions.this_thread.misc.get('save_status', 'new')
    if interview_status.question.question_type == "interview_exit":
        exit_link = title_info.get('exit link', 'exit')
        if exit_link in ('exit', 'leave', 'logout'):
            interview_status.question.question_type = exit_link
    if interview_status.question.question_type == "exit":
        manual_checkout(manual_filename=yaml_filename)
        reset_user_dict(user_code, yaml_filename)
        delete_session_for_interview(i=yaml_filename)
        release_lock(user_code, yaml_filename)
        current_app.logger.error("Redirecting because of an exit.\n")
        if interview_status.questionText != '':
            response = do_redirect(interview_status.questionText, is_ajax, is_json, js_target)
        else:
            response = do_redirect(title_info.get('exit url', None) or exit_page, is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type in ("exit_logout", "logout"):
        manual_checkout(manual_filename=yaml_filename)
        if interview_status.question.question_type == "exit_logout":
            reset_user_dict(user_code, yaml_filename)
        release_lock(user_code, yaml_filename)
        delete_session_info()
        current_app.logger.error("Redirecting because of a logout.\n")
        if interview_status.questionText != '':
            response = do_redirect(interview_status.questionText, is_ajax, is_json, js_target)
        else:
            response = do_redirect(title_info.get('exit url', None) or exit_page, is_ajax, is_json, js_target)
        if current_user.is_authenticated:
            docassemble_flask_user.signals.user_logged_out.send(current_app._get_current_object(), user=current_user)
            logout_user()
        delete_session_info()
        session.clear()
        response.set_cookie('remember_token', '', expires=0)
        response.set_cookie('visitor_secret', '', expires=0)
        response.set_cookie('secret', '', expires=0)
        response.set_cookie('session', '', expires=0)
        if return_fake_html:
            fake_up(response, current_language)
        return response
    will_save = True
    if interview_status.question.question_type == "refresh":
        release_lock(user_code, yaml_filename)
        response = do_refresh(is_ajax, yaml_filename)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type == "signin":
        release_lock(user_code, yaml_filename)
        current_app.logger.error("Redirecting because of a signin.\n")
        response = do_redirect(url_for('user.login', next=url_for('index.index', i=yaml_filename, session=user_code)),
                               is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type == "register":
        release_lock(user_code, yaml_filename)
        current_app.logger.error("Redirecting because of a register.\n")
        response = do_redirect(
            url_for('user.register', next=url_for('index.index', i=yaml_filename, session=user_code)),
            is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type == "leave":
        release_lock(user_code, yaml_filename)
        current_app.logger.error("Redirecting because of a leave.\n")
        if interview_status.questionText != '':
            response = do_redirect(interview_status.questionText, is_ajax, is_json, js_target)
        else:
            response = do_redirect(title_info.get('exit url', None) or exit_page, is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview.use_progress_bar and interview_status.question.progress is not None:
        if interview_status.question.progress == -1:
            user_dict['_internal']['progress'] = None
        elif user_dict['_internal']['progress'] is None or interview_status.question.interview.options.get(
                'strict progress', False) or interview_status.question.progress > user_dict['_internal']['progress']:
            user_dict['_internal']['progress'] = interview_status.question.progress
    if interview.use_navigation and interview_status.question.section is not None:
        user_dict['nav'].set_section(interview_status.question.section)
    if interview_status.question.question_type == "response":
        if is_ajax:
            release_lock(user_code, yaml_filename)
            response = jsonify(action='resubmit', csrf_token=generate_csrf())
            if return_fake_html:
                fake_up(response, current_language)
            if response_wrapper:
                response_wrapper(response)
            return response
        if hasattr(interview_status.question, 'response_code'):
            resp_code = interview_status.question.response_code
        else:
            resp_code = 200
        if hasattr(interview_status.question, 'all_variables'):
            if hasattr(interview_status.question, 'include_internal'):
                include_internal = interview_status.question.include_internal
            else:
                include_internal = False
            response_to_send = make_response(
                docassemble.base.functions.dict_as_json(user_dict, include_internal=include_internal).encode('utf-8'),
                resp_code)
        elif hasattr(interview_status.question, 'binaryresponse'):
            response_to_send = make_response(interview_status.question.binaryresponse, resp_code)
        else:
            response_to_send = make_response(interview_status.questionText.encode('utf-8'), resp_code)
        response_to_send.headers['Content-Type'] = interview_status.extras['content_type']
    elif interview_status.question.question_type == "sendfile":
        if is_ajax:
            release_lock(user_code, yaml_filename)
            response = jsonify(action='resubmit', csrf_token=generate_csrf())
            if return_fake_html:
                fake_up(response, current_language)
            if response_wrapper:
                response_wrapper(response)
            return response
        if interview_status.question.response_file is not None:
            the_path = interview_status.question.response_file.path()
        else:
            logmessage("index: could not send file because the response was None")
            return ('File not found', 404)
        if not os.path.isfile(the_path):
            logmessage("index: could not send file because file (" + the_path + ") not found")
            return ('File not found', 404)
        response_to_send = send_file(the_path, mimetype=interview_status.extras['content_type'])
        response_to_send.headers[
            'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    elif interview_status.question.question_type == "redirect":
        current_app.logger.error("Redirecting because of a redirect.\n")
        response_to_send = do_redirect(interview_status.questionText, is_ajax, is_json, js_target)
    else:
        response_to_send = None
    if (not interview_status.followed_mc) and len(user_dict['_internal']['answers']):
        user_dict['_internal']['answers'].clear()
    if not validated:
        changed = False
    if changed and validated:
        if save_status == 'new':
            steps += 1
            user_dict['_internal']['steps'] = steps
    if action and not changed:
        changed = True
        if save_status == 'new':
            steps += 1
            user_dict['_internal']['steps'] = steps
    if changed and interview.use_progress_bar and interview_status.question.progress is None and save_status == 'new':
        advance_progress(user_dict, interview)
    title_info = interview.get_title(user_dict, status=interview_status,
                                     converter=lambda content, part: title_converter(content, part, interview_status))
    if save_status != 'ignore':
        if save_status == 'overwrite':
            changed = False
        save_user_dict(user_code, user_dict, yaml_filename, secret=secret, changed=changed, encrypt=encrypted,
                       steps=steps)
        if user_dict.get('multi_user', False) is True and encrypted is True:
            encrypted = False
            update_session(yaml_filename, encrypted=encrypted)
            decrypt_session(secret, user_code=user_code, filename=yaml_filename)
        if user_dict.get('multi_user', False) is False and encrypted is False:
            encrypt_session(secret, user_code=user_code, filename=yaml_filename)
            encrypted = True
            update_session(yaml_filename, encrypted=encrypted)
    if response_to_send is not None:
        release_lock(user_code, yaml_filename)
        if return_fake_html:
            fake_up(response_to_send, current_language)
        if response_wrapper:
            response_wrapper(response_to_send)
        return response_to_send
    messages = get_flashed_messages(with_categories=True) + error_messages
    if messages and len(messages):
        notification_interior = ''
        for classname, message in messages:
            if classname == 'error':
                classname = 'danger'
            notification_interior += NOTIFICATION_MESSAGE % (classname, str(message))
        flash_content = NOTIFICATION_CONTAINER % (notification_interior,)
    else:
        flash_content = ''
    if 'reload_after' in interview_status.extras:
        reload_after = 1000 * int(interview_status.extras['reload_after'])
    else:
        reload_after = 0
    allow_going_back = bool(
        interview_status.question.can_go_back and (steps - user_dict['_internal']['steps_offset']) > 1)
    if hasattr(interview_status.question, 'id'):
        question_id = interview_status.question.id
    else:
        question_id = None
    question_id_dict = dict(id=question_id)
    if interview.options.get('analytics on', True):
        if 'segment' in interview_status.extras:
            question_id_dict['segment'] = interview_status.extras['segment']
        if 'ga_id' in interview_status.extras:
            question_id_dict['ga'] = interview_status.extras['ga_id']
    append_script_urls = []
    append_javascript = ''
    if not is_ajax:
        scripts = standard_scripts(interview_language=current_language) + additional_scripts(interview_status,
                                                                                             yaml_filename)
        if is_js:
            append_javascript += additional_scripts(interview_status, yaml_filename, as_javascript=True)
        if 'javascript' in interview.external_files:
            for packageref, fileref in interview.external_files['javascript']:
                the_url = get_url_from_file_reference(fileref, _package=packageref)
                if the_url is not None:
                    scripts += "\n" + '    <script src="' + get_url_from_file_reference(fileref,
                                                                                        _package=packageref) + '"></script>'
                    if is_js:
                        append_script_urls.append(get_url_from_file_reference(fileref, _package=packageref))
                else:
                    logmessage("index: could not find javascript file " + str(fileref))
        if interview_status.question.checkin is not None:
            do_action = json.dumps(interview_status.question.checkin)
        else:
            do_action = 'null'
        chat_available = user_dict['_internal']['livehelp']['availability'] or 'unavailable'
        chat_mode = user_dict['_internal']['livehelp']['mode']
        if chat_available == 'unavailable':
            chat_status = 'off'
            update_session(yaml_filename, chatstatus='off')
        elif chat_available == 'observeonly':
            chat_status = 'observeonly'
            update_session(yaml_filename, chatstatus='observeonly')
        else:
            chat_status = session_info['chatstatus']
        if chat_status in ('ready', 'on'):
            chat_status = 'ringing'
            update_session(yaml_filename, chatstatus='ringing')
        if chat_status != 'off':
            send_changes = 'true'
        else:
            if do_action != 'null':
                send_changes = 'true'
            else:
                send_changes = 'false'
        if current_user.is_authenticated:
            user_id_string = str(current_user.id)
            if current_user.has_role('admin', 'developer', 'advocate'):
                is_user = 'false'
            else:
                is_user = 'true'
        else:
            user_id_string = 't' + str(session['tempuser'])
            is_user = 'true'
        if r.get('da:control:uid:' + str(user_code) + ':i:' + str(yaml_filename) + ':userid:' + str(
                the_user_id)) is not None:
            being_controlled = 'true'
        else:
            being_controlled = 'false'
        if debug_mode:
            debug_readability_help = """
            $("#dareadability-help").show();
            $("#dareadability-question").hide();
"""
            debug_readability_question = """
            $("#dareadability-help").hide();
            $("#dareadability-question").show();
"""
        else:
            debug_readability_help = ''
            debug_readability_question = ''
        the_checkin_interval = interview.options.get('checkin interval', CHECKIN_INTERVAL)
        if interview.options.get('analytics on', True):
            if ga_configured:
                ga_id = google_config.get('analytics id')
            else:
                ga_id = None
            if 'segment id' in daconfig:
                segment_id = daconfig['segment id']
            else:
                segment_id = None
        else:
            ga_id = None
            segment_id = None
        page_sep = "#page"
        if refer is None:
            location_bar = url_for('index.index', **index_params)
        elif refer[0] in ('start', 'run'):
            location_bar = url_for('interview.run_interview_in_package', package=refer[1], filename=refer[2])
            page_sep = "#/"
        elif refer[0] in ('start_dispatch', 'run_dispatch'):
            location_bar = url_for('interview.run_interview', dispatch=refer[1])
            page_sep = "#/"
        elif refer[0] in ('start_directory', 'run_directory'):
            location_bar = url_for('interview.run_interview_in_package_directory', package=refer[1], directory=refer[2],
                                   filename=refer[3])
            page_sep = "#/"
        else:
            location_bar = None
            for k, v in daconfig['dispatch'].items():
                if v == yaml_filename:
                    location_bar = url_for('interview.run_interview', dispatch=k)
                    page_sep = "#/"
                    break
            if location_bar is None:
                location_bar = url_for('index.index', **index_params)
        index_params_external = copy.copy(index_params)
        index_params_external['_external'] = True
        the_js = render_template(
            "base.js",
            word=word,
            js_target=js_target,
            is_js=is_js,
            allow_going_back=allow_going_back,
            steps=steps,
            is_user=is_user,
            chat_status=chat_status,
            chat_mode=chat_mode,
            send_changes=send_changes,
            being_controlled=being_controlled,
            user_id_string=user_dict['_internal']['informed'].get(user_id_string, {}),
            ga_id=ga_id,
            segment_id=segment_id,
            question_id_dict=question_id_dict,
            csrf=generate_csrf(),
            index_params=index_params,
            location_bar=location_bar,
            index_params_external=index_params_external,
            yaml_filename=yaml_filename,
            NOTIFICATION_CONTAINER=NOTIFICATION_CONTAINER,
            NOTIFICATION_MESSAGE=NOTIFICATION_MESSAGE,
            roles=user_dict['_internal']['livehelp']['roles'],
            partner_roles=user_dict['_internal']['livehelp']['partner_roles'],
            page_sep=page_sep,
            reload_after=int(reload_after),
            the_checkin_interval=the_checkin_interval,
            daconfig=daconfig,
            debug_readability_help=debug_readability_help,
            debug_readability_question=debug_readability_question,
            button_style=current_app.config['BUTTON_STYLE'],
            ROOT=ROOT,
            forceFullScreen=interview.force_fullscreen is True or (
                    re.search(r'mobile', str(interview.force_fullscreen).lower()) and is_mobile_or_tablet()),
            custom_data_types=interview.custom_data_types,
            custom_types=docassemble.base.functions.custom_types,
            question_data=interview_status.as_data(user_dict) if interview.options.get('send question data',
                                                                                       False) else None,
            popover_trigger=interview.options.get('popover trigger', 'focus'),
            chat_available=chat_available,
            message_log=safeid(json.dumps(docassemble.base.functions.get_message_log()))
        )
        scripts += """
    <script type="text/javascript">
""" + the_js + """
    </script>"""
    if interview_status.question.language != '*':
        interview_language = interview_status.question.language
    else:
        interview_language = current_language
    validation_rules = {'rules': {}, 'messages': {}, 'errorClass': 'da-has-error invalid-feedback', 'debug': False}
    interview_status.exit_url = title_info.get('exit url', None)
    interview_status.exit_link = title_info.get('exit link', 'exit')
    interview_status.exit_label = title_info.get('exit label', word('Exit'))
    interview_status.title = title_info.get('full', default_title)
    interview_status.display_title = title_info.get('logo', interview_status.title)
    interview_status.tabtitle = title_info.get('tab', interview_status.title)
    interview_status.short_title = title_info.get('short', title_info.get('full', default_short_title))
    interview_status.display_short_title = title_info.get('short logo',
                                                          title_info.get('logo', interview_status.short_title))
    interview_status.title_url = title_info.get('title url', None)
    interview_status.title_url_opens_in_other_window = title_info.get('title url opens in other window', True)
    interview_status.nav_item = title_info.get('navigation bar html', '')
    the_main_page_parts = main_page_parts.get(interview_language, main_page_parts.get('*'))
    interview_status.pre = title_info.get('pre', the_main_page_parts['main page pre'])
    interview_status.post = title_info.get('post', the_main_page_parts['main page post'])
    interview_status.footer = title_info.get('footer',
                                             the_main_page_parts['main page footer'] or get_part('global footer'))
    if interview_status.footer:
        interview_status.footer = re.sub(r'</?p.*?>', '', str(interview_status.footer), flags=re.IGNORECASE).strip()
        if interview_status.footer == 'off':
            interview_status.footer = ''
    interview_status.submit = title_info.get('submit', the_main_page_parts['main page submit'])
    interview_status.back = title_info.get('back button label', the_main_page_parts[
        'main page back button label'] or interview_status.question.back())
    interview_status.cornerback = title_info.get('corner back button label', the_main_page_parts[
        'main page corner back button label'] or interview_status.question.back())
    bootstrap_theme = interview.get_bootstrap_theme()
    if not is_ajax:
        social = copy.deepcopy(daconfig['social'])
        if 'social' in interview.consolidated_metadata and isinstance(interview.consolidated_metadata['social'], dict):
            populate_social(social, interview.consolidated_metadata['social'])
        standard_header_start = standard_html_start(interview_language=interview_language, debug=debug_mode,
                                                    bootstrap_theme=bootstrap_theme, page_title=interview_status.title,
                                                    social=social, yaml_filename=yaml_filename)
    if interview_status.question.question_type == "signature":
        interview_status.extra_scripts.append(
            '<script>$( document ).ready(function() {daInitializeSignature();});</script>')
        if interview.options.get('hide navbar', False):
            bodyclass = "dasignature navbarhidden"
        else:
            bodyclass = "dasignature"
    else:
        if interview.options.get('hide navbar', False):
            bodyclass = "dabody"
        else:
            bodyclass = "dabody da-pad-for-navbar"
    if 'cssClass' in interview_status.extras:
        bodyclass += ' ' + re.sub(r'[^A-Za-z0-9\_]+', '-', interview_status.extras['cssClass'])
    elif hasattr(interview_status.question, 'id'):
        bodyclass += ' question-' + re.sub(r'[^A-Za-z0-9]+', '-', interview_status.question.id.lower())
    if interview_status.footer:
        bodyclass += ' da-pad-for-footer'
    if debug_mode:
        interview_status.screen_reader_text = {}
    if 'speak_text' in interview_status.extras and interview_status.extras['speak_text']:
        interview_status.initialize_screen_reader()
        util_language = docassemble.base.functions.get_language()
        util_dialect = docassemble.base.functions.get_dialect()
        question_language = interview_status.question.language
        if len(interview.translations) > 0:
            the_language = util_language
        elif question_language != '*':
            the_language = question_language
        else:
            the_language = util_language
        if voicerss_config and 'language map' in voicerss_config and isinstance(voicerss_config['language map'],
                                                                                dict) and the_language in \
                voicerss_config['language map']:
            the_language = voicerss_config['language map'][the_language]
        if the_language == util_language and util_dialect is not None:
            the_dialect = util_dialect
        elif voicerss_config and 'dialects' in voicerss_config and isinstance(voicerss_config['dialects'],
                                                                              dict) and the_language in voicerss_config[
            'dialects']:
            the_dialect = voicerss_config['dialects'][the_language]
        elif the_language in valid_voicerss_dialects:
            the_dialect = valid_voicerss_dialects[the_language][0]
        else:
            logmessage("index: unable to determine dialect; reverting to default")
            the_language = DEFAULT_LANGUAGE
            the_dialect = DEFAULT_DIALECT
        for question_type in ('question', 'help'):
            for audio_format in ('mp3', 'ogg'):
                interview_status.screen_reader_links[question_type].append([url_for('files.speak_file', i=yaml_filename,
                                                                                    question=interview_status.question.number,
                                                                                    digest='XXXTHEXXX' + question_type + 'XXXHASHXXX',
                                                                                    type=question_type,
                                                                                    format=audio_format,
                                                                                    language=the_language,
                                                                                    dialect=the_dialect),
                                                                            audio_mimetype_table[audio_format]])
    if (not validated) and the_question.name == interview_status.question.name:
        for def_key, def_val in new_values.items():
            safe_def_key = safeid(def_key)
            if isinstance(def_val, list):
                def_val = '[' + ','.join(def_val) + ']'
            if safe_def_key in all_field_numbers:
                for number in all_field_numbers[safe_def_key]:
                    try:
                        interview_status.defaults[number] = eval(def_val, pre_user_dict)
                    except:
                        pass
            else:
                try:
                    interview_status.other_defaults[def_key] = eval(def_val, pre_user_dict)
                except:
                    pass
        the_field_errors = field_error
    else:
        the_field_errors = None
    # restore this, maybe
    # if next_action_to_set:
    #     interview_status.next_action.append(next_action_to_set)
    if next_action_to_set:
        if 'event_stack' not in user_dict['_internal']:
            user_dict['_internal']['event_stack'] = {}
        session_uid = interview_status.current_info['user']['session_uid']
        if session_uid not in user_dict['_internal']['event_stack']:
            user_dict['_internal']['event_stack'][session_uid] = []
        already_there = False
        for event_item in user_dict['_internal']['event_stack'][session_uid]:
            if event_item['action'] == next_action_to_set['action']:
                already_there = True
                break
        if not already_there:
            user_dict['_internal']['event_stack'][session_uid].insert(0, next_action_to_set)
    if interview.use_progress_bar and (
            interview_status.question.progress is None or interview_status.question.progress >= 0):
        the_progress_bar = progress_bar(user_dict['_internal']['progress'], interview)
    else:
        the_progress_bar = None
    if interview.use_navigation and user_dict['nav'].visible():
        if interview.use_navigation_on_small_screens == 'dropdown':
            current_dict = {}
            dropdown_nav_bar = navigation_bar(user_dict['nav'], interview, wrapper=False, a_class='dropdown-item',
                                              hide_inactive_subs=False, always_open=True, return_dict=current_dict)
            if dropdown_nav_bar != '':
                dropdown_nav_bar = '        <div class="col d-md-none text-end">\n          <div class="dropdown">\n            <button class="btn btn-primary dropdown-toggle" type="button" id="daDropdownSections" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false">' + current_dict.get(
                    'title', word(
                        "Sections")) + '</button>\n            <div class="dropdown-menu" aria-labelledby="daDropdownSections">' + dropdown_nav_bar + '\n          </div>\n          </div>\n        </div>\n'
        else:
            dropdown_nav_bar = ''
        if interview.use_navigation == 'horizontal':
            if interview.use_navigation_on_small_screens is not True:
                nav_class = ' d-none d-md-block'
            else:
                nav_class = ''
            the_nav_bar = navigation_bar(user_dict['nav'], interview, wrapper=False,
                                         inner_div_class='nav flex-row justify-content-center align-items-center nav-pills danav danavlinks danav-horiz danavnested-horiz')
            if the_nav_bar != '':
                the_nav_bar = dropdown_nav_bar + '        <div class="col' + nav_class + '">\n          <div class="nav flex-row justify-content-center align-items-center nav-pills danav danavlinks danav-horiz">\n            ' + the_nav_bar + '\n          </div>\n        </div>\n      </div>\n      <div class="row tab-content">\n'
        else:
            if interview.use_navigation_on_small_screens == 'dropdown':
                if dropdown_nav_bar:
                    horiz_nav_bar = dropdown_nav_bar + '\n      </div>\n      <div class="row tab-content">\n'
                else:
                    horiz_nav_bar = ''
            elif interview.use_navigation_on_small_screens:
                horiz_nav_bar = navigation_bar(user_dict['nav'], interview, wrapper=False,
                                               inner_div_class='nav flex-row justify-content-center align-items-center nav-pills danav danavlinks danav-horiz danavnested-horiz')
                if horiz_nav_bar != '':
                    horiz_nav_bar = dropdown_nav_bar + '        <div class="col d-md-none">\n          <div class="nav flex-row justify-content-center align-items-center nav-pills danav danavlinks danav-horiz">\n            ' + horiz_nav_bar + '\n          </div>\n        </div>\n      </div>\n      <div class="row tab-content">\n'
            else:
                horiz_nav_bar = ''
            the_nav_bar = navigation_bar(user_dict['nav'], interview)
        if the_nav_bar != '':
            if interview.use_navigation == 'horizontal':
                interview_status.using_navigation = 'horizontal'
            else:
                interview_status.using_navigation = 'vertical'
        else:
            interview_status.using_navigation = False
    else:
        the_nav_bar = ''
        interview_status.using_navigation = False
    content = as_html(interview_status, debug_mode, url_for('index.index', **index_params), validation_rules,
                      the_field_errors, the_progress_bar, steps - user_dict['_internal']['steps_offset'])
    if debug_mode:
        readability = {}
        for question_type in ('question', 'help'):
            if question_type not in interview_status.screen_reader_text:
                continue
            phrase = to_text(interview_status.screen_reader_text[question_type])
            if (not phrase) or len(phrase) < 10:
                phrase = "The sky is blue."
            phrase = re.sub(r'[^A-Za-z 0-9\.\,\?\#\!\%\&\(\)]', r' ', phrase)
            readability[question_type] = [('Flesch Reading Ease', textstat.flesch_reading_ease(phrase)),
                                          ('Flesch-Kincaid Grade Level', textstat.flesch_kincaid_grade(phrase)),
                                          ('Gunning FOG Scale', textstat.gunning_fog(phrase)),
                                          ('SMOG Index', textstat.smog_index(phrase)),
                                          ('Automated Readability Index', textstat.automated_readability_index(phrase)),
                                          ('Coleman-Liau Index', textstat.coleman_liau_index(phrase)),
                                          ('Linsear Write Formula', textstat.linsear_write_formula(phrase)),
                                          ('Dale-Chall Readability Score',
                                           textstat.dale_chall_readability_score(phrase)),
                                          ('Readability Consensus', textstat.text_standard(phrase))]
        readability_report = ''
        for question_type in ('question', 'help'):
            if question_type in readability:
                readability_report += '          <div id="dareadability-' + question_type + '"' + (
                    ' style="display: none;"' if question_type == 'help' else '') + '>\n'
                if question_type == 'question':
                    readability_report += '            <h3>' + word("Readability of question") + '</h3>\n'
                else:
                    readability_report += '            <h3>' + word("Readability of help text") + '</h3>\n'
                readability_report += '            <table class="table">' + "\n"
                readability_report += '              <tr><th>' + word("Formula") + '</th><th>' + word(
                    "Score") + '</th></tr>' + "\n"
                for read_type, value in readability[question_type]:
                    readability_report += '              <tr><td>' + read_type + '</td><td>' + str(
                        value) + "</td></tr>\n"
                readability_report += '            </table>' + "\n"
                readability_report += '          </div>' + "\n"
    if interview_status.using_screen_reader:
        for question_type in ('question', 'help'):
            if question_type not in interview_status.screen_reader_text:
                continue
            phrase = to_text(interview_status.screen_reader_text[question_type])
            if encrypted:
                the_phrase = encrypt_phrase(phrase, secret)
            else:
                the_phrase = pack_phrase(phrase)
            the_hash = MD5Hash(data=phrase).hexdigest()
            content = re.sub(r'XXXTHEXXX' + question_type + 'XXXHASHXXX', the_hash, content)
            existing_entry = db.session.execute(select(SpeakList).filter_by(filename=yaml_filename, key=user_code,
                                                                            question=interview_status.question.number,
                                                                            digest=the_hash, type=question_type,
                                                                            language=the_language,
                                                                            dialect=the_dialect).with_for_update()).scalar()
            if existing_entry:
                if existing_entry.encrypted:
                    existing_phrase = decrypt_phrase(existing_entry.phrase, secret)
                else:
                    existing_phrase = unpack_phrase(existing_entry.phrase)
                if phrase != existing_phrase:
                    logmessage("index: the phrase changed; updating it")
                    existing_entry.phrase = the_phrase
                    existing_entry.upload = None
                    existing_entry.encrypted = encrypted
            else:
                new_entry = SpeakList(filename=yaml_filename, key=user_code, phrase=the_phrase,
                                      question=interview_status.question.number, digest=the_hash, type=question_type,
                                      language=the_language, dialect=the_dialect, encrypted=encrypted)
                db.session.add(new_entry)
            db.session.commit()
    append_css_urls = []
    if not is_ajax:
        start_output = standard_header_start
        if 'css' in interview.external_files:
            for packageref, fileref in interview.external_files['css']:
                the_url = get_url_from_file_reference(fileref, _package=packageref)
                if is_js:
                    append_css_urls.append(the_url)
                if the_url is not None:
                    start_output += "\n" + '    <link href="' + the_url + '" rel="stylesheet">'
                else:
                    logmessage("index: could not find css file " + str(fileref))
        start_output += current_app.config['GLOBAL_CSS'] + additional_css(interview_status)
        if is_js:
            append_javascript += additional_css(interview_status, js_only=True)
        start_output += '\n    <title>' + interview_status.tabtitle + '</title>\n  </head>\n  <body class="' + bodyclass + '">\n  <div id="dabody">\n'
    if interview.options.get('hide navbar', False):
        output = make_navbar(interview_status, (steps - user_dict['_internal']['steps_offset']),
                             interview.consolidated_metadata.get('show login', SHOW_LOGIN),
                             user_dict['_internal']['livehelp'], debug_mode, index_params, extra_class='dainvisible')
    else:
        output = make_navbar(interview_status, (steps - user_dict['_internal']['steps_offset']),
                             interview.consolidated_metadata.get('show login', SHOW_LOGIN),
                             user_dict['_internal']['livehelp'], debug_mode, index_params)
    output += flash_content + '    <div class="container">' + "\n      " + '<div class="row tab-content">' + "\n"
    if the_nav_bar != '':
        if interview_status.using_navigation == 'vertical':
            output += horiz_nav_bar
        output += the_nav_bar
    output += content
    if 'rightText' in interview_status.extras:
        if interview_status.using_navigation == 'vertical':
            output += '          <section id="daright" role="complementary" class="d-none d-lg-block col-lg-3 col-xl-2 daright">\n'
        else:
            if interview.flush_left:
                output += '          <section id="daright" role="complementary" class="d-none d-lg-block col-lg-6 col-xl-5 daright">\n'
            else:
                output += '          <section id="daright" role="complementary" class="d-none d-lg-block col-lg-3 col-xl-3 daright">\n'
        output += docassemble.base.util.markdown_to_html(interview_status.extras['rightText'], trim=False,
                                                         status=interview_status) + "\n"
        output += '          </section>\n'
    output += "      </div>\n"
    if interview_status.question.question_type != "signature" and interview_status.post:
        output += '      <div class="row">' + "\n"
        if interview_status.using_navigation == 'vertical':
            output += '        <div class="offset-xl-3 offset-lg-3 offset-md-3 col-lg-6 col-md-9 col-sm-12 daattributions" id="daattributions">\n'
        else:
            if interview.flush_left:
                output += '        <div class="offset-xl-1 col-xl-5 col-lg-6 col-md-8 col-sm-12 daattributions" id="daattributions">\n'
            else:
                output += '        <div class="offset-xl-3 offset-lg-3 col-xl-6 col-lg-6 offset-md-2 col-md-8 col-sm-12 daattributions" id="daattributions">\n'
        output += interview_status.post
        output += '        </div>\n'
        output += '      </div>' + "\n"
    if len(interview_status.attributions) > 0:
        output += '      <div class="row">' + "\n"
        if interview_status.using_navigation == 'vertical':
            output += '        <div class="offset-xl-3 offset-lg-3 offset-md-3 col-lg-6 col-md-9 col-sm-12 daattributions" id="daattributions">\n'
        else:
            if interview.flush_left:
                output += '        <div class="offset-xl-1 col-xl-5 col-lg-6 col-md-8 col-sm-12 daattributions" id="daattributions">\n'
            else:
                output += '        <div class="offset-xl-3 offset-lg-3 col-xl-6 col-lg-6 offset-md-2 col-md-8 col-sm-12 daattributions" id="daattributions">\n'
        output += '          <br/><br/><br/><br/><br/><br/><br/>\n'
        for attribution in sorted(interview_status.attributions):
            output += '          <div><p><cite><small>' + docassemble.base.util.markdown_to_html(attribution,
                                                                                                 status=interview_status,
                                                                                                 strip_newlines=True,
                                                                                                 trim=True) + '</small></cite></p></div>\n'
        output += '        </div>\n'
        output += '      </div>' + "\n"
    if debug_mode:
        output += '      <div id="dasource" class="collapse mt-3">' + "\n"
        output += '      <h2 class="visually-hidden">Information for developers</h2>\n'
        output += '      <div class="row">' + "\n"
        output += '        <div class="col-md-12">' + "\n"
        if interview_status.using_screen_reader:
            output += '          <h3>' + word('Plain text of sections') + '</h3>' + "\n"
            for question_type in ('question', 'help'):
                if question_type in interview_status.screen_reader_text:
                    output += '<pre style="white-space: pre-wrap;">' + to_text(
                        interview_status.screen_reader_text[question_type]) + '</pre>\n'
        output += '          <hr>\n'
        output += '          <h3>' + word(
            'Source code for question') + '<a class="float-end btn btn-info" target="_blank" href="' + url_for(
            'get_variables', i=yaml_filename) + '">' + word('Show variables and values') + '</a></h3>' + "\n"
        if interview_status.question.from_source.path != interview.source.path and interview_status.question.from_source.path is not None:
            output += '          <p style="font-weight: bold;"><small>(' + word(
                'from') + ' ' + interview_status.question.from_source.path + ")</small></p>\n"
        if (not hasattr(interview_status.question, 'source_code')) or interview_status.question.source_code is None:
            output += '          <p>' + word('unavailable') + '</p>'
        else:
            output += highlight(interview_status.question.source_code, YamlLexer(), HtmlFormatter())
        if len(interview_status.seeking) > 1:
            output += '          <h4>' + word('How question came to be asked') + '</h4>' + "\n"
            output += get_history(interview, interview_status)
        output += '        </div>' + "\n"
        output += '      </div>' + "\n"
        output += '      <div class="row mt-4">' + "\n"
        output += '        <div class="col-md-8 col-lg-6">' + "\n"
        output += readability_report
        output += '        </div>' + "\n"
        output += '      </div>' + "\n"
        output += '      </div>' + "\n"
    output += '    </div>'
    if interview_status.footer:
        output += """
    <footer class=""" + '"' + current_app.config['FOOTER_CLASS'] + '"' + """>
      <div class="container">
        """ + interview_status.footer + """
      </div>
    </footer>
"""
    if not is_ajax:
        end_output = scripts + current_app.config['GLOBAL_JS'] + "\n" + indent_by("".join(interview_status.extra_scripts).strip(), 4).rstrip() + "\n  </div>\n  </body>\n</html>"
    key = 'da:html:uid:' + str(user_code) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
    pipe = r.pipeline()
    pipe.set(key, json.dumps(dict(body=output, extra_scripts=interview_status.extra_scripts, global_css=current_app.config['GLOBAL_CSS'],
                                  extra_css=interview_status.extra_css, browser_title=interview_status.tabtitle,
                                  lang=interview_language, bodyclass=bodyclass, bootstrap_theme=bootstrap_theme)))
    pipe.expire(key, 60)
    pipe.execute()
    if user_dict['_internal']['livehelp']['availability'] != 'unavailable':
        inputkey = 'da:input:uid:' + str(user_code) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
        r.publish(inputkey, json.dumps(dict(message='newpage', key=key)))
    if is_json:
        data = dict(browser_title=interview_status.tabtitle, lang=interview_language, csrf_token=generate_csrf(),
                    steps=steps, allow_going_back=allow_going_back,
                    message_log=docassemble.base.functions.get_message_log(), id_dict=question_id_dict)
        data.update(interview_status.as_data(user_dict))
        if reload_after and reload_after > 0:
            data['reload_after'] = reload_after
        if 'action' in data and data['action'] == 'redirect' and 'url' in data:
            current_app.logger.error("Redirecting because of a redirect action.\n")
            response = redirect(data['url'])
        else:
            response = jsonify(**data)
    elif is_ajax:
        if interview_status.question.checkin is not None:
            do_action = interview_status.question.checkin
        else:
            do_action = None
        if interview.options.get('send question data', False):
            response = jsonify(action='body', body=output, extra_scripts=interview_status.extra_scripts,
                               extra_css=interview_status.extra_css, browser_title=interview_status.tabtitle,
                               lang=interview_language, bodyclass=bodyclass, reload_after=reload_after,
                               livehelp=user_dict['_internal']['livehelp'], csrf_token=generate_csrf(),
                               do_action=do_action, steps=steps, allow_going_back=allow_going_back,
                               message_log=docassemble.base.functions.get_message_log(), id_dict=question_id_dict,
                               question_data=interview_status.as_data(user_dict))
        else:
            response = jsonify(action='body', body=output, extra_scripts=interview_status.extra_scripts,
                               extra_css=interview_status.extra_css, browser_title=interview_status.tabtitle,
                               lang=interview_language, bodyclass=bodyclass, reload_after=reload_after,
                               livehelp=user_dict['_internal']['livehelp'], csrf_token=generate_csrf(),
                               do_action=do_action, steps=steps, allow_going_back=allow_going_back,
                               message_log=docassemble.base.functions.get_message_log(), id_dict=question_id_dict)
        if response_wrapper:
            response_wrapper(response)
        if return_fake_html:
            fake_up(response, interview_language)
    elif is_js:
        output = the_js + "\n" + append_javascript
        if 'global css' in daconfig:
            for fileref in daconfig['global css']:
                append_css_urls.append(get_url_from_file_reference(fileref))
        if 'global javascript' in daconfig:
            for fileref in daconfig['global javascript']:
                append_script_urls.append(get_url_from_file_reference(fileref))
        if len(append_css_urls) > 0:
            output += """
      var daLink;"""
        for path in append_css_urls:
            output += """
      daLink = document.createElement('link');
      daLink.href = """ + json.dumps(path) + """;
      daLink.rel = "stylesheet";
      document.head.appendChild(daLink);
"""
        if len(append_script_urls) > 0:
            output += """
      var daScript;"""
        for path in append_script_urls:
            output += """
      daScript = document.createElement('script');
      daScript.src = """ + json.dumps(path) + """;
      document.head.appendChild(daScript);
"""
        response = make_response(output.encode('utf-8'), '200 OK')
        response.headers['Content-type'] = 'application/javascript; charset=utf-8'
    else:
        output = start_output + output + end_output
        response = make_response(output.encode('utf-8'), '200 OK')
        response.headers['Content-type'] = 'text/html; charset=utf-8'
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    release_lock(user_code, yaml_filename)
    if 'in error' in session:
        del session['in error']
    if response_wrapper:
        response_wrapper(response)
    return response
