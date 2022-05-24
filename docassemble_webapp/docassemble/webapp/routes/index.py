import base64
import codecs
import copy
import datetime
import json
import os
import pickle
import re
import sys
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
from docassemble.webapp.global_values import global_css, global_js
from docassemble.webapp.core.models import MachineLearning, SpeakList
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.package import get_url_from_file_reference
from docassemble.webapp.page_values import additional_css, additional_scripts, exit_href, navigation_bar, \
    standard_html_start, standard_scripts
from docassemble.webapp.screenreader import to_text
from docassemble.webapp.setup import da_version
from docassemble.webapp.users.models import TempUser
from docassemble.webapp.util import MD5Hash, add_referer, as_int, do_redirect, fresh_dictionary, from_safeid, \
    get_history, get_part, illegal_variable_name, indent_by, is_mobile_or_tablet, \
    myb64unquote, noquote, process_bracket_expression, process_file, process_set_variable, refresh_or_continue, safeid, \
    secure_filename, sub_indices, tidy_action, title_converter, update_current_info_with_session_info
from docassemble_textstat.textstat import textstat
from flask import Blueprint, current_app, flash, get_flashed_messages, jsonify, make_response, redirect, request, \
    send_file, session
from flask_login import current_user, logout_user
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import YamlLexer
from sqlalchemy import select

indexBp = Blueprint('index', __name__)


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
    progress = min(progress, 100)
    if hasattr(interview, 'show_progress_bar_percentage') and interview.show_progress_bar_percentage:
        percentage = str(int(progress)) + '%'
    else:
        percentage = ''
    return '<div class="progress mt-2"><div class="progress-bar" aria-label="' + noquote(
        word('Interview Progress')) + '" role="progressbar" aria-valuenow="' + str(
        progress) + '" aria-valuemin="0" aria-valuemax="100" style="width: ' + str(
        progress) + '%;">' + percentage + '</div></div>\n'


def do_refresh(is_ajax, yaml_filename):
    if is_ajax:
        return jsonify(action='refresh', csrf_token=generate_csrf())
    return redirect(url_for('index', i=yaml_filename))


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
    if 'jsembed' in docassemble.base.functions.this_thread.misc:
        fixed_top = ''
    else:
        fixed_top = ' fixed-top'
    if extra_class is not None:
        fixed_top += ' ' + extra_class
    navbar = """\
    <div class="navbar""" + fixed_top + """ navbar-expand-md """ + inverse + '"' + """ role="banner">
      <div class="container danavcontainer justify-content-start">
"""
    if status.question.can_go_back and steps > 1:
        if status.question.interview.navigation_back_button:
            navbar += """\
        <form style="display: inline-block" id="dabackbutton" method="POST" action=""" + json.dumps(url_for('index',
                                                                                                            **index_params)) + """><input type="hidden" name="csrf_token" value=""" + '"' + generate_csrf() + '"' + """/><input type="hidden" name="_back_one" value="1"/><button class="navbar-brand navbar-nav dabackicon dabackbuttoncolor me-3" type="submit" title=""" + json.dumps(
                word(
                    "Go back to the previous question")) + """><span class="nav-link"><i class="fas fa-chevron-left"></i><span class="daback">""" + status.cornerback + """</span></span></button></form>
"""
        else:
            navbar += """\
        <form hidden style="display: inline-block" id="dabackbutton" method="POST" action=""" + json.dumps(
                url_for('index',
                        **index_params)) + """><input type="hidden" name="csrf_token" value=""" + '"' + generate_csrf() + '"' + """/><input type="hidden" name="_back_one" value="1"/></form>
"""
    if status.title_url:
        if str(status.title_url_opens_in_other_window) == 'False':
            target = ''
        else:
            target = ' target="_blank"'
        navbar += """\
        <a id="dapagetitle" class="navbar-brand danavbar-title dapointer" href=""" + '"' + status.title_url + '"' + target + """><span class="d-none d-md-block">""" + status.display_title + """</span><span class="d-block d-md-none">""" + status.display_short_title + """</span></a>
"""
    else:
        navbar += """\
        <span id="dapagetitle" class="navbar-brand danavbar-title"><span class="d-none d-md-block">""" + status.display_title + """</span><span class="d-block d-md-none">""" + status.display_short_title + """</span></span>
"""
    help_message = word("Help is available")
    help_label = None
    if status.question.interview.question_help_button:
        the_sections = status.interviewHelpText
    else:
        the_sections = status.helpText + status.interviewHelpText
    for help_section in the_sections:
        if help_section['label']:
            help_label = help_section['label']
            break
    if help_label is None:
        help_label = status.extras.get('help label text', None)
    if help_label is None:
        help_label = status.question.help()
    extra_help_message = word("Help is available for this question")
    phone_sr = word("Phone help")
    phone_message = word("Phone help is available")
    chat_sr = word("Live chat")
    source_message = word("Information for the developer")
    if debug_mode:
        source_button = '<div class="nav-item navbar-nav d-none d-md-block"><button class="btn btn-link nav-link da-no-outline" title=' + json.dumps(
            source_message) + ' id="dasourcetoggle" data-bs-toggle="collapse" data-bs-target="#dasource"><i class="fas fa-code"></i></button></div>'
        source_menu_item = '<a class="dropdown-item d-block d-md-none navbar" title=' + json.dumps(
            source_message) + ' href="#dasource" data-bs-toggle="collapse" aria-expanded="false" aria-controls="source">' + word(
            'Source') + '</a>'
    else:
        source_button = ''
        source_menu_item = ''
    hidden_question_button = '<li class="nav-item visually-hidden-focusable"><button class="btn btn-link nav-link active da-no-outline" id="daquestionlabel" data-bs-toggle="tab" data-bs-target="#daquestion">' + word(
        'Question') + '</button></li>'
    navbar += '        ' + source_button + '<ul id="nav-bar-tab-list" class="nav navbar-nav damynavbar-right" role="tablist">' + hidden_question_button
    if len(status.interviewHelpText) > 0 or (
            len(status.helpText) > 0 and not status.question.interview.question_help_button):
        if status.question.helptext is None or status.question.interview.question_help_button:
            navbar += '<li class="nav-item" role="presentation"><button class="btn btn-link nav-link dahelptrigger da-no-outline" data-bs-target="#dahelp" data-bs-toggle="tab" role="tab" id="dahelptoggle" title=' + json.dumps(
                help_message) + '>' + help_label + '</button></li>'
        else:
            navbar += '<li class="nav-item" role="presentation"><button class="btn btn-link nav-link dahelptrigger da-no-outline daactivetext" data-bs-target="#dahelp" data-bs-toggle="tab" role="tab" id="dahelptoggle" title=' + json.dumps(
                extra_help_message) + '>' + help_label + ' <i class="fas fa-star"></i></button></li>'
    else:
        navbar += '<li hidden class="nav-item dainvisible" role="presentation"><button class="btn btn-link nav-link dahelptrigger da-no-outline" id="dahelptoggle" data-bs-target="#dahelp" data-bs-toggle="tab" role="tab">' + word(
            'Help') + '</button></li>'
    navbar += '<li hidden class="nav-item dainvisible" id="daPhoneAvailable"><button data-bs-target="#dahelp" data-bs-toggle="tab" role="tab" title=' + json.dumps(
        phone_message) + ' class="btn btn-link nav-link dapointer dahelptrigger da-no-outline"><i class="fas fa-phone da-chat-active"></i><span class="visually-hidden">' + phone_sr + '</span></button></li>' + \
              '<li class="nav-item dainvisible" id="daChatAvailable"><button data-bs-target="#dahelp" data-bs-toggle="tab" class="btn btn-link nav-link dapointer dahelptrigger da-no-outline"><i class="fas fa-comment-alt"></i><span class="visually-hidden">' + chat_sr + '</span></button></li></ul>'
    navbar += """
        <button id="damobile-toggler" type="button" class="navbar-toggler ms-auto" data-bs-toggle="collapse" data-bs-target="#danavbar-collapse">
          <span class="navbar-toggler-icon"></span><span class="visually-hidden">""" + word("Display the menu") + """</span>
        </button>
        <div class="collapse navbar-collapse" id="danavbar-collapse">
          <ul class="navbar-nav ms-auto">
"""
    navbar += status.nav_item
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
                    match_action = re.search(r'^\?action=([^\&]+)', menu_item['url'])
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
    if ALLOW_REGISTRATION:
        sign_in_text = word('Sign in or sign up to save answers')
    else:
        sign_in_text = word('Sign in to save answers')
    if daconfig.get('resume interview after login', False):
        login_url = url_for('user.login', next=url_for('index', **index_params))
    else:
        login_url = url_for('user.login')
    if show_login:
        if current_user.is_anonymous:
            if custom_menu:
                navbar += '            <li class="nav-item dropdown"><a href="#" class="nav-link dropdown-toggle d-none d-md-block" data-bs-toggle="dropdown" role="button" id="damenuLabel" aria-haspopup="true" aria-expanded="false">' + word(
                    "Menu") + '</a><div class="dropdown-menu dropdown-menu-end" aria-labelledby="damenuLabel">' + custom_menu + '<a class="dropdown-item" href="' + login_url + '">' + sign_in_text + '</a></div></li>'
            else:
                if daconfig.get('login link style', 'normal') == 'button':
                    if ALLOW_REGISTRATION:
                        if daconfig.get('resume interview after login', False):
                            register_url = url_for('user.register', next=url_for('index', **index_params))
                        else:
                            register_url = url_for('user.register')
                        navbar += '            <li class="nav-item"><a class="nav-link" href="' + register_url + '">' + word(
                            'Sign up') + '</a></li>'
                        navbar += '            <li class="nav-item"><a class="nav-link d-block d-md-none" href="' + login_url + '">' + word(
                            'Sign in') + '</a>'

                else:
                    navbar += '            <li class="nav-item"><a class="nav-link" href="' + login_url + '">' + sign_in_text + '</a></li>'
        else:
            if (custom_menu is False or custom_menu == '') and status.question.interview.options.get(
                    'hide standard menu', False):
                navbar += '            <li class="nav-item"><a class="nav-link" tabindex="-1">' + (
                    current_user.email if current_user.email else re.sub(r'.*\$', '',
                                                                         current_user.social_id)) + '</a></li>'
            else:
                navbar += '            <li class="nav-item dropdown"><a class="nav-link dropdown-toggle d-none d-md-block" href="#" data-bs-toggle="dropdown" role="button" id="damenuLabel" aria-haspopup="true" aria-expanded="false">' + (
                    current_user.email if current_user.email else re.sub(r'.*\$', '',
                                                                         current_user.social_id)) + '</a><div class="dropdown-menu dropdown-menu-end" aria-labelledby="damenuLabel">'
                if custom_menu:
                    navbar += custom_menu
                if not status.question.interview.options.get('hide standard menu', False):
                    if current_user.has_role('admin', 'developer'):
                        navbar += source_menu_item
                    if current_user.has_role('admin', 'advocate') and current_app.config['ENABLE_MONITOR']:
                        navbar += '<a class="dropdown-item" href="' + url_for('monitor') + '">' + word(
                            'Monitor') + '</a>'
                    if current_user.has_role('admin', 'developer', 'trainer'):
                        navbar += '<a class="dropdown-item" href="' + url_for('train') + '">' + word('Train') + '</a>'
                    if current_user.has_role('admin', 'developer'):
                        if current_app.config['ALLOW_UPDATES']:
                            navbar += '<a class="dropdown-item" href="' + url_for('update_package') + '">' + word(
                                'Package Management') + '</a>'
                        navbar += '<a class="dropdown-item" href="' + url_for('logs') + '">' + word('Logs') + '</a>'
                        if current_app.config['ENABLE_PLAYGROUND']:
                            navbar += '<a class="dropdown-item" href="' + url_for('playground_page') + '">' + word(
                                'Playground') + '</a>'
                        navbar += '<a class="dropdown-item" href="' + url_for('utilities') + '">' + word(
                            'Utilities') + '</a>'
                    if current_user.has_role('admin', 'advocate') or current_user.can_do('access_user_info'):
                        navbar += '<a class="dropdown-item" href="' + url_for('user_list') + '">' + word(
                            'User List') + '</a>'
                    if current_user.has_role('admin'):
                        navbar += '<a class="dropdown-item" href="' + url_for('config_page') + '">' + word(
                            'Configuration') + '</a>'
                    if current_app.config['SHOW_DISPATCH']:
                        navbar += '<a class="dropdown-item" href="' + url_for('interview_start') + '">' + word(
                            'Available Interviews') + '</a>'
                    for item in current_app.config['ADMIN_INTERVIEWS']:
                        if item.can_use() and docassemble.base.functions.this_thread.current_info.get('yaml_filename',
                                                                                                      '') != item.interview:
                            navbar += '<a class="dropdown-item" href="' + url_for('index', i=item.interview,
                                                                                  new_session='1') + '">' + item.get_title(
                                docassemble.base.functions.get_language()) + '</a>'
                    if current_app.config['SHOW_MY_INTERVIEWS'] or current_user.has_role('admin'):
                        navbar += '<a class="dropdown-item" href="' + url_for('interview_list') + '">' + word(
                            'My Interviews') + '</a>'
                    if current_user.has_role('admin', 'developer'):
                        navbar += '<a class="dropdown-item" href="' + url_for('user_profile_page') + '">' + word(
                            'Profile') + '</a>'
                    else:
                        if current_app.config['SHOW_PROFILE'] or current_user.has_role('admin'):
                            navbar += '<a class="dropdown-item" href="' + url_for('user_profile_page') + '">' + word(
                                'Profile') + '</a>'
                        else:
                            navbar += '<a class="dropdown-item" href="' + url_for('user.change_password') + '">' + word(
                                'Change Password') + '</a>'
                    navbar += '<a class="dropdown-item" href="' + url_for('user.logout') + '">' + word(
                        'Sign Out') + '</a>'
                navbar += '</div></li>'
    else:
        if custom_menu:
            navbar += '            <li class="nav-item dropdown"><a class="nav-link dropdown-toggle" href="#" class="dropdown-toggle d-none d-md-block" data-bs-toggle="dropdown" role="button" aria-haspopup="true" aria-expanded="false">' + word(
                "Menu") + '</a><div class="dropdown-menu dropdown-menu-end">' + custom_menu
            if not status.question.interview.options.get('hide standard menu', False):
                navbar += '<a class="dropdown-item" href="' + exit_href(status) + '">' + status.exit_label + '</a>'
            navbar += '</div></li>'
        else:
            navbar += '            <li class="nav-item"><a class="nav-link" href="' + exit_href(
                status) + '">' + status.exit_label + '</a></li>'
    navbar += """
          </ul>"""
    if daconfig.get('login link style',
                    'normal') == 'button' and show_login and current_user.is_anonymous and not custom_menu:
        navbar += '\n          <a class="btn btn-' + BUTTON_COLOR_NAV_LOGIN + ' btn-sm mb-0 ms-3 d-none d-md-block" href="' + login_url + '">' + word(
            'Sign in') + '</a>'
    navbar += """
        </div>
      </div>
    </div>
"""
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
            sys.stderr.write(
                "Redirecting to login because no YAML filename provided and no anonymous access is allowed.\n")
            return redirect(url_for('user.login'))
        if len(daconfig['dispatch']) > 0:
            sys.stderr.write("Redirecting to dispatch page because no YAML filename provided.\n")
            return redirect(url_for('interview_start'))
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
            sys.stderr.write("Redirecting to login because no anonymous access allowed.\n")
            return redirect(url_for('user.login', next=url_for('index', **request.args)))
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
                sys.stderr.write("Redirecting to login because sessions are unique.\n")
                return redirect(url_for('user.login', next=url_for('index', **request.args)))
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
                    sys.stderr.write(
                        "Redirecting to login because anonymous user not allowed to access this interview.\n")
                    return redirect(url_for('user.login', next=url_for('index', **request.args)))
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
                sys.stderr.write("Redirecting to login because sessions are unique.\n")
                return redirect(url_for('user.login', next=url_for('index', **request.args)))
            if current_user.is_anonymous:
                if (not interview.allowed_to_initiate(is_anonymous=True)) or (
                        not interview.allowed_to_access(is_anonymous=True)):
                    delete_session_for_interview(yaml_filename)
                    flash(word("You need to be logged in to access this interview."), "info")
                    sys.stderr.write(
                        "Redirecting to login because anonymous user not allowed to access this interview.\n")
                    return redirect(url_for('user.login', next=url_for('index', **request.args)))
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
            sys.stderr.write("index: there was an exception " + str(the_err.__class__.__name__) + ": " + str(
                the_err) + " after fetch_user_dict with %s and %s, so we need to reset\n" % (user_code, yaml_filename))
        except:
            sys.stderr.write("index: there was an exception " + str(
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
                sys.stderr.write("Session error because failure to get user dictionary.\n")
                return do_redirect(redirect_url, is_ajax, is_json, js_target)
        sys.stderr.write("Redirecting back to index because of failure to get user dictionary.\n")
        response = do_redirect(url_for('index', i=yaml_filename), is_ajax, is_json, js_target)
        if session_parameter is not None:
            flash(word("Unable to retrieve interview session.  Starting a new session instead."), "error")
        return response
    if user_dict is None:
        sys.stderr.write("index: no user_dict found after fetch_user_dict with %s and %s, so we need to reset\n" % (
            user_code, yaml_filename))
        release_lock(user_code, yaml_filename)
        logmessage("index: dictionary fetch returned no results")
        clear_session(yaml_filename)
        redirect_url = daconfig.get('session error redirect url', None)
        if isinstance(redirect_url, str) and redirect_url:
            redirect_url = redirect_url.format(i=urllibquote(yaml_filename), error=urllibquote('answers_missing'))
            sys.stderr.write("Session error because user dictionary was None.\n")
            return do_redirect(redirect_url, is_ajax, is_json, js_target)
        sys.stderr.write("Redirecting back to index because user dictionary was None.\n")
        response = do_redirect(url_for('index', i=yaml_filename), is_ajax, is_json, js_target)
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
                    sys.stderr.write(errMess.__class__.__name__ + ": " + str(errMess) + " after running " + the_string)
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
                                    sys.stderr.write("Error: " + errMess.__class__.__name__ + ": " + str(
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
                            sys.stderr.write("Error: " + errMess.__class__.__name__ + ": " + str(
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
                                    sys.stderr.write("Error: " + errMess.__class__.__name__ + ": " + str(
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
                            sys.stderr.write("Error: " + errMess.__class__.__name__ + ": " + str(
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
        sys.stderr.write("Redirecting because of an exit.\n")
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
        sys.stderr.write("Redirecting because of a logout.\n")
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
        sys.stderr.write("Redirecting because of a signin.\n")
        response = do_redirect(url_for('user.login', next=url_for('index', i=yaml_filename, session=user_code)),
                               is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type == "register":
        release_lock(user_code, yaml_filename)
        sys.stderr.write("Redirecting because of a register.\n")
        response = do_redirect(url_for('user.register', next=url_for('index', i=yaml_filename, session=user_code)),
                               is_ajax, is_json, js_target)
        if return_fake_html:
            fake_up(response, current_language)
        if response_wrapper:
            response_wrapper(response)
        return response
    if interview_status.question.question_type == "leave":
        release_lock(user_code, yaml_filename)
        sys.stderr.write("Redirecting because of a leave.\n")
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
        sys.stderr.write("Redirecting because of a redirect.\n")
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
        chat_available = user_dict['_internal']['livehelp']['availability']
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
        if interview.force_fullscreen is True or (
                re.search(r'mobile', str(interview.force_fullscreen).lower()) and is_mobile_or_tablet()):
            forceFullScreen = """
          if (data.steps > 1 && window != top) {
            top.location.href = location.href;
            return;
          }
"""
        else:
            forceFullScreen = ''
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
            location_bar = url_for('index', **index_params)
        elif refer[0] in ('start', 'run'):
            location_bar = url_for('run_interview_in_package', package=refer[1], filename=refer[2])
            page_sep = "#/"
        elif refer[0] in ('start_dispatch', 'run_dispatch'):
            location_bar = url_for('run_interview', dispatch=refer[1])
            page_sep = "#/"
        elif refer[0] in ('start_directory', 'run_directory'):
            location_bar = url_for('run_interview_in_package_directory', package=refer[1], directory=refer[2],
                                   filename=refer[3])
            page_sep = "#/"
        else:
            location_bar = None
            for k, v in daconfig['dispatch'].items():
                if v == yaml_filename:
                    location_bar = url_for('run_interview', dispatch=k)
                    page_sep = "#/"
                    break
            if location_bar is None:
                location_bar = url_for('index', **index_params)
        index_params_external = copy.copy(index_params)
        index_params_external['_external'] = True
        the_js = """\
      if (typeof($) == 'undefined'){
        var $ = jQuery.noConflict();
      }
      var daMapInfo = null;
      var daWhichButton = null;
      var daSocket = null;
      var daChatHistory = [];
      var daCheckinCode = null;
      var daCheckingIn = 0;
      var daShowingHelp = 0;
      var daIframeEmbed;
      if ( window.location !== window.parent.location ) {
        daIframeEmbed = true;
      }
      else {
        daIframeEmbed = false;
      }
      var daJsEmbed = """ + (json.dumps(js_target) if is_js else 'false') + """;
      var daAllowGoingBack = """ + ('true' if allow_going_back else 'false') + """;
      var daSteps = """ + str(steps) + """;
      var daIsUser = """ + is_user + """;
      var daChatStatus = """ + json.dumps(chat_status) + """;
      var daChatAvailable = """ + json.dumps(chat_available) + """;
      var daChatPartnersAvailable = 0;
      var daPhoneAvailable = false;
      var daChatMode = """ + json.dumps(chat_mode) + """;
      var daSendChanges = """ + send_changes + """;
      var daInitialized = false;
      var daNotYetScrolled = true;
      var daBeingControlled = """ + being_controlled + """;
      var daInformedChanged = false;
      var daInformed = """ + json.dumps(user_dict['_internal']['informed'].get(user_id_string, {})) + """;
      var daShowingSpinner = false;
      var daSpinnerTimeout = null;
      var daSubmitter = null;
      var daUsingGA = """ + ("true" if ga_id is not None else 'false') + """;
      var daUsingSegment = """ + ("true" if segment_id is not None else 'false') + """;
      var daDoAction = """ + do_action + """;
      var daQuestionID = """ + json.dumps(question_id_dict) + """;
      var daCsrf = """ + json.dumps(generate_csrf()) + """;
      var daShowIfInProcess = false;
      var daFieldsToSkip = ['_checkboxes', '_empties', '_ml_info', '_back_one', '_files', '_files_inline', '_question_name', '_the_image', '_save_as', '_success', '_datatypes', '_event', '_visible', '_tracker', '_track_location', '_varnames', '_next_action', '_next_action_to_set', 'ajax', 'json', 'informed', 'csrf_token', '_action', '_order_changes', '_collect', '_list_collect_list', '_null_question'];
      var daVarLookup = Object();
      var daVarLookupRev = Object();
      var daVarLookupMulti = Object();
      var daVarLookupRevMulti = Object();
      var daVarLookupSelect = Object();
      var daTargetDiv;
      var daComboBoxes = Object();
      var daGlobalEval = eval;
      var daInterviewUrl = """ + json.dumps(url_for('index', **index_params)) + """;
      var daLocationBar = """ + json.dumps(location_bar) + """;
      var daPostURL = """ + json.dumps(url_for('index', **index_params_external)) + """;
      var daYamlFilename = """ + json.dumps(yaml_filename) + """;
      var daFetchAcceptIncoming = false;
      var daFetchAjaxTimeout = null;
      var daFetchAjaxTimeoutRunning = null;
      var daFetchAjaxTimeoutFetchAfter = null;
      var daShowHideHappened = false;
      if (daJsEmbed){
        daTargetDiv = '#' + daJsEmbed;
      }
      else{
        daTargetDiv = "#dabody";
      }
      var daNotificationContainer = """ + json.dumps(NOTIFICATION_CONTAINER) + """;
      var daNotificationMessage = """ + json.dumps(NOTIFICATION_MESSAGE) + """;
      Object.defineProperty(String.prototype, "daSprintf", {
        value: function () {
          var args = Array.from(arguments),
            i = 0;
          function defaultNumber(iValue) {
            return iValue != undefined && !isNaN(iValue) ? iValue : "0";
          }
          function defaultString(iValue) {
            return iValue == undefined ? "" : "" + iValue;
          }
          return this.replace(
            /%%|%([+\\-])?([^1-9])?(\\d+)?(\\.\\d+)?([deEfhHioQqs])/g,
            function (match, sign, filler, scale, precision, type) {
              var strOut, space, value;
              var asNumber = false;
              if (match == "%%") return "%";
              if (i >= args.length) return match;
              value = args[i];
              while (Array.isArray(value)) {
                args.splice(i, 1);
                for (var j = i; value.length > 0; j++)
                  args.splice(j, 0, value.shift());
                value = args[i];
              }
              i++;
              if (filler == undefined) filler = " "; // default
              if (scale == undefined && !isNaN(filler)) {
                scale = filler;
                filler = " ";
              }
              if (sign == undefined) sign = "sqQ".indexOf(type) >= 0 ? "+" : "-"; // default
              if (scale == undefined) scale = 0; // default
              if (precision == undefined) precision = ".0"; // default
              scale = parseInt(scale);
              precision = parseInt(precision.substr(1));
              switch (type) {
                case "d":
                case "i":
                  // decimal integer
                  asNumber = true;
                  strOut = parseInt(defaultNumber(value));
                  if (precision > 0) strOut += "." + "0".repeat(precision);
                  break;
                case "e":
                case "E":
                  // float in exponential notation
                  asNumber = true;
                  strOut = parseFloat(defaultNumber(value));
                  if (precision == 0) strOut = strOut.toExponential();
                  else strOut = strOut.toExponential(precision);
                  if (type == "E") strOut = strOut.replace("e", "E");
                  break;
                case "f":
                  // decimal float
                  asNumber = true;
                  strOut = parseFloat(defaultNumber(value));
                  if (precision != 0) strOut = strOut.toFixed(precision);
                  break;
                case "o":
                case "h":
                case "H":
                  // Octal or Hexagesimal integer notation
                  strOut =
                    "\\\\" +
                    (type == "o" ? "0" : type) +
                    parseInt(defaultNumber(value)).toString(type == "o" ? 8 : 16);
                  break;
                case "q":
                  // single quoted string
                  strOut = "'" + defaultString(value) + "'";
                  break;
                case "Q":
                  // double quoted string
                  strOut = '"' + defaultString(value) + '"';
                  break;
                default:
                  // string
                  strOut = defaultString(value);
                  break;
              }
              if (typeof strOut != "string") strOut = "" + strOut;
              if ((space = strOut.length) < scale) {
                if (asNumber) {
                  if (sign == "-") {
                    if (strOut.indexOf("-") < 0)
                      strOut = filler.repeat(scale - space) + strOut;
                    else
                      strOut =
                        "-" +
                        filler.repeat(scale - space) +
                        strOut.replace("-", "");
                  } else {
                    if (strOut.indexOf("-") < 0)
                      strOut = "+" + filler.repeat(scale - space - 1) + strOut;
                    else
                      strOut =
                        "-" +
                        filler.repeat(scale - space) +
                        strOut.replace("-", "");
                  }
                } else {
                  if (sign == "-") strOut = filler.repeat(scale - space) + strOut;
                  else strOut = strOut + filler.repeat(scale - space);
                }
              } else if (asNumber && sign == "+" && strOut.indexOf("-") < 0)
                strOut = "+" + strOut;
              return strOut;
            }
          );
        },
      });
      Object.defineProperty(window, "daSprintf", {
        value: function (str, ...rest) {
          if (typeof str == "string")
            return String.prototype.daSprintf.apply(str, rest);
          return "";
        },
      });
      function daGoToAnchor(target){
        if (daJsEmbed){
          scrollTarget = $(target).first().position().top - 60;
        }
        else{
          scrollTarget = $(target).first().offset().top - 60;
        }
        if (scrollTarget != null){
          if (daJsEmbed){
            $(daTargetDiv).animate({
              scrollTop: scrollTarget
            }, 500);
          }
          else{
            $("html, body").animate({
              scrollTop: scrollTarget
            }, 500);
          }
        }
      }
      function dabtoa(str) {
        return window.btoa(str).replace(/[\\n=]/g, '');
      }
      function daatob(str) {
        return window.atob(str);
      }
      function hideTablist() {
        var anyTabs = $("#daChatAvailable").is(":visible")
            || $("daPhoneAvailable").is(":visible")
            || $("#dahelptoggle").is(":visible");
        if (anyTabs) {
          $("#nav-bar-tab-list").removeClass("dainvisible");
          $("#daquestionlabel").parent().removeClass("dainvisible");
        } else {
          $("#nav-bar-tab-list").addClass("dainvisible");
          $("#daquestionlabel").parent().addClass("dainvisible");
        }
      }
      function getFields(){
        var allFields = [];
        for (var rawFieldName in daVarLookup){
          if (daVarLookup.hasOwnProperty(rawFieldName)){
            var fieldName = atob(rawFieldName);
            if (allFields.indexOf(fieldName) == -1){
              allFields.push(fieldName);
            }
          }
        }
        return allFields;
      }
      var daGetFields = getFields;
      function daAppendIfExists(fieldName, theArray){
        var elem = $("[name='" + fieldName + "']");
        if (elem.length > 0){
          for (var i = 0; i < theArray.length; ++i){
            if (theArray[i] == elem[0]){
              return;
            }
          }
          theArray.push(elem[0]);
        }
      }
      function getField(fieldName, notInDiv){
        if (daVarLookupSelect[fieldName]){
          var n = daVarLookupSelect[fieldName].length;
          for (var i = 0; i < n; ++i){
            var elem = daVarLookupSelect[fieldName][i].select;
            if (!$(elem).prop('disabled')){
              var showifParents = $(elem).parents(".dajsshowif,.dashowif");
              if (showifParents.length == 0 || $(showifParents[0]).data("isVisible") == '1'){
                if (notInDiv && $.contains(notInDiv, elem)){
                  continue;
                }
                return elem;
              }
            }
          }
        }
        var fieldNameEscaped = dabtoa(fieldName);
        var possibleElements = [];
        daAppendIfExists(fieldNameEscaped, possibleElements);
        if (daVarLookupMulti.hasOwnProperty(fieldNameEscaped)){
          for (var i = 0; i < daVarLookupMulti[fieldNameEscaped].length; ++i){
            daAppendIfExists(daVarLookupMulti[fieldNameEscaped][i], possibleElements);
          }
        }
        var returnVal = null;
        for (var i = 0; i < possibleElements.length; ++i){
          if (!$(possibleElements[i]).prop('disabled')){
            var showifParents = $(possibleElements[i]).parents(".dajsshowif,.dashowif");
            if (showifParents.length == 0 || $(showifParents[0]).data("isVisible") == '1'){
              if (notInDiv && $.contains(notInDiv, possibleElements[i])){
                continue;
              }
              returnVal = possibleElements[i];
            }
          }
        }
        return returnVal;
      }
      var daGetField = getField;
      function setField(fieldName, val){
        var elem = daGetField(fieldName);
        if (elem == null){
          console.log('setField: reference to non-existent field ' + fieldName);
          return;
        }
        if ($(elem).attr('type') == "checkbox"){
          if (val){
            if ($(elem).prop('checked') != true){
              $(elem).prop('checked', true);
              $(elem).trigger('change');
            }
          }
          else{
            if ($(elem).prop('checked') != false){
              $(elem).prop('checked', false);
              $(elem).trigger('change');
            }
          }
        }
        else if ($(elem).attr('type') == "radio"){
          var fieldNameEscaped = $(elem).attr('name').replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
          var wasSet = false;
          $("input[name='" + fieldNameEscaped + "']").each(function(){
            if ($(this).val() == val){
              if ($(this).prop('checked') != true){
                $(this).prop('checked', true);
                $(this).trigger('change');
              }
              wasSet = true;
              return false;
            }
          });
          if (!wasSet){
            console.log('setField: could not set radio button ' + fieldName + ' to ' + val);
          }
        }
        else{
          if ($(elem).val() != val){
            $(elem).val(val);
            $(elem).trigger('change');
          }
        }
      }
      var daSetField = setField;
      function val(fieldName){
        var elem = daGetField(fieldName);
        if (elem == null){
          return null;
        }
        if ($(elem).attr('type') == "checkbox"){
          if ($(elem).prop('checked')){
            theVal = true;
          }
          else{
            theVal = false;
          }
        }
        else if ($(elem).attr('type') == "radio"){
          var fieldNameEscaped = $(elem).attr('name').replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
          theVal = $("input[name='" + fieldNameEscaped + "']:checked").val();
          if (typeof(theVal) == 'undefined'){
            theVal = null;
          }
          else{
            if (theVal == 'True'){
              theVal = true;
            }
            else if (theVal == 'False'){
              theVal = false;
            }
          }
        }
        else if ($(elem).prop('tagName') == "SELECT" && $(elem).hasClass('damultiselect') && daVarLookupSelect[fieldName]){
          var n = daVarLookupSelect[fieldName].length;
          for (var i = 0; i < n; ++i){
            if (daVarLookupSelect[fieldName][i].select === elem){
              return $(daVarLookupSelect[fieldName][i].option).prop('selected');
            }
          }
        }
        else{
          theVal = $(elem).val();
        }
        return theVal;
      }
      var da_val = val;
      function daFormAsJSON(){
        var formData = $("#daform").serializeArray();
        var data = Object();
        var n = formData.length;
        for (var i = 0; i < n; ++i){
          var key = formData[i]['name'];
          var val = formData[i]['value'];
          if ($.inArray(key, daFieldsToSkip) != -1 || key.indexOf('_ignore') == 0){
            continue;
          }
          if (typeof daVarLookupRev[key] != "undefined"){
            data[atob(daVarLookupRev[key])] = val;
          }
          else{
            data[atob(key)] = val;
          }
        }
        return JSON.stringify(data);
      }
      var daMessageLog = JSON.parse(atob(""" + json.dumps(
            safeid(json.dumps(docassemble.base.functions.get_message_log()))) + """));
      function daPreloadImage(url){
        var img = new Image();
        img.src = url;
      }
      daPreloadImage('""" + str(url_for('static', filename='app/chat.ico', v=da_version)) + """');
      function daShowHelpTab(){
          $('#dahelptoggle').tab('show');
      }
      function addCsrfHeader(xhr, settings){
        if (daJsEmbed && !/^(GET|HEAD|OPTIONS|TRACE)$/i.test(settings.type)){
          xhr.setRequestHeader("X-CSRFToken", daCsrf);
        }
      }
      function flash(message, priority, clear){
        if (priority == null){
          priority = 'info'
        }
        if (!$("#daflash").length){
          $(daTargetDiv).append(daSprintf(daNotificationContainer, ""));
        }
        if (clear){
          $("#daflash").empty();
        }
        if (message != null){
          $("#daflash").append(daSprintf(daNotificationMessage, priority, message));
          if (priority == 'success'){
            setTimeout(function(){
              $("#daflash .alert-success").hide(300, function(){
                $(this).remove();
              });
            }, 3000);
          }
        }
      }
      var da_flash = flash;
      function url_action(action, args){
        if (args == null){
          args = {};
        }
        data = {action: action, arguments: args};
        var url;
        if (daJsEmbed){
          url = daPostURL + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        else{
          if (daLocationBar.indexOf('?') !== -1){
            url = daLocationBar + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
          }
          else {
            url = daLocationBar + "?action=" + encodeURIComponent(btoa(JSON_stringify(data)))
          }
        }
        return url;
      }
      var da_url_action = url_action;
      function action_call(action, args, callback){
        if (args == null){
            args = {};
        }
        if (callback == null){
            callback = function(){};
        }
        var data = {action: action, arguments: args};
        var url;
        if (daJsEmbed){
          url = daPostURL + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        else{
          url = daInterviewUrl + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        return $.ajax({
          type: "GET",
          url: url,
          success: callback,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          }
        });
      }
      var da_action_call = action_call;
      var url_action_call = action_call;
      function action_perform(action, args){
        if (args == null){
            args = {};
        }
        var data = {action: action, arguments: args};
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        return $.ajax({
          type: "POST",
          url: daInterviewUrl,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          data: $.param({_action: btoa(JSON_stringify(data)), csrf_token: daCsrf, ajax: 1}),
          success: function(data){
            setTimeout(function(){
              daProcessAjax(data, $("#daform"), 1);
            }, 0);
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          },
          dataType: 'json'
        });
      }
      var da_action_perform = action_perform;
      var url_action_perform = action_perform;
      function action_perform_with_next(action, args, next_data){
        //console.log("action_perform_with_next: " + action + " | " + next_data)
        if (args == null){
            args = {};
        }
        var data = {action: action, arguments: args};
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        return $.ajax({
          type: "POST",
          url: daInterviewUrl,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          data: $.param({_action: btoa(JSON_stringify(data)), _next_action_to_set: btoa(JSON_stringify(next_data)), csrf_token: daCsrf, ajax: 1}),
          success: function(data){
            setTimeout(function(){
              daProcessAjax(data, $("#daform"), 1);
            }, 0);
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          },
          dataType: 'json'
        });
      }
      var da_action_perform_with_next = action_perform_with_next;
      var url_action_perform_with_next = action_perform_with_next;
      function get_interview_variables(callback){
        if (callback == null){
          callback = function(){};
        }
        return $.ajax({
          type: "GET",
          url: """ + '"' + url_for('get_variables', i=yaml_filename) + '"' + """,
          success: callback,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          }
        });
      }
      var da_get_interview_variables = get_interview_variables;
      function daInformAbout(subject, chatMessage){
        if (subject in daInformed || (subject != 'chatmessage' && !daIsUser)){
          return;
        }
        if (daShowingHelp && subject != 'chatmessage'){
          daInformed[subject] = 1;
          daInformedChanged = true;
          return;
        }
        if (daShowingHelp && subject == 'chatmessage'){
          return;
        }
        var target;
        var message;
        var waitPeriod = 3000;
        if (subject == 'chat'){
          target = "#daChatAvailable a";
          message = """ + json.dumps(word("Get help through live chat by clicking here.")) + """;
        }
        else if (subject == 'chatmessage'){
          target = "#daChatAvailable a";
          //message = """ + json.dumps(word("A chat message has arrived.")) + """;
          message = chatMessage;
        }
        else if (subject == 'phone'){
          target = "#daPhoneAvailable a";
          message = """ + json.dumps(word("Click here to get help over the phone.")) + """;
        }
        else{
          return;
        }
        if (subject != 'chatmessage'){
          daInformed[subject] = 1;
          daInformedChanged = true;
        }
        if (subject == 'chatmessage'){
          $(target).popover({"content": message, "placement": "bottom", "trigger": "manual", "container": "body", "title": """ + json.dumps(
            word("New chat message")) + """});
        }
        else {
          $(target).popover({"content": message, "placement": "bottom", "trigger": "manual", "container": "body", "title": """ + json.dumps(
            word("Live chat is available")) + """});
        }
        $(target).popover('show');
        setTimeout(function(){
          $(target).popover('dispose');
          $(target).removeAttr('title');
        }, waitPeriod);
      }
      // function daCloseSocket(){
      //   if (typeof daSocket !== 'undefined' && daSocket.connected){
      //     //daSocket.emit('terminate');
      //     //io.unwatch();
      //   }
      // }
      function daPublishMessage(data){
        var newDiv = document.createElement('li');
        $(newDiv).addClass("list-group-item");
        if (data.is_self){
          $(newDiv).addClass("list-group-item-primary dalistright");
        }
        else{
          $(newDiv).addClass("list-group-item-secondary dalistleft");
        }
        //var newSpan = document.createElement('span');
        //$(newSpan).html(data.message);
        //$(newSpan).appendTo($(newDiv));
        //var newName = document.createElement('span');
        //$(newName).html(userNameString(data));
        //$(newName).appendTo($(newDiv));
        $(newDiv).html(data.message);
        $("#daCorrespondence").append(newDiv);
      }
      function daScrollChat(){
        var chatScroller = $("#daCorrespondence");
        if (chatScroller.length){
          var height = chatScroller[0].scrollHeight;
          //console.log("Slow scrolling to " + height);
          if (height == 0){
            daNotYetScrolled = true;
            return;
          }
          chatScroller.animate({scrollTop: height}, 800);
        }
        else{
          console.log("daScrollChat: error");
        }
      }
      function daScrollChatFast(){
        var chatScroller = $("#daCorrespondence");
        if (chatScroller.length){
          var height = chatScroller[0].scrollHeight;
          if (height == 0){
            daNotYetScrolled = true;
            return;
          }
          //console.log("Scrolling to " + height + " where there are " + chatScroller[0].childElementCount + " children");
          chatScroller.scrollTop(height);
        }
        else{
          console.log("daScrollChatFast: error");
        }
      }
      function daSender(){
        //console.log("daSender");
        if ($("#daMessage").val().length){
          daSocket.emit('chatmessage', {data: $("#daMessage").val(), i: daYamlFilename});
          $("#daMessage").val("");
          $("#daMessage").focus();
        }
        return false;
      }
      function daShowControl(mode){
        //console.log("You are now being controlled");
        if ($("body").hasClass("dacontrolled")){
          return;
        }
        $('input[type="submit"], button[type="submit"]').prop("disabled", true);
        $("body").addClass("dacontrolled");
        var newDiv = document.createElement('div');
        $(newDiv).addClass("datop-alert col-xs-10 col-sm-7 col-md-6 col-lg-5 dacol-centered");
        $(newDiv).html(""" + json.dumps(word("Your screen is being controlled by an operator.")) + """)
        $(newDiv).attr('id', "dacontrolAlert");
        $(newDiv).css("display", "none");
        $(newDiv).appendTo($(daTargetDiv));
        if (mode == 'animated'){
          $(newDiv).slideDown();
        }
        else{
          $(newDiv).show();
        }
      }
      function daHideControl(){
        //console.log("You are no longer being controlled");
        if (! $("body").hasClass("dacontrolled")){
          return;
        }
        $('input[type="submit"], button[type="submit"]').prop("disabled", false);
        $("body").removeClass("dacontrolled");
        $("#dacontrolAlert").html(""" + json.dumps(word("The operator is no longer controlling your screen.")) + """);
        setTimeout(function(){
          $("#dacontrolAlert").slideUp(300, function(){
            $("#dacontrolAlert").remove();
          });
        }, 2000);
      }
      function daInitializeSocket(){
        if (daSocket != null){
            if (daSocket.connected){
                //console.log("Calling connectagain");
                if (daChatStatus == 'ready'){
                  daSocket.emit('connectagain', {i: daYamlFilename});
                }
                if (daBeingControlled){
                    daShowControl('animated');
                    daSocket.emit('start_being_controlled', {i: daYamlFilename});
                }
            }
            else{
                //console.log('daInitializeSocket: daSocket.connect()');
                daSocket.connect();
            }
            return;
        }
        if (location.protocol === 'http:' || document.location.protocol === 'http:'){
            daSocket = io.connect('http://' + document.domain + '/wsinterview', {path: '""" + ROOT + """ws/socket.io', query: "i=" + daYamlFilename});
        }
        if (location.protocol === 'https:' || document.location.protocol === 'https:'){
            daSocket = io.connect('https://' + document.domain + '/wsinterview', {path: '""" + ROOT + """ws/socket.io', query: "i=" + daYamlFilename});
        }
        //console.log("daInitializeSocket: socket is " + daSocket);
        if (daSocket != null){
            daSocket.on('connect', function() {
                if (daSocket == null){
                    console.log("Error: socket is null");
                    return;
                }
                //console.log("Connected socket with sid " + daSocket.id);
                if (daChatStatus == 'ready'){
                    daChatStatus = 'on';
                    daDisplayChat();
                    daPushChanges();
                    //daTurnOnChat();
                    //console.log("Emitting chat_log from on connect");
                    daSocket.emit('chat_log', {i: daYamlFilename});
                }
                if (daBeingControlled){
                    daShowControl('animated')
                    daSocket.emit('start_being_controlled', {i: daYamlFilename});
                }
            });
            daSocket.on('chat_log', function(arg) {
                //console.log("Got chat_log");
                $("#daCorrespondence").html('');
                daChatHistory = [];
                var messages = arg.data;
                for (var i = 0; i < messages.length; ++i){
                    daChatHistory.push(messages[i]);
                    daPublishMessage(messages[i]);
                }
                daScrollChatFast();
            });
            daSocket.on('chatready', function(data) {
                //var key = 'da:session:uid:' + data.uid + ':i:' + data.i + ':userid:' + data.userid
                //console.log('chatready');
            });
            daSocket.on('terminate', function() {
                //console.log("interview: terminating socket");
                daSocket.disconnect();
            });
            daSocket.on('controllerstart', function(){
              daBeingControlled = true;
              daShowControl('animated');
            });
            daSocket.on('controllerexit', function(){
              daBeingControlled = false;
              //console.log("Hiding control 2");
              daHideControl();
              if (daChatStatus != 'on'){
                if (daSocket != null && daSocket.connected){
                  //console.log('Terminating interview socket because control over');
                  daSocket.emit('terminate');
                }
              }
            });
            daSocket.on('disconnect', function() {
                //console.log("Manual disconnect");
                //daSocket.emit('manual_disconnect', {i: daYamlFilename});
                //console.log("Disconnected socket");
                //daSocket = null;
            });
            daSocket.on('reconnected', function() {
                //console.log("Reconnected");
                daChatStatus = 'on';
                daDisplayChat();
                daPushChanges();
                daTurnOnChat();
                //console.log("Emitting chat_log from reconnected");
                daSocket.emit('chat_log', {i: daYamlFilename});
            });
            daSocket.on('mymessage', function(arg) {
                //console.log("Received " + arg.data);
                $("#daPushResult").html(arg.data);
            });
            daSocket.on('departure', function(arg) {
                //console.log("Departure " + arg.numpartners);
                if (arg.numpartners == 0){
                    daCloseChat();
                }
            });
            daSocket.on('chatmessage', function(arg) {
                //console.log("Received chat message " + arg.data);
                daChatHistory.push(arg.data);
                daPublishMessage(arg.data);
                daScrollChat();
                daInformAbout('chatmessage', arg.data.message);
            });
            daSocket.on('newpage', function(incoming) {
                //console.log("newpage received");
                var data = incoming.obj;
                daProcessAjax(data, $("#daform"), 1);
            });
            daSocket.on('controllerchanges', function(data) {
                //console.log("controllerchanges: " + data.parameters);
                var valArray = Object();
                var values = JSON.parse(data.parameters);
                for (var i = 0; i < values.length; i++) {
                    valArray[values[i].name] = values[i].value;
                }
                //console.log("valArray is " + JSON.stringify(valArray));
                $("#daform").each(function(){
                    $(this).find(':input').each(function(){
                        var type = $(this).attr('type');
                        var id = $(this).attr('id');
                        var name = $(this).attr('name');
                        if (type == 'checkbox'){
                            if (name in valArray){
                                if (valArray[name] == 'True'){
                                    if ($(this).prop('checked') != true){
                                        $(this).prop('checked', true);
                                        $(this).trigger('change');
                                    }
                                }
                                else{
                                    if ($(this).prop('checked') != false){
                                        $(this).prop('checked', false);
                                        $(this).trigger('change');
                                    }
                                }
                            }
                            else{
                                if ($(this).prop('checked') != false){
                                    $(this).prop('checked', false);
                                    $(this).trigger('change');
                                }
                            }
                        }
                        else if (type == 'radio'){
                            if (name in valArray){
                                if (valArray[name] == $(this).val()){
                                    if ($(this).prop('checked') != true){
                                        $(this).prop('checked', true);
                                        $(this).trigger('change');
                                    }
                                }
                                else{
                                    if ($(this).prop('checked') != false){
                                        $(this).prop('checked', false);
                                        $(this).trigger('change');
                                    }
                                }
                            }
                        }
                        else if ($(this).data().hasOwnProperty('sliderMax')){
                            $(this).slider('setValue', parseInt(valArray[name]));
                        }
                        else{
                            if (name in valArray){
                                $(this).val(valArray[name]);
                            }
                        }
                    });
                });
                if (data.clicked){
                    //console.log("Need to click " + data.clicked);
                    $(data.clicked).prop("disabled", false);
                    $(data.clicked).addClass("da-click-selected");
                    if ($(data.clicked).prop("tagName") == 'A' && typeof $(data.clicked).attr('href') != 'undefined' && ($(data.clicked).attr('href').indexOf('javascript') == 0 || $(data.clicked).attr('href').indexOf('#') == 0)){
                      setTimeout(function(){
                        $(data.clicked).removeClass("da-click-selected");
                      }, 2200);
                    }
                    setTimeout(function(){
                      //console.log("Clicking it now");
                      $(data.clicked).click();
                      //console.log("Clicked it.");
                    }, 200);
                }
            });
        }
      }
      var daCheckinSeconds = """ + str(the_checkin_interval) + """;
      var daCheckinInterval = null;
      var daReloader = null;
      var daDisable = null;
      var daChatRoles = """ + json.dumps(user_dict['_internal']['livehelp']['roles']) + """;
      var daChatPartnerRoles = """ + json.dumps(user_dict['_internal']['livehelp']['partner_roles']) + """;
      function daUnfakeHtmlResponse(text){
        text = text.substr(text.indexOf('ABCDABOUNDARYSTARTABC') + 21);
        text = text.substr(0, text.indexOf('ABCDABOUNDARYENDABC')).replace(/\s/g, '');
        text = atob(text);
        return text;
      }
      function daInjectTrim(handler){
        return function (element, event) {
          if (element.tagName === "TEXTAREA" || (element.tagName === "INPUT" && element.type !== "password" && element.type !== "date" && element.type !== "datetime" && element.type !== "file")) {
            setTimeout(function(){
              element.value = $.trim(element.value);
            }, 10);
          }
          return handler.call(this, element, event);
        };
      }
      function daInvalidHandler(form, validator){
        var errors = validator.numberOfInvalids();
        var scrollTarget = null;
        if (errors && $(validator.errorList[0].element).parents('.da-form-group').length > 0) {
          if (daJsEmbed){
            scrollTarget = $(validator.errorList[0].element).parents('.da-form-group').first().position().top - 60;
          }
          else{
            scrollTarget = $(validator.errorList[0].element).parents('.da-form-group').first().offset().top - 60;
          }
        }
        if (scrollTarget != null){
          if (daJsEmbed){
            $(daTargetDiv).animate({
              scrollTop: scrollTarget
            }, 1000);
          }
          else{
            $("html, body").animate({
              scrollTop: scrollTarget
            }, 1000);
          }
        }
      }
      function daValidationHandler(form){
        //form.submit();
        //console.log("daValidationHandler");
        var visibleElements = [];
        var seen = Object();
        $(form).find("input, select, textarea").filter(":not(:disabled)").each(function(){
          //console.log("Considering an element");
          if ($(this).attr('name') && $(this).attr('type') != "hidden" && (($(this).hasClass('da-active-invisible') && $(this).parent().is(":visible")) || $(this).is(":visible"))){
            var theName = $(this).attr('name');
            //console.log("Including an element " + theName);
            if (!seen.hasOwnProperty(theName)){
              visibleElements.push(theName);
              seen[theName] = 1;
            }
          }
        });
        $(form).find("input[name='_visible']").val(btoa(JSON_stringify(visibleElements)));
        $(form).each(function(){
          $(this).find(':input').off('change', daPushChanges);
        });
        $("meta[name=viewport]").attr('content', "width=device-width, minimum-scale=1.0, maximum-scale=1.0, initial-scale=1.0");
        if (daCheckinInterval != null){
          clearInterval(daCheckinInterval);
        }
        daDisable = setTimeout(function(){
          $(form).find('input[type="submit"]').prop("disabled", true);
          $(form).find('button[type="submit"]').prop("disabled", true);
        }, 1);
        if (daWhichButton != null){
          $(".da-field-buttons .btn-da").each(function(){
            if (this != daWhichButton){
              $(this).removeClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """primary """ + current_app.config[
                     'BUTTON_STYLE'] + """info """ + current_app.config['BUTTON_STYLE'] + """warning """ + current_app.config[
                     'BUTTON_STYLE'] + """danger """ + current_app.config['BUTTON_STYLE'] + """secondary");
              $(this).addClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """light");
            }
          });
          if ($(daWhichButton).hasClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """success")){
            $(daWhichButton).removeClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """success");
            $(daWhichButton).addClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """primary");
          }
          else{
            $(daWhichButton).removeClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """primary """ + current_app.config[
                     'BUTTON_STYLE'] + """info """ + current_app.config['BUTTON_STYLE'] + """warning """ + current_app.config[
                     'BUTTON_STYLE'] + """danger """ + current_app.config['BUTTON_STYLE'] + """success """ + current_app.config[
                     'BUTTON_STYLE'] + """light");
            $(daWhichButton).addClass(""" + '"' + current_app.config['BUTTON_STYLE'] + """secondary");
          }
        }
        var tableOrder = {};
        var tableOrderChanges = {};
        $("a.datableup").each(function(){
          var tableName = $(this).data('tablename');
          if (!tableOrder.hasOwnProperty(tableName)){
            tableOrder[tableName] = [];
          }
          tableOrder[tableName].push(parseInt($(this).data('tableitem')));
        });
        var tableChanged = false;
        for (var tableName in tableOrder){
          if (tableOrder.hasOwnProperty(tableName)){
            var n = tableOrder[tableName].length;
            for (var i = 0; i < n; ++i){
              if (i != tableOrder[tableName][i]){
                tableChanged = true;
                if (!tableOrderChanges.hasOwnProperty(tableName)){
                  tableOrderChanges[tableName] = [];
                }
                tableOrderChanges[tableName].push([tableOrder[tableName][i], i])
              }
            }
          }
        }
        if (tableChanged){
          $('<input>').attr({
            type: 'hidden',
            name: '_order_changes',
            value: JSON.stringify(tableOrderChanges)
          }).appendTo($(form));
        }
        var collectToDelete = [];
        $(".dacollectunremove:visible").each(function(){
          collectToDelete.push(parseInt($(this).parent().parent().data('collectnum')));
        });
        var lastOk = parseInt($(".dacollectremove:visible, .dacollectremoveexisting:visible").last().parent().parent().data('collectnum'));
        $(".dacollectremove, .dacollectremoveexisting").each(function(){
          if (parseInt($(this).parent().parent().data('collectnum')) > lastOk){
            collectToDelete.push(parseInt($(this).parent().parent().data('collectnum')));
          }
        });
        if (collectToDelete.length > 0){
          $('<input>').attr({
            type: 'hidden',
            name: '_collect_delete',
            value: JSON.stringify(collectToDelete)
          }).appendTo($(form));
        }
       $("select.damultiselect:not(:disabled)").each(function(){
          var showifParents = $(this).parents(".dajsshowif,.dashowif");
          if (showifParents.length == 0 || $(showifParents[0]).data("isVisible") == '1'){
            $(this).find('option').each(function(){
              $('<input>').attr({
                type: 'hidden',
                name: $(this).val(),
                value: $(this).prop('selected') ? 'True' : 'False'
              }).appendTo($(form));
            });
          }
          $(this).prop('disabled', true);
        });
        daWhichButton = null;
        if (daSubmitter != null){
          $('<input>').attr({
            type: 'hidden',
            name: daSubmitter.name,
            value: daSubmitter.value
          }).appendTo($(form));
        }
        if (daInformedChanged){
          $("<input>").attr({
            type: 'hidden',
            name: 'informed',
            value: Object.keys(daInformed).join(',')
          }).appendTo($(form));
        }
        $('<input>').attr({
          type: 'hidden',
          name: 'ajax',
          value: '1'
        }).appendTo($(form));
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        var do_iframe_upload = false;
        inline_succeeded = false;
        if ($('input[name="_files"]').length){
          var filesToRead = 0;
          var filesRead = 0;
          var newFileList = Array();
          var nullFileList = Array();
          var fileArray = {keys: Array(), values: Object()};
          var file_list = JSON.parse(atob($('input[name="_files"]').val()));
          var inline_file_list = Array();
          var namesWithImages = Object();
          for (var i = 0; i < file_list.length; i++){
            var the_file_input = $('#' + file_list[i].replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\\\$1'))[0];
            var the_max_size = $(the_file_input).data('maximagesize');
            var the_image_type = $(the_file_input).data('imagetype');
            var hasImages = false;
            if (typeof the_max_size != 'undefined' || typeof the_image_type != 'undefined'){
              for (var j = 0; j < the_file_input.files.length; j++){
                var the_file = the_file_input.files[j];
                if (the_file.type.match(/image.*/)){
                  hasImages = true;
                }
              }
            }
            if (hasImages || (daJsEmbed && the_file_input.files.length > 0)){
              for (var j = 0; j < the_file_input.files.length; j++){
                var the_file = the_file_input.files[j];
                filesToRead++;
              }
              inline_file_list.push(file_list[i]);
            }
            else if (the_file_input.files.length > 0){
              newFileList.push(file_list[i]);
            }
            else{
              nullFileList.push(file_list[i]);
            }
            namesWithImages[file_list[i]] = hasImages;
          }
          if (inline_file_list.length > 0){
            var originalFileList = atob($('input[name="_files"]').val())
            if (newFileList.length == 0 && nullFileList.length == 0){
              $('input[name="_files"]').remove();
            }
            else{
              $('input[name="_files"]').val(btoa(JSON_stringify(newFileList.concat(nullFileList))));
            }
            for (var i = 0; i < inline_file_list.length; i++){
              fileArray.keys.push(inline_file_list[i])
              fileArray.values[inline_file_list[i]] = Array()
              var fileInfoList = fileArray.values[inline_file_list[i]];
              var file_input = $('#' + inline_file_list[i].replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\\\$1'))[0];
              var max_size;
              var image_type;
              var image_mime_type;
              var this_has_images = false;
              if (namesWithImages[inline_file_list[i]]){
                this_has_images = true;
                max_size = parseInt($(file_input).data('maximagesize'));
                image_type = $(file_input).data('imagetype');
                image_mime_type = null;
                if (image_type){
                  if (image_type == 'png'){
                    image_mime_type = 'image/png';
                  }
                  else if (image_type == 'bmp'){
                    image_mime_type = 'image/bmp';
                  }
                  else {
                    image_mime_type = 'image/jpeg';
                    image_type = 'jpg';
                  }
                }
              }
              for (var j = 0; j < file_input.files.length; j++){
                var a_file = file_input.files[j];
                var tempFunc = function(the_file, max_size, has_images){
                  var reader = new FileReader();
                  var thisFileInfo = {name: the_file.name, size: the_file.size, type: the_file.type};
                  fileInfoList.push(thisFileInfo);
                  reader.onload = function(readerEvent){
                    if (has_images && the_file.type.match(/image.*/) && !(the_file.type.indexOf('image/svg') == 0)){
                      var convertedName = the_file.name;
                      var convertedType = the_file.type;
                      if (image_type){
                        var pos = the_file.name.lastIndexOf(".");
                        convertedName = the_file.name.substr(0, pos < 0 ? the_file.name.length : pos) + "." + image_type;
                        convertedType = image_mime_type;
                        thisFileInfo.name = convertedName;
                        thisFileInfo.type = convertedType;
                      }
                      var image = new Image();
                      image.onload = function(imageEvent) {
                        var canvas = document.createElement('canvas'),
                          width = image.width,
                          height = image.height;
                        if (width > height) {
                          if (width > max_size) {
                              height *= max_size / width;
                              width = max_size;
                          }
                        }
                        else {
                          if (height > max_size) {
                            width *= max_size / height;
                            height = max_size;
                          }
                        }
                        canvas.width = width;
                        canvas.height = height;
                        canvas.getContext('2d').drawImage(image, 0, 0, width, height);
                        thisFileInfo['content'] = canvas.toDataURL(convertedType);
                        filesRead++;
                        if (filesRead >= filesToRead){
                          daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList);
                        }
                      };
                      image.src = reader.result;
                    }
                    else{
                      thisFileInfo['content'] = reader.result;
                      filesRead++;
                      if (filesRead >= filesToRead){
                        daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList);
                      }
                    }
                  };
                  reader.readAsDataURL(the_file);
                };
                tempFunc(a_file, max_size, this_has_images);
                inline_succeeded = true;
              }
            }
          }
          if (newFileList.length == 0){
            //$('input[name="_files"]').remove();
          }
          else{
            do_iframe_upload = true;
          }
        }
        if (inline_succeeded){
          return(false);
        }
        if (do_iframe_upload){
          $("#dauploadiframe").remove();
          var iframe = $('<iframe name="dauploadiframe" id="dauploadiframe" style="display: none"><\/iframe>');
          $(daTargetDiv).append(iframe);
          $(form).attr("target", "dauploadiframe");
          iframe.bind('load', function(){
            setTimeout(function(){
              try {
                daProcessAjax($.parseJSON(daUnfakeHtmlResponse($("#dauploadiframe").contents().text())), form, 1);
              }
              catch (e){
                try {
                  daProcessAjax($.parseJSON($("#dauploadiframe").contents().text()), form, 1);
                }
                catch (f){
                  daShowErrorScreen(document.getElementById('dauploadiframe').contentWindow.document.body.innerHTML, f);
                }
              }
            }, 0);
          });
          form.submit();
        }
        else{
          $.ajax({
            type: "POST",
            url: daInterviewUrl,
            data: $(form).serialize(),
            beforeSend: addCsrfHeader,
            xhrFields: {
              withCredentials: true
            },
            success: function(data){
              setTimeout(function(){
                daProcessAjax(data, form, 1);
              }, 0);
            },
            error: function(xhr, status, error){
              setTimeout(function(){
                daProcessAjaxError(xhr, status, error);
              }, 0);
            }
          });
        }
        return(false);
      }
      function daSignatureSubmit(event){
        $(this).find("input[name='ajax']").val(1);
        $.ajax({
          type: "POST",
          url: daInterviewUrl,
          data: $(this).serialize(),
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          success: function(data){
            setTimeout(function(){
              daProcessAjax(data, $(this), 1);
            }, 0);
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          }
        });
        event.preventDefault();
        event.stopPropagation();
        return(false);
      }
      function JSON_stringify(s){
         var json = JSON.stringify(s);
         return json.replace(/[\\u007f-\\uffff]/g,
            function(c) {
              return '\\\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4);
            }
         );
      }
      function daResumeUploadSubmission(form, fileArray, inline_file_list, newFileList){
        $('<input>').attr({
          type: 'hidden',
          name: '_files_inline',
          value: btoa(JSON_stringify(fileArray))
        }).appendTo($(form));
        for (var i = 0; i < inline_file_list.length; ++i){
          document.getElementById(inline_file_list[i]).disabled = true;
        }
        if (newFileList.length > 0){
          $("#dauploadiframe").remove();
          var iframe = $('<iframe name="dauploadiframe" id="dauploadiframe" style="display: none"><\/iframe>');
          $(daTargetDiv).append(iframe);
          $(form).attr("target", "dauploadiframe");
          iframe.bind('load', function(){
            setTimeout(function(){
              daProcessAjax($.parseJSON($("#dauploadiframe").contents().text()), form, 1);
            }, 0);
          });
          form.submit();
        }
        else{
          $.ajax({
            type: "POST",
            url: daInterviewUrl,
            data: $(form).serialize(),
            beforeSend: addCsrfHeader,
            xhrFields: {
              withCredentials: true
            },
            success: function(data){
              setTimeout(function(){
                daProcessAjax(data, form, 1);
              }, 0);
            },
            error: function(xhr, status, error){
              setTimeout(function(){
                daProcessAjaxError(xhr, status, error);
              }, 0);
            }
          });
        }
      }
      function daPushChanges(){
        //console.log("daPushChanges");
        if (daCheckinSeconds == 0 || daShowIfInProcess){
          return true;
        }
        if (daCheckinInterval != null){
          clearInterval(daCheckinInterval);
        }
        daCheckin();
        daCheckinInterval = setInterval(daCheckin, daCheckinSeconds);
        return true;
      }
      function daProcessAjaxError(xhr, status, error){
        if (xhr.responseType == undefined || xhr.responseType == '' || xhr.responseType == 'text'){
          var theHtml = xhr.responseText;
          if (theHtml == undefined){
            $(daTargetDiv).html("error");
          }
          else{
            theHtml = theHtml.replace(/<script[^>]*>[^<]*<\/script>/g, '');
            $(daTargetDiv).html(theHtml);
          }
          if (daJsEmbed){
            $(daTargetDiv)[0].scrollTo(0, 1);
          }
          else{
            window.scrollTo(0, 1);
          }
        }
        else {
          console.log("daProcessAjaxError: response was not text");
        }
      }
      function daAddScriptToHead(src){
        var head = document.getElementsByTagName("head")[0];
        var script = document.createElement("script");
        script.type = "text/javascript";
        script.src = src;
        script.async = true;
        script.defer = true;
        head.appendChild(script);
      }
      $(document).on('keydown', function(e){
        if (e.which == 13){
          if (daShowingHelp == 0){
            var tag = $( document.activeElement ).prop("tagName");
            if (tag != "INPUT" && tag != "TEXTAREA" && tag != "A" && tag != "LABEL" && tag != "BUTTON"){
              e.preventDefault();
              e.stopPropagation();
              if ($("#daform .da-field-buttons button").not('.danonsubmit').length == 1){
                $("#daform .da-field-buttons button").not('.danonsubmit').click();
              }
              return false;
            }
          }
          if ($(document.activeElement).hasClass("btn-file")){
            e.preventDefault();
            e.stopPropagation();
            $(document.activeElement).find('input').click();
            return false;
          }
        }
      });
      function daShowErrorScreen(data, error){
        console.log('daShowErrorScreen: ' + error);
        if ("activeElement" in document){
          document.activeElement.blur();
        }
        $(daTargetDiv).html(data);
      }
      function daProcessAjax(data, form, doScroll, actionURL){
        daInformedChanged = false;
        if (daDisable != null){
          clearTimeout(daDisable);
        }
        daCsrf = data.csrf_token;
        if (data.question_data){
          daQuestionData = data.question_data;
        }
        if (data.action == 'body'){""" + forceFullScreen + """
          if ("activeElement" in document){
            document.activeElement.blur();
          }
          $(daTargetDiv).html(data.body);
          var bodyClasses = $(daTargetDiv).parent()[0].className.split(/\s+/);
          var n = bodyClasses.length;
          while (n--){
            if (bodyClasses[n] == 'dabody' || bodyClasses[n] == 'dasignature' || bodyClasses[n].indexOf('question-') == 0){
              $(daTargetDiv).parent().removeClass(bodyClasses[n]);
            }
          }
          $(daTargetDiv).parent().addClass(data.bodyclass);
          $("meta[name=viewport]").attr('content', "width=device-width, initial-scale=1");
          daDoAction = data.do_action;
          //daNextAction = data.next_action;
          daChatAvailable = data.livehelp.availability;
          daChatMode = data.livehelp.mode;
          daChatRoles = data.livehelp.roles;
          daChatPartnerRoles = data.livehelp.partner_roles;
          daSteps = data.steps;
          //console.log("daProcessAjax: pushing " + daSteps);
          if (!daJsEmbed && !daIframeEmbed){
            if (history.state != null && daSteps > history.state.steps){
              history.pushState({steps: daSteps}, data.browser_title + " - page " + daSteps, daLocationBar + """ + json.dumps(
            page_sep) + """ + daSteps);
            }
            else{
              history.replaceState({steps: daSteps}, "", daLocationBar + """ + json.dumps(page_sep) + """ + daSteps);
            }
          }
          daAllowGoingBack = data.allow_going_back;
          daQuestionID = data.id_dict;
          daMessageLog = data.message_log;
          daInitialize(doScroll);
          var tempDiv = document.createElement('div');
          tempDiv.innerHTML = data.extra_scripts;
          var scripts = tempDiv.getElementsByTagName('script');
          for (var i = 0; i < scripts.length; i++){
            //console.log("Found one script");
            if (scripts[i].src != ""){
              //console.log("Added script to head");
              daAddScriptToHead(scripts[i].src);
            }
            else{
              daGlobalEval(scripts[i].innerHTML);
            }
          }
          $(".da-group-has-error").each(function(){
            if ($(this).is(":visible")){
              if (daJsEmbed){
                var scrollToTarget = $(this).position().top - 60;
                setTimeout(function(){
                  $(daTargetDiv).animate({scrollTop: scrollToTarget}, 1000);
                }, 100);
              }
              else{
                var scrollToTarget = $(this).offset().top - 60;
                setTimeout(function(){
                  $(daTargetDiv).parent().parent().animate({scrollTop: scrollToTarget}, 1000);
                }, 100);
              }
              return false;
            }
          });
          for (var i = 0; i < data.extra_css.length; i++){
            $("head").append(data.extra_css[i]);
          }
          document.title = data.browser_title;
          if ($("html").attr("lang") != data.lang){
            $("html").attr("lang", data.lang);
          }
          if (daReloader != null){
            clearTimeout(daReloader);
          }
          if (data.reload_after != null && data.reload_after > 0){
            //daReloader = setTimeout(function(){location.reload();}, data.reload_after);
            daReloader = setTimeout(function(){daRefreshSubmit();}, data.reload_after);
          }
          daUpdateHeight();
        }
        else if (data.action == 'redirect'){
          if (daSpinnerTimeout != null){
            clearTimeout(daSpinnerTimeout);
            daSpinnerTimeout = null;
          }
          if (daShowingSpinner){
            daHideSpinner();
          }
          window.location = data.url;
        }
        else if (data.action == 'refresh'){
          daRefreshSubmit();
        }
        else if (data.action == 'reload'){
          location.reload(true);
        }
        else if (data.action == 'resubmit'){
          if (form == null){
            window.location = actionURL;
          }
          $("input[name='ajax']").remove();
          if (daSubmitter != null){
            var input = $("<input>")
              .attr("type", "hidden")
              .attr("name", daSubmitter.name).val(daSubmitter.value);
            $(form).append($(input));
          }
          form.submit();
        }
      }
      function daEmbeddedJs(e){
        //console.log("using embedded js");
        var data = decodeURIComponent($(this).data('js'));
        daGlobalEval(data);
        e.preventDefault();
        return false;
      }
      function daEmbeddedAction(e){
        if ($(this).hasClass("daremovebutton")){
          if (confirm(""" + json.dumps(word("Are you sure you want to delete this item?")) + """)){
            return true;
          }
          e.preventDefault();
          $(this).blur();
          return false;
        }
        var actionData = decodeURIComponent($(this).data('embaction'));
        var theURL = $(this).attr("href");
        $.ajax({
          type: "POST",
          url: daInterviewUrl,
          data: $.param({_action: actionData, csrf_token: daCsrf, ajax: 1}),
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          success: function(data){
            setTimeout(function(){
              daProcessAjax(data, null, 1, theURL);
            }, 0);
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          },
          dataType: 'json'
        });
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        e.preventDefault();
        return false;
      }
      function daReviewAction(e){
        //action_perform_with_next($(this).data('action'), null, daNextAction);
        var info = $.parseJSON(atob($(this).data('action')));
        da_action_perform(info['action'], info['arguments']);
        e.preventDefault();
        return false;
      }
      function daRingChat(){
        daChatStatus = 'ringing';
        daPushChanges();
      }
      function daTurnOnChat(){
        //console.log("Publishing from daTurnOnChat");
        $("#daChatOnButton").addClass("dainvisible");
        $("#daChatBox").removeClass("dainvisible");
        $("#daCorrespondence").html('');
        for(var i = 0; i < daChatHistory.length; i++){
          daPublishMessage(daChatHistory[i]);
        }
        daScrollChatFast();
        $("#daMessage").prop('disabled', false);
        if (daShowingHelp){
          $("#daMessage").focus();
        }
      }
      function daCloseChat(){
        //console.log('daCloseChat');
        daChatStatus = 'hangup';
        daPushChanges();
        if (daSocket != null && daSocket.connected){
          daSocket.disconnect();
        }
      }
      // function daTurnOffChat(){
      //   $("#daChatOnButton").removeClass("dainvisible");
      //   $("#daChatBox").addClass("dainvisible");
      //   //daCloseSocket();
      //   $("#daMessage").prop('disabled', true);
      //   $("#daSend").unbind();
      //   //daStartCheckingIn();
      // }
      function daDisplayChat(){
        if (daChatStatus == 'off' || daChatStatus == 'observeonly'){
          $("#daChatBox").addClass("dainvisible");
          $("#daChatAvailable").addClass("dainvisible");
          $("#daChatOnButton").addClass("dainvisible");
        }
        else{
          if (daChatStatus == 'waiting'){
            if (daChatPartnersAvailable > 0){
              $("#daChatBox").removeClass("dainvisible");
            }
          }
          else {
            $("#daChatBox").removeClass("dainvisible");
          }
        }
        if (daChatStatus == 'waiting'){
          //console.log("I see waiting")
          if (daChatHistory.length > 0){
            $("#daChatAvailable a i").removeClass("da-chat-active");
            $("#daChatAvailable a i").addClass("da-chat-inactive");
            $("#daChatAvailable").removeClass("dainvisible");
          }
          else{
            $("#daChatAvailable a i").removeClass("da-chat-active");
            $("#daChatAvailable a i").removeClass("da-chat-inactive");
            $("#daChatAvailable").addClass("dainvisible");
          }
          $("#daChatOnButton").addClass("dainvisible");
          $("#daChatOffButton").addClass("dainvisible");
          $("#daMessage").prop('disabled', true);
          $("#daSend").prop('disabled', true);
        }
        if (daChatStatus == 'standby' || daChatStatus == 'ready'){
          //console.log("I see standby")
          $("#daChatAvailable").removeClass("dainvisible");
          $("#daChatAvailable a i").removeClass("da-chat-inactive");
          $("#daChatAvailable a i").addClass("da-chat-active");
          $("#daChatOnButton").removeClass("dainvisible");
          $("#daChatOffButton").addClass("dainvisible");
          $("#daMessage").prop('disabled', true);
          $("#daSend").prop('disabled', true);
          daInformAbout('chat');
        }
        if (daChatStatus == 'on'){
          $("#daChatAvailable").removeClass("dainvisible");
          $("#daChatAvailable a i").removeClass("da-chat-inactive");
          $("#daChatAvailable a i").addClass("da-chat-active");
          $("#daChatOnButton").addClass("dainvisible");
          $("#daChatOffButton").removeClass("dainvisible");
          $("#daMessage").prop('disabled', false);
          if (daShowingHelp){
            $("#daMessage").focus();
          }
          $("#daSend").prop('disabled', false);
          daInformAbout('chat');
        }
        hideTablist();
      }
      function daChatLogCallback(data){
        if (data.action && data.action == 'reload'){
          location.reload(true);
        }
        //console.log("daChatLogCallback: success is " + data.success);
        if (data.success){
          $("#daCorrespondence").html('');
          daChatHistory = [];
          var messages = data.messages;
          for (var i = 0; i < messages.length; ++i){
            daChatHistory.push(messages[i]);
            daPublishMessage(messages[i]);
          }
          daDisplayChat();
          daScrollChatFast();
        }
      }
      function daRefreshSubmit(){
        $.ajax({
          type: "POST",
          url: daInterviewUrl,
          data: 'csrf_token=' + daCsrf + '&ajax=1',
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          success: function(data){
            setTimeout(function(){
              daProcessAjax(data, $("#daform"), 0);
            }, 0);
          },
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          }
        });
      }
      function daResetCheckinCode(){
        daCheckinCode = Math.random();
      }
      function daCheckinCallback(data){
        if (data.action && data.action == 'reload'){
          location.reload(true);
        }
        daCheckingIn = 0;
        //console.log("daCheckinCallback: success is " + data.success);
        if (data.checkin_code != daCheckinCode){
          console.log("Ignoring checkincallback because code is wrong");
          return;
        }
        if (data.success){
          if (data.commands.length > 0){
            for (var i = 0; i < data.commands.length; ++i){
              var command = data.commands[i];
              if (command.extra == 'flash'){
                if (!$("#daflash").length){
                  $(daTargetDiv).append(daSprintf(daNotificationContainer, ""));
                }
                $("#daflash").append(daSprintf(daNotificationMessage, "info", command.value));
                //console.log("command is " + command.value);
              }
              else if (command.extra == 'refresh'){
                daRefreshSubmit();
              }
              else if (command.extra == 'javascript'){
                //console.log("I should eval" + command.value);
                daGlobalEval(command.value);
              }
              else if (command.extra == 'fields'){
                for (var key in command.value){
                  if (command.value.hasOwnProperty(key)){
                    daSetField(key, command.value[key]);
                  }
                }
              }
              else if (command.extra == 'backgroundresponse'){
                var assignments = Array();
                if (command.value.hasOwnProperty('target') && command.value.hasOwnProperty('content')){
                  assignments.push({target: command.value.target, content: command.value.content});
                }
                if (Array.isArray(command.value)){
                  for (i = 0; i < command.value.length; ++i){
                    var possible_assignment = command.value[i];
                    if (possible_assignment.hasOwnProperty('target') && possible_assignment.hasOwnProperty('content')){
                      assignments.push({target: possible_assignment.target, content: possible_assignment.content});
                    }
                  }
                }
                for (i = 0; i < assignments.length; ++i){
                  var assignment = assignments[i];
                  $('.datarget' + assignment.target.replace(/[^A-Za-z0-9\_]/g)).prop('innerHTML', assignment.content);
                }
                //console.log("Triggering daCheckIn");
                $(document).trigger('daCheckIn', [command.action, command.value]);
              }
            }
            // setTimeout(function(){
            //   $("#daflash .daalert-interlocutory").hide(300, function(){
            //     $(self).remove();
            //   });
            // }, 5000);
          }
          oldDaChatStatus = daChatStatus;
          //console.log("daCheckinCallback: from " + daChatStatus + " to " + data.chat_status);
          if (data.phone == null){
            $("#daPhoneMessage").addClass("dainvisible");
            $("#daPhoneMessage p").html('');
            $("#daPhoneAvailable").addClass("dainvisible");
            daPhoneAvailable = false;
          }
          else{
            $("#daPhoneMessage").removeClass("dainvisible");
            $("#daPhoneMessage p").html(data.phone);
            $("#daPhoneAvailable").removeClass("dainvisible");
            daPhoneAvailable = true;
            daInformAbout('phone');
          }
          var statusChanged;
          if (daChatStatus == data.chat_status){
            statusChanged = false;
          }
          else{
            statusChanged = true;
          }
          if (statusChanged){
            daChatStatus = data.chat_status;
            daDisplayChat();
            if (daChatStatus == 'ready'){
              //console.log("calling initialize socket because ready");
              daInitializeSocket();
            }
          }
          daChatPartnersAvailable = 0;
          if (daChatMode == 'peer' || daChatMode == 'peerhelp'){
            daChatPartnersAvailable += data.num_peers;
            if (data.num_peers == 1){
              $("#dapeerMessage").html('<span class="badge bg-info">' + data.num_peers + ' ' + """ + json.dumps(
            word("other user")) + """ + '<\/span>');
            }
            else{
              $("#dapeerMessage").html('<span class="badge bg-info">' + data.num_peers + ' ' + """ + json.dumps(
            word("other users")) + """ + '<\/span>');
            }
            $("#dapeerMessage").removeClass("dainvisible");
          }
          else{
            $("#dapeerMessage").addClass("dainvisible");
          }
          if (daChatMode == 'peerhelp' || daChatMode == 'help'){
            if (data.help_available == 1){
              $("#dapeerHelpMessage").html('<span class="badge bg-primary">' + data.help_available + ' ' + """ + json.dumps(
            word("operator")) + """ + '<\/span>');
            }
            else{
              $("#dapeerHelpMessage").html('<span class="badge bg-primary">' + data.help_available + ' ' + """ + json.dumps(
            word("operators")) + """ + '<\/span>');
            }
            $("#dapeerHelpMessage").removeClass("dainvisible");
          }
          else{
            $("#dapeerHelpMessage").addClass("dainvisible");
          }
          if (daBeingControlled){
            if (!data.observerControl){
              daBeingControlled = false;
              //console.log("Hiding control 1");
              daHideControl();
              if (daChatStatus != 'on'){
                if (daSocket != null && daSocket.connected){
                  //console.log('Terminating interview socket because control is over');
                  daSocket.emit('terminate');
                }
              }
            }
          }
          else{
            if (data.observerControl){
              daBeingControlled = true;
              daInitializeSocket();
            }
          }
        }
        hideTablist();
      }
      function daCheckoutCallback(data){
      }
      function daCheckin(){
        //console.log("daCheckin");
        daCheckingIn += 1;
        //if (daCheckingIn > 1 && !(daCheckingIn % 3)){
        if (daCheckingIn > 1){
          //console.log("daCheckin: request already pending, not re-sending");
          return;
        }
        var datastring;
        if ((daChatStatus != 'off') && $("#daform").length > 0 && !daBeingControlled){ // daChatStatus == 'waiting' || daChatStatus == 'standby' || daChatStatus == 'ringing' || daChatStatus == 'ready' || daChatStatus == 'on' || daChatStatus == 'observeonly'
          if (daDoAction != null){
            datastring = $.param({action: 'checkin', chatstatus: daChatStatus, chatmode: daChatMode, csrf_token: daCsrf, checkinCode: daCheckinCode, parameters: daFormAsJSON(), raw_parameters: JSON.stringify($("#daform").serializeArray()), do_action: daDoAction, ajax: '1'});
          }
          else{
            datastring = $.param({action: 'checkin', chatstatus: daChatStatus, chatmode: daChatMode, csrf_token: daCsrf, checkinCode: daCheckinCode, parameters: daFormAsJSON(), raw_parameters: JSON.stringify($("#daform").serializeArray()), ajax: '1'});
          }
        }
        else{
          if (daDoAction != null){
            datastring = $.param({action: 'checkin', chatstatus: daChatStatus, chatmode: daChatMode, csrf_token: daCsrf, checkinCode: daCheckinCode, do_action: daDoAction, parameters: daFormAsJSON(), ajax: '1'});
          }
          else{
            datastring = $.param({action: 'checkin', chatstatus: daChatStatus, chatmode: daChatMode, csrf_token: daCsrf, checkinCode: daCheckinCode, ajax: '1'});
          }
        }
        //console.log("Doing checkin with " + daChatStatus);
        $.ajax({
          type: 'POST',
          url: """ + "'" + url_for('checkin', i=yaml_filename) + "'" + """,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          data: datastring,
          success: daCheckinCallback,
          dataType: 'json'
        });
        return true;
      }
      function daCheckout(){
        $.ajax({
          type: 'POST',
          url: """ + "'" + url_for('checkout', i=yaml_filename) + "'" + """,
          beforeSend: addCsrfHeader,
          xhrFields: {
            withCredentials: true
          },
          data: 'csrf_token=' + daCsrf + '&ajax=1&action=checkout',
          success: daCheckoutCallback,
          dataType: 'json'
        });
        return true;
      }
      function daStopCheckingIn(){
        daCheckout();
        if (daCheckinInterval != null){
          clearInterval(daCheckinInterval);
        }
      }
      function daShowSpinner(){
        if ($("#daquestion").length > 0){
          $('<div id="daSpinner" class="da-spinner-container da-top-for-navbar"><div class="container"><div class="row"><div class="col text-center"><span class="da-spinner"><i class="fas fa-spinner fa-spin"><\/i><\/span><\/div><\/div><\/div><\/div>').appendTo(daTargetDiv);
        }
        else{
          var newSpan = document.createElement('span');
          var newI = document.createElement('i');
          $(newI).addClass("fas fa-spinner fa-spin");
          $(newI).appendTo(newSpan);
          $(newSpan).attr("id", "daSpinner");
          $(newSpan).addClass("da-sig-spinner da-top-for-navbar");
          $(newSpan).appendTo("#dasigtoppart");
        }
        daShowingSpinner = true;
      }
      function daHideSpinner(){
        $("#daSpinner").remove();
        daShowingSpinner = false;
        daSpinnerTimeout = null;
      }
      function daAdjustInputWidth(e){
        var contents = $(this).val();
        var leftBracket = new RegExp('<', 'g');
        var rightBracket = new RegExp('>', 'g');
        contents = contents.replace(/&/g,'&amp;').replace(leftBracket,'&lt;').replace(rightBracket,'&gt;').replace(/ /g, '&nbsp;');
        $('<span class="dainput-embedded" id="dawidth">').html( contents ).appendTo('#daquestion');
        $("#dawidth").css('min-width', $(this).css('min-width'));
        $("#dawidth").css('background-color', $(daTargetDiv).css('background-color'));
        $("#dawidth").css('color', $(daTargetDiv).css('background-color'));
        $(this).width($('#dawidth').width() + 16);
        setTimeout(function(){
          $("#dawidth").remove();
        }, 0);
      }
      function daShowNotifications(){
        var n = daMessageLog.length;
        for (var i = 0; i < n; i++){
          var message = daMessageLog[i];
          if (message.priority == 'console'){
            console.log(message.message);
          }
          else if (message.priority == 'javascript'){
            daGlobalEval(message.message);
          }
          else if (message.priority == 'success' || message.priority == 'warning' || message.priority == 'danger' || message.priority == 'secondary' || message.priority == 'info' || message.priority == 'secondary' || message.priority == 'dark' || message.priority == 'light' || message.priority == 'primary'){
            da_flash(message.message, message.priority);
          }
          else{
            da_flash(message.message, 'info');
          }
        }
      }
      function daIgnoreAllButTab(event){
        event = event || window.event;
        var code = event.keyCode;
        if (code != 9){
          if (code == 13){
            $(event.target).parents(".file-caption-main").find("input.dafile").click();
          }
          event.preventDefault();
          return false;
        }
      }
      function daDisableIfNotHidden(query, value){
        $(query).each(function(){
          var showIfParent = $(this).parents('.dashowif,.dajsshowif');
          if (!(showIfParent.length && ($(showIfParent[0]).data('isVisible') == '0' || !$(showIfParent[0]).is(":visible")))){
            if ($(this).hasClass('combobox')){
              if (value){
                daComboBoxes[$(this).attr('id')].disable();
              }
              else {
                daComboBoxes[$(this).attr('id')].enable();
              }
            }
            else {
              $(this).prop("disabled", value);
            }
          }
        });
      }
      function daShowIfCompare(theVal, showIfVal){
        if (typeof theVal == 'string' && theVal.match(/^-?\d+\.\d+$/)){
          theVal = parseFloat(theVal);
        }
        else if (typeof theVal == 'string' && theVal.match(/^-?\d+$/)){
          theVal = parseInt(theVal);
        }
        if (typeof showIfVal == 'string' && showIfVal.match(/^-?\d+\.\d+$/)){
          showIfVal = parseFloat(showIfVal);
        }
        else if (typeof showIfVal == 'string' && showIfVal.match(/^-?\d+$/)){
          showIfVal = parseInt(showIfVal);
        }
        if (typeof theVal == 'string' || typeof showIfVal == 'string'){
          if (String(showIfVal) == 'None' && String(theVal) == ''){
            return true;
          }
          return (String(theVal) == String(showIfVal));
        }
        return (theVal == showIfVal);
      }
      function rationalizeListCollect(){
        var finalNum = $(".dacollectextraheader").last().data('collectnum');
        var num = $(".dacollectextraheader:visible").last().data('collectnum');
        if (parseInt(num) < parseInt(finalNum)){
          if ($('div.dacollectextraheader[data-collectnum="' + num + '"]').find(".dacollectadd").hasClass('dainvisible')){
            $('div.dacollectextraheader[data-collectnum="' + (num + 1) + '"]').show('fast');
          }
        }
        var n = parseInt(finalNum);
        var firstNum = parseInt($(".dacollectextraheader").first().data('collectnum'));
        while (n-- > firstNum){
          if ($('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]:visible').length > 0){
            if (!$('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').find(".dacollectadd").hasClass('dainvisible') && $('div.dacollectextraheader[data-collectnum="' + n + '"]').find(".dacollectremove").hasClass('dainvisible')){
              $('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').hide();
            }
          }
        }
        var n = parseInt(finalNum);
        var seenAddAnother = false;
        while (n-- > firstNum){
          if ($('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]:visible').length > 0){
            if (!$('div.dacollectextraheader[data-collectnum="' + (n + 1) + '"]').find(".dacollectadd").hasClass('dainvisible')){
              seenAddAnother = true;
            }
            var current = $('div.dacollectextraheader[data-collectnum="' + n + '"]');
            if (seenAddAnother && !$(current).find(".dacollectadd").hasClass('dainvisible')){
              $(current).find(".dacollectadd").addClass('dainvisible');
              $(current).find(".dacollectunremove").removeClass('dainvisible');
            }
          }
        }
      }
      function daFetchAjax(elem, cb, doShow){
        var wordStart = $(elem).val();
        if (wordStart.length < parseInt(cb.$source.data('trig'))){
          if (cb.shown){
            cb.hide();
          }
          return;
        }
        if (daFetchAjaxTimeout != null && daFetchAjaxTimeoutRunning){
          daFetchAjaxTimeoutFetchAfter = true;
          return;
        }
        if (doShow){
          daFetchAjaxTimeout = setTimeout(function(){
            daFetchAjaxTimeoutRunning = false;
            if (daFetchAjaxTimeoutFetchAfter){
              daFetchAjax(elem, cb, doShow);
              daFetchAjaxTimeoutFetchAfter = false;
            }
          }, 2000);
          daFetchAjaxTimeoutRunning = true;
          daFetchAjaxTimeoutFetchAfter = false;
        }
        da_action_call(cb.$source.data('action'), {wordstart: wordStart}, function(data){
          wordStart = $(elem).val();
          if (typeof data == "object"){
            var upperWordStart = wordStart.toUpperCase()
            cb.$source.empty();
            var emptyItem = $("<option>");
            emptyItem.val("");
            emptyItem.text("");
            cb.$source.append(emptyItem);
            var notYetSelected = true;
            var selectedValue = null;
            if (Array.isArray(data)){
              for (var i = 0; i < data.length; ++i){
                if (Array.isArray(data[i])){
                  if (data[i].length >= 2){
                    var item = $("<option>");
                    if (notYetSelected && ((doShow && data[i][1].toString() == wordStart) || data[i][0].toString() == wordStart)){
                      item.prop('selected', true);
                      notYetSelected = false;
                      selectedValue = data[i][1]
                    }
                    item.text(data[i][1]);
                    item.val(data[i][0]);
                    cb.$source.append(item);
                  }
                  else if (data[i].length == 1){
                    var item = $("<option>");
                    if (notYetSelected && ((doShow && data[i][0].toString() == wordStart) || data[i][0].toString() == wordStart)){
                      item.prop('selected', true);
                      notYetSelected = false;
                      selectedValue = data[i][0]
                    }
                    item.text(data[i][0]);
                    item.val(data[i][0]);
                    cb.$source.append(item);
                  }
                }
                else if (typeof data[i] == "object"){
                  for (var key in data[i]){
                    if (data[i].hasOwnProperty(key)){
                      var item = $("<option>");
                      if (notYetSelected && ((doShow && key.toString() == wordStart) || key.toString() == wordStart)){
                        item.prop('selected', true);
                        notYetSelected = false;
                        selectedValue = data[i][key];
                      }
                      item.text(data[i][key]);
                      item.val(key);
                      cb.$source.append(item);
                    }
                  }
                }
                else{
                  var item = $("<option>");
                  if (notYetSelected && ((doShow && data[i].toString().toUpperCase() == upperWordStart) || data[i].toString() == wordStart)){
                    item.prop('selected', true);
                    notYetSelected = false;
                    selectedValue = data[i];
                  }
                  item.text(data[i]);
                  item.val(data[i]);
                  cb.$source.append(item);
                }
              }
            }
            else if (typeof data == "object"){
              var keyList = Array();
              for (var key in data){
                if (data.hasOwnProperty(key)){
                  keyList.push(key);
                }
              }
              keyList = keyList.sort();
              for (var i = 0; i < keyList.length; ++i){
                var item = $("<option>");
                if (notYetSelected && ((doShow && keyList[i].toString().toUpperCase() == upperWordStart) || keyList[i].toString() == wordStart)){
                  item.prop('selected', true);
                  notYetSelected = false;
                  selectedValue = data[keyList[i]];
                }
                item.text(data[keyList[i]]);
                item.val(keyList[i]);
                cb.$source.append(item);
              }
            }
            if (doShow){
              cb.refresh();
              cb.clearTarget();
              cb.$target.val(cb.$element.val());
              cb.lookup();
            }
            else{
              if (!notYetSelected){
                cb.$element.val(selectedValue);
              }
            }
          }
        });
      }
      function daInitialize(doScroll){
        daResetCheckinCode();
        daComboBoxes = Object();
        if (daSpinnerTimeout != null){
          clearTimeout(daSpinnerTimeout);
          daSpinnerTimeout = null;
        }
        if (daShowingSpinner){
          daHideSpinner();
        }
        daNotYetScrolled = true;
        // $(".dahelptrigger").click(function(e) {
        //   e.preventDefault();
        //   $(this).tab('show');
        // });
        $(".datableup,.databledown").click(function(e){
          e.preventDefault();
          $(this).blur();
          var row = $(this).parents("tr").first();
          if ($(this).is(".datableup")) {
            var prev = row.prev();
            if (prev.length == 0){
              return false;
            }
            row.addClass("datablehighlighted");
            setTimeout(function(){
              row.insertBefore(prev);
            }, 200);
          }
          else {
            var next = row.next();
            if (next.length == 0){
              return false;
            }
            row.addClass("datablehighlighted");
            setTimeout(function(){
              row.insertAfter(row.next());
            }, 200);
          }
          setTimeout(function(){
            row.removeClass("datablehighlighted");
          }, 1000);
          return false;
        });
        $(".dacollectextra").find('input, textarea, select').prop("disabled", true);
        $(".dacollectextra").find('input.combobox').each(function(){
          daComboBoxes[$(this).attr('id')].disable();
        });
        $("#da-extra-collect").on('click', function(){
          $("<input>").attr({
            type: 'hidden',
            name: '_collect',
            value: $(this).val()
          }).appendTo($("#daform"));
          $("#daform").submit();
          event.preventDefault();
          return false;
        });
        $(".dacollectadd").on('click', function(e){
          e.preventDefault();
          if ($("#daform").valid()){
            var num = $(this).parent().parent().data('collectnum');
            $('div[data-collectnum="' + num + '"]').show('fast');
            $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", false);
            $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function(){
               daComboBoxes[$(this).attr('id')].enable();
            });
            $(this).parent().find("button.dacollectremove").removeClass("dainvisible");
            $(this).parent().find("span.dacollectnum").removeClass("dainvisible");
            $(this).addClass("dainvisible");
            $(".da-first-delete").removeClass("dainvisible");
            rationalizeListCollect();
            var elem = $('div[data-collectnum="' + num + '"]').find('input, textarea, select').first();
            if ($(elem).visible()){
              $(elem).focus();
            }
          }
          return false;
        });
        $("#dasigform").on('submit', daSignatureSubmit);
        $(".dacollectremove").on('click', function(e){
          e.preventDefault();
          var num = $(this).parent().parent().data('collectnum');
          $('div[data-collectnum="' + num + '"]:not(.dacollectextraheader, .dacollectheader, .dacollectfirstheader)').hide('fast');
          $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", true);
          $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function(){
            daComboBoxes[$(this).attr('id')].disable();
          });
          $(this).parent().find("button.dacollectadd").removeClass("dainvisible");
          $(this).parent().find("span.dacollectnum").addClass("dainvisible");
          $(this).addClass("dainvisible");
          rationalizeListCollect();
          return false;
        });
        $(".dacollectremoveexisting").on('click', function(e){
          e.preventDefault();
          var num = $(this).parent().parent().data('collectnum');
          $('div[data-collectnum="' + num + '"]:not(.dacollectextraheader, .dacollectheader, .dacollectfirstheader)').hide('fast');
          $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", true);
          $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function(){
            daComboBoxes[$(this).attr('id')].disable();
          });
          $(this).parent().find("button.dacollectunremove").removeClass("dainvisible");
          $(this).parent().find("span.dacollectremoved").removeClass("dainvisible");
          $(this).addClass("dainvisible");
          rationalizeListCollect();
          return false;
        });
        $(".dacollectunremove").on('click', function(e){
          e.preventDefault();
          var num = $(this).parent().parent().data('collectnum');
          $('div[data-collectnum="' + num + '"]').show('fast');
          $('div[data-collectnum="' + num + '"]').find('input, textarea, select').prop("disabled", false);
          $('div[data-collectnum="' + num + '"]').find('input.combobox').each(function(){
            daComboBoxes[$(this).attr('id')].enable();
          });
          $(this).parent().find("button.dacollectremoveexisting").removeClass("dainvisible");
          $(this).parent().find("button.dacollectremove").removeClass("dainvisible");
          $(this).parent().find("span.dacollectnum").removeClass("dainvisible");
          $(this).parent().find("span.dacollectremoved").addClass("dainvisible");
          $(this).addClass("dainvisible");
          rationalizeListCollect();
          return false;
        });
        //$('#daquestionlabel').click(function(e) {
        //  e.preventDefault();
        //  $(this).tab('show');
        //});
        //$('#dapagetitle').click(function(e) {
        //  if ($(this).prop('href') == '#'){
        //    e.preventDefault();
        //    //$('#daquestionlabel').tab('show');
        //  }
        //});
        $('select.damultiselect').each(function(){
          var varname = atob($(this).data('varname'));
          var theSelect = this;
          $(this).find('option').each(function(){
            var theVal = atob($(this).data('valname'));
            var key = varname + '["' + theVal + '"]';
            if (!daVarLookupSelect[key]){
              daVarLookupSelect[key] = [];
            }
            daVarLookupSelect[key].push({'select': theSelect, 'option': this});
            key = varname + "['" + theVal + "']"
            if (!daVarLookupSelect[key]){
              daVarLookupSelect[key] = [];
            }
            daVarLookupSelect[key].push({'select': theSelect, 'option': this});
          });
        })
        $('.dacurrency').each(function(){
          var theVal = $(this).val().toString();
          if (theVal.indexOf('.') >= 0 || theVal.indexOf(',') >= 0){
            var num = parseFloat(theVal);
            var cleanNum = num.toFixed(""" + str(daconfig.get('currency decimal places', 2)) + """);
            $(this).val(cleanNum);
          }
        });
        $('.dacurrency').on('blur', function(){
          var theVal = $(this).val().toString();
          if (theVal.indexOf('.') >= 0 || theVal.indexOf(',') >= 0){
            var num = parseFloat(theVal);
            var cleanNum = num.toFixed(""" + str(daconfig.get('currency decimal places', 2)) + """);
            if (cleanNum != 'NaN') {
              $(this).val(cleanNum);
            }
          }
        });
        // iOS will truncate text in `select` options. Adding an empty optgroup fixes that
        if (navigator.userAgent.match(/(iPad|iPhone|iPod touch);/i)) {
          var selects = document.querySelectorAll("select");
          for (var i = 0; i < selects.length; i++){
            selects[i].appendChild(document.createElement("optgroup"));
          }
        }
        $(".da-to-labelauty").labelauty({ class: "labelauty da-active-invisible dafullwidth" });
        $(".da-to-labelauty-icon").labelauty({ label: false });
        $("button").on('click', function(){
          daWhichButton = this;
          return true;
        });
        $('#dasource').on('shown.bs.collapse', function (e) {
          if (daJsEmbed){
            var scrollTarget = $("#dasource").first().position().top - 60;
            $(daTargetDiv).animate({
              scrollTop: scrollTarget
            }, 1000);
          }
          else{
            var scrollTarget = $("#dasource").first().offset().top - 60;
            $("html, body").animate({
              scrollTop: scrollTarget
            }, 1000);
          }
        });
        $('button[data-bs-target="#dahelp"]').on('shown.bs.tab', function (e) {
          daShowingHelp = 1;
          if (daNotYetScrolled){
            daScrollChatFast();
            daNotYetScrolled = false;
          }""" + debug_readability_help + """
        });
        $('button[data-bs-target="#daquestion"]').on('shown.bs.tab', function (e) {
          daShowingHelp = 0;""" + debug_readability_question + """
        });
        $("input.danota-checkbox").click(function(){
          $(this).parent().find('input.danon-nota-checkbox').each(function(){
            var existing_val = $(this).prop('checked');
            $(this).prop('checked', false);
            if (existing_val != false){
              $(this).trigger('change');
            }
          });
        });
        $("input.danon-nota-checkbox").click(function(){
          $(this).parent().find('input.danota-checkbox').each(function(){
            var existing_val = $(this).prop('checked');
            $(this).prop('checked', false);
            if (existing_val != false){
              $(this).trigger('change');
            }
          });
        });
        $("input.dafile").fileinput({theme: "fas", language: document.documentElement.lang});
        $('select.combobox').combobox();
        $('select.da-ajax-combobox').combobox({clearIfNoMatch: true});
        $('input.da-ajax-combobox').each(function(){
          var cb = daComboBoxes[$(this).attr("id")];
          daFetchAjax(this, cb, false);
          $(this).on('keyup', function(e){
            switch(e.keyCode){
              case 40:
              case 39: // right arrow
              case 38: // up arrow
              case 37: // left arrow
              case 36: // home
              case 35: // end
              case 16: // shift
              case 17: // ctrl
              case 9:  // tab
              case 13: // enter
              case 27: // escape
              case 18: // alt
                return;
            }
            daFetchAjax(this, cb, true);
            daFetchAcceptIncoming = true;
            e.preventDefault();
            return false;
          });
        });
        $("#daemailform").validate({'submitHandler': daValidationHandler, 'rules': {'_attachment_email_address': {'minlength': 1, 'required': true, 'email': true}}, 'messages': {'_attachment_email_address': {'required': """ + json.dumps(
            word("An e-mail address is required.")) + """, 'email': """ + json.dumps(
            word("You need to enter a complete e-mail address.")) + """}}, 'errorClass': 'da-has-error invalid-feedback'});
        $("a[data-embaction]").click(daEmbeddedAction);
        $("a[data-js]").click(daEmbeddedJs);
        $("a.da-review-action").click(daReviewAction);
        $("input.dainput-embedded").on('keyup', daAdjustInputWidth);
        $("input.dainput-embedded").each(daAdjustInputWidth);
        var daPopoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        var daPopoverList = daPopoverTriggerList.map(function (daPopoverTriggerEl) {
          return new bootstrap.Popover(daPopoverTriggerEl, {trigger: """ + json.dumps(
            interview.options.get('popover trigger', 'focus')) + """, html: true});
        });
        $('label a[data-bs-toggle="popover"]').on('click', function(event){
          event.preventDefault();
          event.stopPropagation();
          var thePopover = bootstrap.Popover.getOrCreateInstance(this);
          thePopover.show();
          return false;
        });
        if (daPhoneAvailable){
          $("#daPhoneAvailable").removeClass("dainvisible");
        }
        $(".daquestionbackbutton").on('click', function(event){
          event.preventDefault();
          $("#dabackbutton").submit();
          return false;
        });
        $("#dabackbutton").on('submit', function(event){
          if (daShowingHelp){
            event.preventDefault();
            $('#daquestionlabel').tab('show');
            return false;
          }
          $("#dabackbutton").addClass("dabackiconpressed");
          var informed = '';
          if (daInformedChanged){
            informed = '&informed=' + Object.keys(daInformed).join(',');
          }
          var url;
          if (daJsEmbed){
            url = daPostURL;
          }
          else{
            url = $("#dabackbutton").attr('action');
          }
          $.ajax({
            type: "POST",
            url: url,
            beforeSend: addCsrfHeader,
            xhrFields: {
              withCredentials: true
            },
            data: $("#dabackbutton").serialize() + '&ajax=1' + informed,
            success: function(data){
              setTimeout(function(){
                daProcessAjax(data, document.getElementById('backbutton'), 1);
              }, 0);
            },
            error: function(xhr, status, error){
              setTimeout(function(){
                daProcessAjaxError(xhr, status, error);
              }, 0);
            }
          });
          daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
          event.preventDefault();
        });
        $("#daChatOnButton").click(daRingChat);
        $("#daChatOffButton").click(daCloseChat);
        $('#daMessage').bind('keypress keydown keyup', function(e){
          var theCode = e.which || e.keyCode;
          if(theCode == 13) { daSender(); e.preventDefault(); }
        });
        $('#daform button[type="submit"]').click(function(){
          daSubmitter = this;
          document.activeElement.blur();
          return true;
        });
        $('#daform input[type="submit"]').click(function(){
          daSubmitter = this;
          document.activeElement.blur();
          return true;
        });
        $('#daemailform button[type="submit"]').click(function(){
          daSubmitter = this;
          return true;
        });
        $('#dadownloadform button[type="submit"]').click(function(){
          daSubmitter = this;
          return true;
        });
        $(".danavlinks a.daclickable").click(function(e){
          var the_key = $(this).data('key');
          da_action_perform("_da_priority_action", {_action: the_key});
          e.preventDefault();
          return false;
        });
        $(".danav-vertical .danavnested").each(function(){
          var box = this;
          var prev = $(this).prev();
          if (prev && !prev.hasClass('active')){
            var toggler;
            if ($(box).hasClass('danotshowing')){
              toggler = $('<a href="#" class="toggler" role="button" aria-pressed="false">');
              $('<i class="fas fa-caret-right">').appendTo(toggler);
            }
            else{
              toggler = $('<a href="#" class="toggler" role="button" aria-pressed="true">');
              $('<i class="fas fa-caret-down">').appendTo(toggler);
            }
            toggler.appendTo(prev);
            toggler.on('click', function(e){
              var oThis = this;
              $(this).find("svg").each(function(){
                if ($(this).attr('data-icon') == 'caret-down'){
                  $(this).removeClass('fa-caret-down');
                  $(this).addClass('fa-caret-right');
                  $(this).attr('data-icon', 'caret-right');
                  $(box).hide();
                  $(oThis).attr('aria-pressed', 'false');
                  $(box).toggleClass('danotshowing');
                }
                else if ($(this).attr('data-icon') == 'caret-right'){
                  $(this).removeClass('fa-caret-right');
                  $(this).addClass('fa-caret-down');
                  $(this).attr('data-icon', 'caret-down');
                  $(box).show();
                  $(oThis).attr('aria-pressed', 'true');
                  $(box).toggleClass('danotshowing');
                }
              });
              e.stopPropagation();
              e.preventDefault();
              return false;
            });
          }
        });
        $("body").focus();
        if (!daJsEmbed){
          setTimeout(function(){
            var firstInput = $("#daform .da-field-container").not(".da-field-container-note").first().find("input, textarea, select").filter(":visible").first();
            if (firstInput.length > 0 && $(firstInput).visible()){
              $(firstInput).focus();
              var inputType = $(firstInput).attr('type');
              if ($(firstInput).prop('tagName') != 'SELECT' && inputType != "checkbox" && inputType != "radio" && inputType != "hidden" && inputType != "submit" && inputType != "file" && inputType != "range" && inputType != "number" && inputType != "date" && inputType != "time"){
                var strLength = $(firstInput).val().length * 2;
                if (strLength > 0){
                  try {
                    $(firstInput)[0].setSelectionRange(strLength, strLength);
                  }
                  catch(err) {
                    console.log(err.message);
                  }
                }
              }
            }
            else {
              var firstButton = $("#danavbar-collapse .nav-link").filter(':visible').first();
              if (firstButton.length > 0 && $(firstButton).visible()){
                setTimeout(function(){
                  $(firstButton).focus();
                  $(firstButton).blur();
                }, 0);
              }
            }
          }, 15);
        }
        $(".dauncheckspecificothers").on('change', function(){
          if ($(this).is(":checked")){
            var theIds = $.parseJSON(atob($(this).data('unchecklist')));
            var n = theIds.length;
            for (var i = 0; i < n; ++i){
              var elem = document.getElementById(theIds[i]);
              $(elem).prop("checked", false);
              $(elem).trigger('change');
            }
          }
        });
        $(".dauncheckspecificothers").each(function(){
          var theIds = $.parseJSON(atob($(this).data('unchecklist')));
          var n = theIds.length;
          var oThis = this;
          for (var i = 0; i < n; ++i){
            var elem = document.getElementById(theIds[i]);
            $(elem).on('change', function(){
              if ($(this).is(":checked")){
                $(oThis).prop("checked", false);
                $(oThis).trigger('change');
              }
            });
          }
        });
        $(".dauncheckothers").on('change', function(){
          if ($(this).is(":checked")){
            $(".dauncheckable").prop("checked", false);
            $(".dauncheckable").trigger('change');
          }
        });
        $(".dauncheckable").on('change', function(){
          if ($(this).is(":checked")){
            $(".dauncheckothers").prop("checked", false);
            $(".dauncheckothers").trigger('change');
          }
        });
        var navMain = $("#danavbar-collapse");
        navMain.on("click", "a", null, function () {
          if (!($(this).hasClass("dropdown-toggle"))){
            navMain.collapse('hide');
          }
        });
        $("button[data-bs-target='#dahelp']").on("shown.bs.tab", function(){
          if (daJsEmbed){
            $(daTargetDiv)[0].scrollTo(0, 1);
          }
          else{
            window.scrollTo(0, 1);
          }
          $("#dahelptoggle").removeClass('daactivetext');
          $("#dahelptoggle").blur();
        });
        $("#dasourcetoggle").on("click", function(){
          $(this).parent().toggleClass("active");
          $(this).blur();
        });
        $('#dabackToQuestion').click(function(event){
          $('#daquestionlabel').tab('show');
        });
        daVarLookup = Object();
        daVarLookupRev = Object();
        daVarLookupMulti = Object();
        daVarLookupRevMulti = Object();
        if ($("input[name='_varnames']").length){
          the_hash = $.parseJSON(atob($("input[name='_varnames']").val()));
          for (var key in the_hash){
            if (the_hash.hasOwnProperty(key)){
              daVarLookup[the_hash[key]] = key;
              daVarLookupRev[key] = the_hash[key];
              if (!daVarLookupMulti.hasOwnProperty(the_hash[key])){
                daVarLookupMulti[the_hash[key]] = [];
              }
              daVarLookupMulti[the_hash[key]].push(key);
              if (!daVarLookupRevMulti.hasOwnProperty(key)){
                daVarLookupRevMulti[key] = [];
              }
              daVarLookupRevMulti[key].push(the_hash[key]);
            }
          }
        }
        if ($("input[name='_checkboxes']").length){
          var patt = new RegExp(/\[B['"][^\]]*['"]\]$/);
          var pattRaw = new RegExp(/\[R['"][^\]]*['"]\]$/);
          the_hash = $.parseJSON(atob($("input[name='_checkboxes']").val()));
          for (var key in the_hash){
            if (the_hash.hasOwnProperty(key)){
              var checkboxName = atob(key);
              var baseName = checkboxName;
              if (patt.test(baseName)){
                bracketPart = checkboxName.replace(/^.*(\[B?['"][^\]]*['"]\])$/, "$1");
                checkboxName = checkboxName.replace(/^.*\[B?['"]([^\]]*)['"]\]$/, "$1");
                baseName = baseName.replace(/^(.*)\[.*/, "$1");
                var transBaseName = baseName;
                if (($("[name='" + key + "']").length == 0) && (typeof daVarLookup[btoa(transBaseName).replace(/[\\n=]/g, '')] != "undefined")){
                  transBaseName = atob(daVarLookup[btoa(transBaseName).replace(/[\\n=]/g, '')]);
                }
                var convertedName;
                try {
                  convertedName = atob(checkboxName);
                }
                catch (e) {
                  continue;
                }
                var daNameOne = btoa(transBaseName + bracketPart).replace(/[\\n=]/g, '');
                var daNameTwo = btoa(baseName + "['" + convertedName + "']").replace(/[\\n=]/g, '');
                var daNameThree = btoa(baseName + '["' + convertedName + '"]').replace(/[\\n=]/g, '');
                daVarLookupRev[daNameOne] = daNameTwo;
                daVarLookup[daNameTwo] = daNameOne;
                daVarLookup[daNameThree] = daNameOne;
                if (!daVarLookupRevMulti.hasOwnProperty(daNameOne)){
                  daVarLookupRevMulti[daNameOne] = [];
                }
                daVarLookupRevMulti[daNameOne].push(daNameTwo);
                if (!daVarLookupMulti.hasOwnProperty(daNameTwo)){
                  daVarLookupMulti[daNameTwo] = [];
                }
                daVarLookupMulti[daNameTwo].push(daNameOne);
                if (!daVarLookupMulti.hasOwnProperty(daNameThree)){
                  daVarLookupMulti[daNameThree] = [];
                }
                daVarLookupMulti[daNameThree].push(daNameOne);
              }
              else if (pattRaw.test(baseName)){
                bracketPart = checkboxName.replace(/^.*(\[R?['"][^\]]*['"]\])$/, "$1");
                checkboxName = checkboxName.replace(/^.*\[R?['"]([^\]]*)['"]\]$/, "$1");
                baseName = baseName.replace(/^(.*)\[.*/, "$1");
                var transBaseName = baseName;
                if (($("[name='" + key + "']").length == 0) && (typeof daVarLookup[btoa(transBaseName).replace(/[\\n=]/g, '')] != "undefined")){
                  transBaseName = atob(daVarLookup[btoa(transBaseName).replace(/[\\n=]/g, '')]);
                }
                var convertedName;
                try {
                  convertedName = atob(checkboxName);
                }
                catch (e) {
                  continue;
                }
                var daNameOne = btoa(transBaseName + bracketPart).replace(/[\\n=]/g, '');
                var daNameTwo = btoa(baseName + "[" + convertedName + "]").replace(/[\\n=]/g, '')
                daVarLookupRev[daNameOne] = daNameTwo;
                daVarLookup[daNameTwo] = daNameOne;
                if (!daVarLookupRevMulti.hasOwnProperty(daNameOne)){
                  daVarLookupRevMulti[daNameOne] = [];
                }
                daVarLookupRevMulti[daNameOne].push(daNameTwo);
                if (!daVarLookupMulti.hasOwnProperty(daNameTwo)){
                  daVarLookupMulti[daNameTwo] = [];
                }
                daVarLookupMulti[daNameTwo].push(daNameOne);
              }
            }
          }
        }
        daShowIfInProcess = true;
        var daTriggerQueries = [];
        function daOnlyUnique(value, index, self){
          return self.indexOf(value) === index;
        }
        $(".dajsshowif").each(function(){
          var showIfDiv = this;
          var jsInfo = JSON.parse(atob($(this).data('jsshowif')));
          var showIfSign = jsInfo['sign'];
          var showIfMode = jsInfo['mode'];
          var jsExpression = jsInfo['expression'];
          var n = jsInfo['vars'].length;
          for (var i = 0; i < n; ++i){
            var showIfVars = [];
            var initShowIfVar = btoa(jsInfo['vars'][i]).replace(/[\\n=]/g, '');
            var initShowIfVarEscaped = initShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
            var elem = $("[name='" + initShowIfVarEscaped + "']");
            if (elem.length > 0){
              showIfVars.push(initShowIfVar);
            }
            if (daVarLookupMulti.hasOwnProperty(initShowIfVar)){
              for (var j = 0; j < daVarLookupMulti[initShowIfVar].length; j++){
                var altShowIfVar = daVarLookupMulti[initShowIfVar][j];
                var altShowIfVarEscaped = altShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
                var altElem = $("[name='" + altShowIfVarEscaped + "']");
                if (altElem.length > 0 && !$.contains(this, altElem[0])){
                  showIfVars.push(altShowIfVar);
                }
              }
            }
            if (showIfVars.length == 0){
              console.log("ERROR: reference to non-existent field " + jsInfo['vars'][i]);
            }
            for (var j = 0; j < showIfVars.length; ++j){
              var showIfVar = showIfVars[j];
              var showIfVarEscaped = showIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
              var showHideDiv = function(speed){
                var elem = daGetField(jsInfo['vars'][i]);
                if (elem != null && !$(elem).parents('.da-form-group').first().is($(this).parents('.da-form-group').first())){
                  return;
                }
                var resultt = eval(jsExpression);
                if(resultt){
                  if (showIfSign){
                    if ($(showIfDiv).data('isVisible') != '1'){
                      daShowHideHappened = true;
                    }
                    if (showIfMode == 0){
                      $(showIfDiv).show(speed);
                    }
                    $(showIfDiv).data('isVisible', '1');
                    $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].enable();
                    });
                  }
                  else{
                    if ($(showIfDiv).data('isVisible') != '0'){
                      daShowHideHappened = true;
                    }
                    if (showIfMode == 0){
                      $(showIfDiv).hide(speed);
                    }
                    $(showIfDiv).data('isVisible', '0');
                    $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].disable();
                    });
                  }
                }
                else{
                  if (showIfSign){
                    if ($(showIfDiv).data('isVisible') != '0'){
                      daShowHideHappened = true;
                    }
                    if (showIfMode == 0){
                      $(showIfDiv).hide(speed);
                    }
                    $(showIfDiv).data('isVisible', '0');
                    $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].disable();
                    });
                  }
                  else{
                    if ($(showIfDiv).data('isVisible') != '1'){
                      daShowHideHappened = true;
                    }
                    if (showIfMode == 0){
                      $(showIfDiv).show(speed);
                    }
                    $(showIfDiv).data('isVisible', '1');
                    $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].enable();
                    });
                  }
                }
                var daThis = this;
                if (!daShowIfInProcess){
                  daShowIfInProcess = true;
                  $(":input").not("[type='file']").each(function(){
                    if (this != daThis){
                      $(this).trigger('change');
                    }
                  });
                  daShowIfInProcess = false;
                }
              };
              var showHideDivImmediate = function(){
                showHideDiv.apply(this, [null]);
              }
              var showHideDivFast = function(){
                showHideDiv.apply(this, ['fast']);
              }
              daTriggerQueries.push("#" + showIfVarEscaped);
              daTriggerQueries.push("input[type='radio'][name='" + showIfVarEscaped + "']");
              daTriggerQueries.push("input[type='checkbox'][name='" + showIfVarEscaped + "']");
              $("#" + showIfVarEscaped).change(showHideDivFast);
              $("input[type='radio'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
              $("input[type='checkbox'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
              $("#" + showIfVarEscaped).on('daManualTrigger', showHideDivImmediate);
              $("input[type='radio'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
              $("input[type='checkbox'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
            }
          }
        });
        $(".dashowif").each(function(){
          var showIfVars = [];
          var showIfSign = $(this).data('showif-sign');
          var showIfMode = parseInt($(this).data('showif-mode'));
          var initShowIfVar = $(this).data('showif-var');
          var varName = atob(initShowIfVar);
          var initShowIfVarEscaped = initShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
          var elem = $("[name='" + initShowIfVarEscaped + "']");
          if (elem.length > 0){
            showIfVars.push(initShowIfVar);
          }
          if (daVarLookupMulti.hasOwnProperty(initShowIfVar)){
            var n = daVarLookupMulti[initShowIfVar].length;
            for (var i = 0; i < n; i++){
              var altShowIfVar = daVarLookupMulti[initShowIfVar][i];
              var altShowIfVarEscaped = altShowIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
              var altElem = $("[name='" + altShowIfVarEscaped + "']");
              if (altElem.length > 0 && !$.contains(this, altElem[0])){
                showIfVars.push(altShowIfVar);
              }
            }
          }
          var showIfVal = $(this).data('showif-val');
          var saveAs = $(this).data('saveas');
          var showIfDiv = this;
          var n = showIfVars.length;
          for (var i = 0; i < n; ++i){
            var showIfVar = showIfVars[i];
            var showIfVarEscaped = showIfVar.replace(/(:|\.|\[|\]|,|=)/g, "\\\\$1");
            var showHideDiv = function(speed){
              var elem = daGetField(varName, showIfDiv);
              if (elem != null && !$(elem).parents('.da-form-group').first().is($(this).parents('.da-form-group').first())){
                return;
              }
              var theVal;
              var showifParents = $(this).parents(".dashowif");
              if (showifParents.length !== 0 && !($(showifParents[0]).data("isVisible") == '1')){
                theVal = '';
                //console.log("Setting theVal to blank.");
              }
              else if ($(this).attr('type') == "checkbox"){
                theVal = $("input[name='" + showIfVarEscaped + "']:checked").val();
                if (typeof(theVal) == 'undefined'){
                  //console.log('manually setting checkbox value to False');
                  theVal = 'False';
                }
              }
              else if ($(this).attr('type') == "radio"){
                theVal = $("input[name='" + showIfVarEscaped + "']:checked").val();
                if (typeof(theVal) == 'undefined'){
                  theVal = '';
                }
                else if (theVal != '' && $("input[name='" + showIfVarEscaped + "']:checked").hasClass("daobject")){
                  try{
                    theVal = atob(theVal);
                  }
                  catch(e){
                  }
                }
              }
              else{
                theVal = $(this).val();
                if (theVal != '' && $(this).hasClass("daobject")){
                  try{
                    theVal = atob(theVal);
                  }
                  catch(e){
                  }
                }
              }
              //console.log("this is " + $(this).attr('id') + " and saveAs is " + atob(saveAs) + " and showIfVar is " + atob(showIfVar) + " and val is " + String(theVal) + " and showIfVal is " + String(showIfVal));
              if(daShowIfCompare(theVal, showIfVal)){
                if (showIfSign){
                  if ($(showIfDiv).data('isVisible') != '1'){
                    daShowHideHappened = true;
                  }
                  if (showIfMode == 0){
                    $(showIfDiv).show(speed);
                  }
                  $(showIfDiv).data('isVisible', '1');
                  var firstChild = $(showIfDiv).children()[0];
                  if (!$(firstChild).hasClass('dacollectextra') || $(firstChild).is(":visible")){
                    $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].enable();
                    });
                  }
                }
                else{
                  if ($(showIfDiv).data('isVisible') != '0'){
                    daShowHideHappened = true;
                  }
                  if (showIfMode == 0){
                    $(showIfDiv).hide(speed);
                  }
                  $(showIfDiv).data('isVisible', '0');
                  $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                  $(showIfDiv).find('input.combobox').each(function(){
                    daComboBoxes[$(this).attr('id')].disable();
                  });
                }
              }
              else{
                if (showIfSign){
                  if ($(showIfDiv).data('isVisible') != '0'){
                    daShowHideHappened = true;
                  }
                  if (showIfMode == 0){
                    $(showIfDiv).hide(speed);
                  }
                  $(showIfDiv).data('isVisible', '0');
                  $(showIfDiv).find('input, textarea, select').prop("disabled", true);
                  $(showIfDiv).find('input.combobox').each(function(){
                    daComboBoxes[$(this).attr('id')].disable();
                  });
                }
                else{
                  if ($(showIfDiv).data('isVisible') != '1'){
                    daShowHideHappened = true;
                  }
                  if (showIfMode == 0){
                    $(showIfDiv).show(speed);
                  }
                  $(showIfDiv).data('isVisible', '1');
                  var firstChild = $(showIfDiv).children()[0];
                  if (!$(firstChild).hasClass('dacollectextra') || $(firstChild).is(":visible")){
                    $(showIfDiv).find('input, textarea, select').prop("disabled", false);
                    $(showIfDiv).find('input.combobox').each(function(){
                      daComboBoxes[$(this).attr('id')].enable();
                    });
                  }
                }
              }
              var daThis = this;
              if (!daShowIfInProcess){
                daShowIfInProcess = true;
                $(":input").not("[type='file']").each(function(){
                  if (this != daThis){
                    $(this).trigger('change');
                  }
                });
                daShowIfInProcess = false;
              }
            };
            var showHideDivImmediate = function(){
              showHideDiv.apply(this, [null]);
            }
            var showHideDivFast = function(){
              showHideDiv.apply(this, ['fast']);
            }
            daTriggerQueries.push("#" + showIfVarEscaped);
            daTriggerQueries.push("input[type='radio'][name='" + showIfVarEscaped + "']");
            daTriggerQueries.push("input[type='checkbox'][name='" + showIfVarEscaped + "']");
            $("#" + showIfVarEscaped).change(showHideDivFast);
            $("#" + showIfVarEscaped).on('daManualTrigger', showHideDivImmediate);
            $("input[type='radio'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
            $("input[type='radio'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
            $("input[type='checkbox'][name='" + showIfVarEscaped + "']").change(showHideDivFast);
            $("input[type='checkbox'][name='" + showIfVarEscaped + "']").on('daManualTrigger', showHideDivImmediate);
          }
        });
        function daTriggerAllShowHides(){
          var daUniqueTriggerQueries = daTriggerQueries.filter(daOnlyUnique);
          var daFirstTime = true;
          var daTries = 0;
          while ((daFirstTime || daShowHideHappened) && ++daTries < 100){
            daShowHideHappened = false;
            daFirstTime = false;
            var n = daUniqueTriggerQueries.length;
            for (var i = 0; i < n; ++i){
              $(daUniqueTriggerQueries[i]).trigger('daManualTrigger');
            }
          }
          if (daTries >= 100){
            console.log("Too many contradictory 'show if' conditions");
          }
        }
        if (daTriggerQueries.length > 0){
          daTriggerAllShowHides();
        }
        $(".danavlink").last().addClass('thelast');
        $(".danavlink").each(function(){
          if ($(this).hasClass('btn') && !$(this).hasClass('danotavailableyet')){
            var the_a = $(this);
            var the_delay = 1000 + 250 * parseInt($(this).data('index'));
            setTimeout(function(){
              $(the_a).removeClass('""" + current_app.config['BUTTON_STYLE'] + """secondary');
              if ($(the_a).hasClass('active')){
                $(the_a).addClass('""" + current_app.config['BUTTON_STYLE'] + """success');
              }
              else{
                $(the_a).addClass('""" + current_app.config['BUTTON_STYLE'] + """warning');
              }
            }, the_delay);
          }
        });
        daShowIfInProcess = false;
        $("#daSend").click(daSender);
        if (daChatAvailable == 'unavailable'){
          daChatStatus = 'off';
        }
        if (daChatAvailable == 'observeonly'){
          daChatStatus = 'observeonly';
        }
        if ((daChatStatus == 'off' || daChatStatus == 'observeonly') && daChatAvailable == 'available'){
          daChatStatus = 'waiting';
        }
        daDisplayChat();
        if (daBeingControlled){
          daShowControl('fast');
        }
        if (daChatStatus == 'ready' || daBeingControlled){
          daInitializeSocket();
        }
        if (daInitialized == false && daCheckinSeconds > 0){ // why was this set to always retrieve the chat log?
          setTimeout(function(){
            //console.log("daInitialize call to chat_log in checkin");
            $.ajax({
              type: 'POST',
              url: """ + "'" + url_for('checkin', i=yaml_filename) + "'" + """,
              beforeSend: addCsrfHeader,
              xhrFields: {
                withCredentials: true
              },
              data: $.param({action: 'chat_log', ajax: '1', csrf_token: daCsrf}),
              success: daChatLogCallback,
              dataType: 'json'
            });
          }, 200);
        }
        if (daInitialized == true){
          //console.log("Publishing from memory");
          $("#daCorrespondence").html('');
          for(var i = 0; i < daChatHistory.length; i++){
            daPublishMessage(daChatHistory[i]);
          }
        }
        if (daChatStatus != 'off'){
          daSendChanges = true;
        }
        else{
          if (daDoAction == null){
            daSendChanges = false;
          }
          else{
            daSendChanges = true;
          }
        }
        if (daSendChanges){
          $("#daform").each(function(){
            $(this).find(':input').change(daPushChanges);
          });
        }
        daInitialized = true;
        daShowingHelp = 0;
        daSubmitter = null;
        setTimeout(function(){
          $("#daflash .alert-success").hide(300, function(){
            $(self).remove();
          });
        }, 3000);
        if (doScroll){
          setTimeout(function () {
            if (daJsEmbed){
              $(daTargetDiv)[0].scrollTo(0, 1);
              if (daSteps > 1){
                $(daTargetDiv)[0].scrollIntoView();
              }
            }
            else{
              window.scrollTo(0, 1);
            }
          }, 20);
        }
        if (daShowingSpinner){
          daHideSpinner();
        }
        if (daCheckinInterval != null){
          clearInterval(daCheckinInterval);
        }
        if (daCheckinSeconds > 0){
          setTimeout(daCheckin, 100);
          daCheckinInterval = setInterval(daCheckin, daCheckinSeconds);
        }
        daShowNotifications();
        if (daUsingGA){
          daPageview();
        }
        if (daUsingSegment){
          daSegmentEvent();
        }
        hideTablist();
        $(document).trigger('daPageLoad');
      }
      $(document).ready(function(){
        daInitialize(1);
        //console.log("ready: replaceState " + daSteps);
        if (!daJsEmbed && !daIframeEmbed){
          history.replaceState({steps: daSteps}, "", daLocationBar + """ + json.dumps(page_sep) + """ + daSteps);
        }
        var daReloadAfter = """ + str(int(reload_after)) + """;
        if (daReloadAfter > 0){
          daReloader = setTimeout(function(){daRefreshSubmit();}, daReloadAfter);
        }
        window.onpopstate = function(event) {
          if (event.state != null && event.state.steps < daSteps && daAllowGoingBack){
            $("#dabackbutton").submit();
          }
        };
        $( window ).bind('unload', function() {
          daStopCheckingIn();
          if (daSocket != null && daSocket.connected){
            //console.log('Terminating interview socket because window unloaded');
            daSocket.emit('terminate');
          }
        });
        var daDefaultAllowList = bootstrap.Tooltip.Default.allowList;
        daDefaultAllowList['*'].push('style');
        daDefaultAllowList['a'].push('style');
        daDefaultAllowList['img'].push('style');
        if (daJsEmbed){
          $.ajax({
            type: "POST",
            url: daPostURL,
            beforeSend: addCsrfHeader,
            xhrFields: {
              withCredentials: true
            },
            data: 'csrf_token=' + daCsrf + '&ajax=1',
            success: function(data){
              setTimeout(function(){
                daProcessAjax(data, $("#daform"), 0);
              }, 0);
            },
            error: function(xhr, status, error){
              setTimeout(function(){
                daProcessAjaxError(xhr, status, error);
              }, 0);
            }
          });
        }
      });
      $(window).ready(daUpdateHeight);
      $(window).resize(daUpdateHeight);
      function daUpdateHeight(){
        $(".dagoogleMap").each(function(){
          var size = $( this ).width();
          $( this ).css('height', size);
        });
      }
      $.validator.setDefaults({
        highlight: function(element) {
            $(element).closest('.da-form-group').addClass('da-group-has-error');
            $(element).addClass('is-invalid');
        },
        unhighlight: function(element) {
            $(element).closest('.da-form-group').removeClass('da-group-has-error');
            $(element).removeClass('is-invalid');
        },
        errorElement: 'span',
        errorClass: 'da-has-error invalid-feedback',
        errorPlacement: function(error, element) {
            $(error).addClass('invalid-feedback');
            var elementName = $(element).attr("name");
            var lastInGroup = $.map(daValidationRules['groups'], function(thefields, thename){
              var fieldsArr;
              if (thefields.indexOf(elementName) >= 0) {
                fieldsArr = thefields.split(" ");
                return fieldsArr[fieldsArr.length - 1];
              }
              else {
                return null;
              }
            })[0];
            if (element.hasClass('dainput-embedded')){
              error.insertAfter(element);
            }
            else if (element.hasClass('dafile-embedded')){
              error.insertAfter(element);
            }
            else if (element.hasClass('daradio-embedded')){
              element.parent().append(error);
            }
            else if (element.hasClass('dacheckbox-embedded')){
              element.parent().append(error);
            }
            else if (element.hasClass('dauncheckable') && lastInGroup){
              $("input[name='" + lastInGroup + "']").parent().append(error);
            }
            else if (element.parent().hasClass('combobox-container')){
              error.insertAfter(element.parent());
            }
            else if (element.hasClass('dafile')){
              var fileContainer = $(element).parents(".file-input").first();
              if (fileContainer.length > 0){
                $(fileContainer).append(error);
              }
              else{
                error.insertAfter(element.parent());
              }
            }
            else if (element.parent('.input-group').length) {
              error.insertAfter(element.parent());
            }
            else if (element.hasClass('da-active-invisible')){
              var choice_with_help = $(element).parents(".dachoicewithhelp").first();
              if (choice_with_help.length > 0){
                $(choice_with_help).parent().append(error);
              }
              else{
                element.parent().append(error);
              }
            }
            else if (element.hasClass('danon-nota-checkbox')){
              element.parent().append(error);
            }
            else {
              error.insertAfter(element);
            }
        }
      });
      $.validator.addMethod("datetime", function(a, b){
        return true;
      });
      $.validator.addMethod("ajaxrequired", function(value, element, params){
        var realElement = $("#" + $(element).attr('name') + "combobox");
        var realValue = $(realElement).val();
        if (!$(realElement).parent().is(":visible")){
          return true;
        }
        if (realValue == null || realValue.replace(/\s/g, '') == ''){
          return false;
        }
        return true;
      });
      $.validator.addMethod('checkone', function(value, element, params){
        var number_needed = params[0];
        var css_query = params[1];
        if ($(css_query).length >= number_needed){
          return true;
        }
        else{
          return false;
        }
      });
      $.validator.addMethod('checkatleast', function(value, element, params){
        if ($(element).attr('name') != '_ignore' + params[0]){
          return true;
        }
        if ($('.dafield' + params[0] + ':checked').length >= params[1]){
          return true;
        }
        else{
          return false;
        }
      });
      $.validator.addMethod('checkatmost', function(value, element, params){
        if ($(element).attr('name') != '_ignore' + params[0]){
          return true;
        }
        if ($('.dafield' + params[0] + ':checked').length > params[1]){
          return false;
        }
        else{
          return true;
        }
      });
      $.validator.addMethod('checkexactly', function(value, element, params){
        if ($(element).attr('name') != '_ignore' + params[0]){
          return true;
        }
        if ($('.dafield' + params[0] + ':checked').length != params[1]){
          return false;
        }
        else{
          return true;
        }
      });
      $.validator.addMethod('selectexactly', function(value, element, params){
        if ($(element).find('option:selected').length == params[0]){
          return true;
        }
        else {
          return false;
        }
      });
      $.validator.addMethod('mindate', function(value, element, params){
        if (value == null || value == ''){
          return true;
        }
        try {
          var date = new Date(value);
          var comparator = new Date(params);
          if (date >= comparator) {
            return true;
          }
        } catch (e) {}
        return false;
      });
      $.validator.addMethod('maxdate', function(value, element, params){
        if (value == null || value == ''){
          return true;
        }
        try {
          var date = new Date(value);
          var comparator = new Date(params);
          if (date <= comparator) {
            return true;
          }
        } catch (e) {}
        return false;
      });
      $.validator.addMethod('minmaxdate', function(value, element, params){
        if (value == null || value == ''){
          return true;
        }
        try {
          var date = new Date(value);
          var before_comparator = new Date(params[0]);
          var after_comparator = new Date(params[1]);
          if (date >= before_comparator && date <= after_comparator) {
            return true;
          }
        } catch (e) {}
        return false;
      });
      $.validator.addMethod('maxuploadsize', function(value, element, param){
        try {
          var limit = parseInt(param) - 2000;
          if (limit <= 0){
            return true;
          }
          var maxImageSize;
          if ($(element).data('maximagesize')){
             maxImageSize = (parseInt($(element).data('maximagesize')) * parseInt($(element).data('maximagesize'))) * 2;
          }
          else {
             maxImageSize = 0;
          }
          if ($(element).attr("type") === "file"){
            if (element.files && element.files.length) {
              var totalSize = 0;
              for ( i = 0; i < element.files.length; i++ ) {
                if (maxImageSize > 0 && element.files[i].size > (0.20 * maxImageSize) && element.files[i].type.match(/image.*/) && !(element.files[i].type.indexOf('image/svg') == 0)){
                  totalSize += maxImageSize;
                }
                else {
                  totalSize += element.files[i].size;
                }
              }
              if (totalSize > limit){
                return false;
              }
            }
            return true;
          }
        } catch (e) {}
        return false;
      });"""
        for custom_type in interview.custom_data_types:
            info = docassemble.base.functions.custom_types[custom_type]
            if isinstance(info['javascript'], str):
                the_js += "\n      try {\n" + indent_by(info['javascript'].strip(),
                                                        8).rstrip() + "\n      }\n      catch {\n        console.log('Error with JavaScript code of CustomDataType " + \
                          info['class'].__name__ + "');\n      }"
        if interview.options.get('send question data', False):
            the_js += "\n      daQuestionData = " + json.dumps(interview_status.as_data(user_dict))
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
                interview_status.screen_reader_links[question_type].append([url_for('speak_file', i=yaml_filename,
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
    content = as_html(interview_status, debug_mode, url_for('index', **index_params), validation_rules,
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
        start_output += global_css + additional_css(interview_status)
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
        end_output = scripts + global_js + "\n" + indent_by("".join(interview_status.extra_scripts).strip(),
                                                            4).rstrip() + "\n  </div>\n  </body>\n</html>"
    key = 'da:html:uid:' + str(user_code) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
    pipe = r.pipeline()
    pipe.set(key, json.dumps(dict(body=output, extra_scripts=interview_status.extra_scripts, global_css=global_css,
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
            sys.stderr.write("Redirecting because of a redirect action.\n")
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
