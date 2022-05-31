import ast
import codecs
import copy
import datetime
import hashlib
import json
import logging
import math
import mimetypes
import operator
import os
import pickle
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid
import xml.etree.ElementTree as ET
import zipfile
from urllib.parse import unquote as urllibunquote

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
import googleapiclient.discovery
import httplib2
import humanize
import pandas
import ruamel.yaml
import twilio.twiml
import twilio.twiml.messaging_response
import twilio.twiml.voice_response
import werkzeug.exceptions
import werkzeug.utils
import xlsxwriter
import yaml
from PIL import Image
from backports import zoneinfo
from bs4 import BeautifulSoup
from celery import chord
from dateutil import tz
from docassemble.base.config import daconfig, hostname, in_celery
from docassemble.base.error import DAError, DAErrorMissingVariable
from docassemble.base.functions import ReturnValue, get_default_timezone, word
from docassemble.base.generate_key import random_alphanumeric, random_lower_string, random_string
from docassemble.base.logger import logmessage, the_logger
from docassemble.base.pandoc import convertible_extensions, convertible_mimetypes, word_to_markdown
from docassemble.base.standardformatter import as_sms, get_choices_with_abb
from docassemble.base.util import DADict, DAEmail, DAEmailRecipient, DAEmailRecipientList, DAFile, DAFileCollection, \
    DAFileList, DAStaticFile
from docassemble.webapp.app_object import app, csrf, flaskbabel
from docassemble.webapp.authentication import backup_session, current_info, decrypt_session, encrypt_session, \
    fix_secret, get_next_link, get_sms_session, get_unique_name, get_user_object, initiate_sms_session, load_user, \
    login_or_register, needs_to_change_password, restore_session, save_user_dict, terminate_sms_session, \
    update_last_login, user_id_dict, user_interviews
from docassemble.webapp.backend import Message, cloud, da_send_mail, decrypt_dictionary, decrypt_phrase, \
    encrypt_dictionary, fetch_previous_user_dict, fetch_user_dict, file_privilege_access, file_set_attributes, \
    file_user_access, get_chat_log, get_info_from_file_number, get_info_from_file_number_with_uids, \
    get_info_from_file_reference, get_new_file_number, get_session, get_session_uids, is_package_ml, project_name, \
    reset_user_dict, save_numbered_file, unpack_phrase, update_session, url_for
from docassemble.webapp.config_server import CHECKIN_INTERVAL, COOKIELESS_SESSIONS, DEBUG, DEFAULT_LANGUAGE, \
    ERROR_TYPES_NO_EMAIL, FULL_PACKAGE_DIRECTORY, LOGFILE, LOGSERVER, LOG_DIRECTORY, PAGINATION_LIMIT, \
    PAGINATION_LIMIT_PLUS_ONE, PDFTOPPM_COMMAND, PERMISSIONS_LIST, PNG_RESOLUTION, PNG_SCREEN_RESOLUTION, ROOT, \
    START_TIME, SUPERVISORCTL, UPLOAD_DIRECTORY, USING_SUPERVISOR, WEBAPP_PATH, amp_match, base_words, clicksend_config, \
    default_yaml_filename, fax_provider, final_default_yaml_filename, gt_match, keymap, lt_match, \
    main_page_parts, noquote_match, telnyx_config, twilio_config, version_warning
from docassemble.webapp.core.models import Email, EmailAttachment, MachineLearning, Shortener, Supervisors, Uploads
from docassemble.webapp.daredis import r, r_user
from docassemble.webapp.db_object import db
from docassemble.webapp.develop import ConfigForm, TrainingForm, TrainingUploadForm, Utilities
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.fixpickle import fix_pickle_obj
from docassemble.webapp.global_values import initialize
from docassemble.webapp.jsonstore import delete_answer_json, read_answer_json, variables_snapshot_connection, \
    write_answer_json
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.package import get_master_branch, get_package_info, get_package_name_from_zip, \
    get_url_from_file_reference, install_git_package, install_pip_package, install_zip_package, uninstall_package, \
    user_can_edit_package
from docassemble.webapp.packages.models import Package
from docassemble.webapp.page_values import navigation_bar
from docassemble.webapp.blueprints.playground import playground
from docassemble.webapp.blueprints.account import account
from docassemble.webapp.blueprints.admin import admin
from docassemble.webapp.blueprints.auth import auth
from docassemble.webapp.blueprints.files import files, html_index
from docassemble.webapp.blueprints.google_drive import google_drive
from docassemble.webapp.blueprints.index import index, indexBp
from docassemble.webapp.blueprints.interview import interview, interview_menu
from docassemble.webapp.blueprints.mfa import mfa
from docassemble.webapp.blueprints.office import office
from docassemble.webapp.blueprints.one_drive import one_drive
from docassemble.webapp.blueprints.util import util
from docassemble.webapp.setup import da_version
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.user_util import api_verify, create_new_interview, get_question_data, go_back_in_session, \
    set_session_variables
from docassemble.webapp.users.forms import RequestDeveloperForm
from docassemble.webapp.users.models import ChatLog, Role, TempUser, UserModel, UserRoles
from docassemble.webapp.util import MD5Hash, RedisCredStorage, add_user_privilege, create_user, from_safeid, \
    get_current_project, get_history, get_part, get_privileges_list, get_referer, get_requester_ip, get_user_info, \
    get_vars_in_use, illegal_variable_name, jsonify_restart_task, jsonify_with_status, make_user_inactive, myb64unquote, \
    pad_to_16, process_file, remove_user_privilege, restart_all, safeid, secure_filename, secure_filename_spaces_ok, \
    set_user_info, should_run_create, sub_indices, summarize_results, transform_json_variables, true_or_false
from docassemble_flask_user import login_required, roles_required, user_changed_password, user_logged_in, \
    user_registered
from flask import Markup, Response, current_app, flash, g, jsonify, make_response, redirect, render_template, request, \
    send_file, session
from flask_cors import cross_origin
from flask_login import current_user
from flask_wtf.csrf import CSRFError
from jinja2.exceptions import TemplateError
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import YamlLexer
from sqlalchemy import and_, delete, select
from twilio.rest import Client as TwilioRestClient

if not in_celery:
    import docassemble.webapp.worker

request_active = True

def set_request_active(value):
    global request_active
    request_active = value


def syslog_message(message):
    global request_active
    message = re.sub(r'\n', ' ', message)
    if current_user and current_user.is_authenticated and not current_user.is_anonymous:
        the_user = current_user.email
    else:
        the_user = "anonymous"
    if request_active:
        try:
            sys_logger.debug('%s', LOGFORMAT % {'message': message, 'clientip': get_requester_ip(request),
                                                'yamlfile': docassemble.base.functions.this_thread.current_info.get(
                                                    'yaml_filename', 'na'), 'user': the_user,
                                                'session': docassemble.base.functions.this_thread.current_info.get(
                                                    'session', 'na')})
        except Exception as err:
            sys.stderr.write("Error writing log message " + str(message) + "\n")
            try:
                sys.stderr.write("Error was " + err.__class__.__name__ + ": " + str(err) + "\n")
            except:
                pass
    else:
        try:
            sys_logger.debug('%s',
                             LOGFORMAT % {'message': message, 'clientip': 'localhost', 'yamlfile': 'na', 'user': 'na',
                                          'session': 'na'})
        except Exception as err:
            sys.stderr.write("Error writing log message " + str(message) + "\n")
            try:
                sys.stderr.write("Error was " + err.__class__.__name__ + ": " + str(err) + "\n")
            except:
                pass


def syslog_message_with_timestamp(message):
    syslog_message(time.strftime("%Y-%m-%d %H:%M:%S") + " " + message)


def chat_partners_available(session_id, yaml_filename, the_user_id, mode, partner_roles):
    key = 'da:session:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
    peer_ok = bool(mode in ('peer', 'peerhelp'))
    help_ok = bool(mode in ('help', 'peerhelp'))
    potential_partners = set()
    if help_ok and len(partner_roles) and not r.exists(
            'da:block:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)):
        chat_session_key = 'da:interviewsession:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(
            the_user_id)
        for role in partner_roles:
            for the_key in r.keys('da:monitor:role:' + role + ':userid:*'):
                user_id = re.sub(r'^.*:userid:', '', the_key.decode())
                potential_partners.add(user_id)
        for the_key in r.keys('da:monitor:chatpartners:*'):
            the_key = the_key.decode()
            user_id = re.sub(r'^.*chatpartners:', '', the_key)
            if user_id not in potential_partners:
                for chat_key in r.hgetall(the_key):
                    if chat_key.decode() == chat_session_key:
                        potential_partners.add(user_id)
    num_peer = 0
    if peer_ok:
        for sess_key in r.keys('da:session:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:*'):
            if sess_key.decode() != key:
                num_peer += 1
    result = ChatPartners()
    result.peer = num_peer
    result.help = len(potential_partners)
    return result


def noquote(string):
    if string is None:
        return string
    string = amp_match.sub('&amp;', string)
    string = noquote_match.sub('&quot;', string)
    string = lt_match.sub('&lt;', string)
    string = gt_match.sub('&gt;', string)
    return string


def ocr_google_in_background(image_file, raw_result, user_code):
    return docassemble.webapp.worker.ocr_google.delay(image_file, raw_result, user_code)


def make_png_for_pdf(doc, prefix, page=None):
    if prefix == 'page':
        resolution = PNG_RESOLUTION
    else:
        resolution = PNG_SCREEN_RESOLUTION
    session_id = docassemble.base.functions.get_uid()
    task = docassemble.webapp.worker.make_png_for_pdf.delay(doc, prefix, resolution, session_id, PDFTOPPM_COMMAND,
                                                            page=page)
    return task.id


def fg_make_png_for_pdf(doc, prefix, page=None):
    if prefix == 'page':
        resolution = PNG_RESOLUTION
    else:
        resolution = PNG_SCREEN_RESOLUTION
    docassemble.base.util.make_png_for_pdf(doc, prefix, resolution, PDFTOPPM_COMMAND, page=page)


def fg_make_png_for_pdf_path(path, prefix, page=None):
    if prefix == 'page':
        resolution = PNG_RESOLUTION
    else:
        resolution = PNG_SCREEN_RESOLUTION
    docassemble.base.util.make_png_for_pdf_path(path, prefix, resolution, PDFTOPPM_COMMAND, page=page)


def fg_make_pdf_for_word_path(path, extension):
    success = docassemble.base.pandoc.word_to_pdf(path, extension, path + ".pdf")
    if not success:
        raise DAError(
            "fg_make_pdf_for_word_path: unable to make PDF from " + path + " using extension " + extension + " and writing to " + path + ".pdf")


def task_ready(task_id):
    result = docassemble.webapp.worker.workerapp.AsyncResult(id=task_id)
    if result.ready():
        return True
    return False


def wait_for_task(task_id, timeout=None):
    if timeout is None:
        timeout = 3
    try:
        result = docassemble.webapp.worker.workerapp.AsyncResult(id=task_id)
        if result.ready():
            return True
        result.get(timeout=timeout)
        return True
    except docassemble.webapp.worker.TimeoutError:
        logmessage("wait_for_task: timed out")
        return False
    except Exception as the_error:
        logmessage("wait_for_task: got error: " + str(the_error))
        return False


def trigger_update(except_for=None):
    sys.stderr.write("trigger_update: except_for is " + str(except_for) + " and hostname is " + hostname + "\n")
    if USING_SUPERVISOR:
        to_delete = set()
        for host in db.session.execute(select(Supervisors)).scalars():
            if host.url and not (except_for and host.hostname == except_for):
                if host.hostname == hostname:
                    the_url = 'http://localhost:9001'
                    sys.stderr.write("trigger_update: using http://localhost:9001\n")
                else:
                    the_url = host.url
                args = [SUPERVISORCTL, '-s', the_url, 'start', 'update']
                result = subprocess.run(args, check=False).returncode
                if result == 0:
                    sys.stderr.write(
                        "trigger_update: sent update to " + str(host.hostname) + " using " + the_url + "\n")
                else:
                    sys.stderr.write(
                        "trigger_update: call to supervisorctl on " + str(host.hostname) + " was not successful\n")
                    to_delete.add(host.id)
        for id_to_delete in to_delete:
            db.session.execute(delete(Supervisors).filter_by(id=id_to_delete))
            db.session.commit()


def html_escape(text):
    text = re.sub('&', '&amp;', text)
    text = re.sub('<', '&lt;', text)
    text = re.sub('>', '&gt;', text)
    return text


@flaskbabel.localeselector
def get_locale():
    translations = [str(translation) for translation in flaskbabel.list_translations()]
    return request.accept_languages.best_match(translations)


app.register_blueprint(account)
app.register_blueprint(admin)
app.register_blueprint(auth)
app.register_blueprint(files)
app.register_blueprint(google_drive)
app.register_blueprint(indexBp)
app.register_blueprint(interview)
app.register_blueprint(mfa)
app.register_blueprint(office)
app.register_blueprint(one_drive)
app.register_blueprint(playground)
app.register_blueprint(util)


class ChatPartners:
    pass


def get_current_chat_log(yaml_filename, session_id, secret, utc=True, timezone=None):
    if timezone is None:
        timezone = get_default_timezone()
    timezone = zoneinfo.ZoneInfo(timezone)
    output = []
    if yaml_filename is None or session_id is None:
        return output
    user_cache = {}
    for record in db.session.execute(
            select(ChatLog).where(and_(ChatLog.filename == yaml_filename, ChatLog.key == session_id)).order_by(
                ChatLog.id)).scalars():
        if record.encrypted:
            try:
                message = decrypt_phrase(record.message, secret)
            except:
                sys.stderr.write("get_current_chat_log: Could not decrypt phrase with secret " + secret + "\n")
                continue
        else:
            message = unpack_phrase(record.message)
        if record.temp_user_id:
            user_first_name = None
            user_last_name = None
            user_email = None
        elif record.user_id in user_cache:
            user_first_name = user_cache[record.user_id].first_name
            user_last_name = user_cache[record.user_id].last_name
            user_email = user_cache[record.user_id].email
        else:
            new_user = get_user_object(record.user_id)
            if new_user is None:
                sys.stderr.write("get_current_chat_log: Invalid user ID in chat log\n")
                continue
            user_cache[record.user_id] = new_user
            user_first_name = user_cache[record.user_id].first_name
            user_last_name = user_cache[record.user_id].last_name
            user_email = user_cache[record.user_id].email
        if utc:
            the_datetime = record.modtime.replace(tzinfo=tz.tzutc())
        else:
            the_datetime = record.modtime.replace(tzinfo=tz.tzutc()).astimezone(timezone)
        output.append(
            dict(message=message, datetime=the_datetime, user_email=user_email, user_first_name=user_first_name,
                 user_last_name=user_last_name))
    return output


def jsonify_with_cache(*pargs, **kwargs):
    response = jsonify(*pargs, **kwargs)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@app.route("/checkin", methods=['POST', 'GET'])
def checkin():
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        return jsonify_with_cache(success=False)
    session_info = get_session(yaml_filename)
    if session_info is None:
        return jsonify_with_cache(success=False)
    session_id = session_info['uid']
    if 'visitor_secret' in request.cookies:
        secret = request.cookies['visitor_secret']
    else:
        secret = request.cookies.get('secret', None)
    if secret is not None:
        secret = str(secret)
    if current_user.is_anonymous:
        if 'tempuser' not in session:
            return jsonify_with_cache(success=False)
        the_user_id = 't' + str(session['tempuser'])
        auth_user_id = None
        temp_user_id = int(session['tempuser'])
    else:
        auth_user_id = current_user.id
        the_user_id = current_user.id
        temp_user_id = None
    the_current_info = current_info(yaml=yaml_filename, req=request, action=None, session_info=session_info,
                                    secret=secret, device_id=request.cookies.get('ds', None))
    docassemble.base.functions.this_thread.current_info = the_current_info
    if request.form.get('action', None) == 'chat_log':
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
        if user_dict is None or user_dict['_internal']['livehelp']['availability'] != 'available':
            return jsonify_with_cache(success=False)
        the_current_info['encrypted'] == is_encrypted
        messages = get_chat_log(user_dict['_internal']['livehelp']['mode'], yaml_filename, session_id, auth_user_id,
                                temp_user_id, secret, auth_user_id, temp_user_id)
        return jsonify_with_cache(success=True, messages=messages)
    if request.form.get('action', None) == 'checkin':
        commands = []
        checkin_code = request.form.get('checkinCode', None)
        do_action = request.form.get('do_action', None)
        if do_action is not None:
            parameters = {}
            form_parameters = request.form.get('parameters', None)
            if form_parameters is not None:
                parameters = json.loads(form_parameters)
            obtain_lock(session_id, yaml_filename)
            steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
            the_current_info['encrypted'] == is_encrypted
            interview = docassemble.base.interview_cache.get_interview(yaml_filename)
            interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
            interview_status.checkin = True
            interview.assemble(user_dict, interview_status=interview_status)
            interview_status.current_info.update(dict(action=do_action, arguments=parameters))
            interview.assemble(user_dict, interview_status=interview_status)
            if interview_status.question.question_type == "backgroundresponse":
                the_response = interview_status.question.backgroundresponse
                if isinstance(the_response, dict) and 'pargs' in the_response and isinstance(the_response['pargs'],
                                                                                             list) and len(
                    the_response['pargs']) == 2 and the_response['pargs'][1] in (
                        'javascript', 'flash', 'refresh', 'fields'):
                    commands.append(
                        dict(action=do_action, value=docassemble.base.functions.safe_json(the_response['pargs'][0]),
                             extra=the_response['pargs'][1]))
                elif isinstance(the_response, list) and len(the_response) == 2 and the_response[1] in (
                        'javascript', 'flash', 'refresh', 'fields'):
                    commands.append(dict(action=do_action, value=docassemble.base.functions.safe_json(the_response[0]),
                                         extra=the_response[1]))
                elif isinstance(the_response, str) and the_response == 'refresh':
                    commands.append(
                        dict(action=do_action, value=docassemble.base.functions.safe_json(None), extra='refresh'))
                else:
                    commands.append(dict(action=do_action, value=docassemble.base.functions.safe_json(the_response),
                                         extra='backgroundresponse'))
            elif interview_status.question.question_type == "template" and interview_status.question.target is not None:
                commands.append(dict(action=do_action, value=dict(target=interview_status.question.target,
                                                                  content=docassemble.base.util.markdown_to_html(
                                                                      interview_status.questionText, trim=True)),
                                     extra='backgroundresponse'))
            save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, steps=steps)
            release_lock(session_id, yaml_filename)
        peer_ok = False
        help_ok = False
        num_peers = 0
        help_available = 0
        session_info = get_session(yaml_filename)
        old_chatstatus = session_info['chatstatus']
        chatstatus = request.form.get('chatstatus', 'off')
        if old_chatstatus != chatstatus:
            update_session(yaml_filename, chatstatus=chatstatus)
        obj = dict(chatstatus=chatstatus, i=yaml_filename, uid=session_id, userid=the_user_id)
        key = 'da:session:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
        call_forwarding_on = False
        forwarding_phone_number = None
        if twilio_config is not None:
            forwarding_phone_number = twilio_config['name']['default'].get('number', None)
            if forwarding_phone_number is not None:
                call_forwarding_on = True
        call_forwarding_code = None
        call_forwarding_message = None
        if call_forwarding_on:
            for call_key in r.keys(re.sub(r'^da:session:uid:', 'da:phonecode:monitor:*:uid:', key)):
                call_key = call_key.decode()
                call_forwarding_code = r.get(call_key)
                if call_forwarding_code is not None:
                    call_forwarding_code = call_forwarding_code.decode()
                    other_value = r.get('da:callforward:' + call_forwarding_code)
                    if other_value is None:
                        r.delete(call_key)
                        continue
                    other_value = other_value.decode()
                    remaining_seconds = r.ttl(call_key)
                    if remaining_seconds > 30:
                        call_forwarding_message = '<span class="daphone-message"><i class="fas fa-phone"></i> ' + word(
                            'To reach an advocate who can assist you, call') + ' <a class="daphone-number" href="tel:' + str(
                            forwarding_phone_number) + '">' + str(forwarding_phone_number) + '</a> ' + word(
                            "and enter the code") + ' <span class="daphone-code">' + str(
                            call_forwarding_code) + '</span>.</span>'
                        break
        chat_session_key = 'da:interviewsession:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(
            the_user_id)
        potential_partners = []
        if str(chatstatus) != 'off':
            steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
            the_current_info['encrypted'] == is_encrypted
            if user_dict is None:
                sys.stderr.write("checkin: error accessing dictionary for %s and %s" % (session_id, yaml_filename))
                return jsonify_with_cache(success=False)
            obj['chatstatus'] = chatstatus
            obj['secret'] = secret
            obj['encrypted'] = is_encrypted
            obj['mode'] = user_dict['_internal']['livehelp']['mode']
            if obj['mode'] in ('peer', 'peerhelp'):
                peer_ok = True
            if obj['mode'] in ('help', 'peerhelp'):
                help_ok = True
            obj['partner_roles'] = user_dict['_internal']['livehelp']['partner_roles']
            if current_user.is_authenticated:
                for attribute in (
                        'email', 'confirmed_at', 'first_name', 'last_name', 'country', 'subdivisionfirst',
                        'subdivisionsecond',
                        'subdivisionthird', 'organization', 'timezone', 'language'):
                    obj[attribute] = str(getattr(current_user, attribute, None))
            else:
                obj['temp_user_id'] = temp_user_id
            if help_ok and len(obj['partner_roles']) and not r.exists(
                    'da:block:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)):
                pipe = r.pipeline()
                for role in obj['partner_roles']:
                    role_key = 'da:chat:roletype:' + str(role)
                    pipe.set(role_key, 1)
                    pipe.expire(role_key, 2592000)
                pipe.execute()
                for role in obj['partner_roles']:
                    for the_key in r.keys('da:monitor:role:' + role + ':userid:*'):
                        user_id = re.sub(r'^.*:userid:', '', the_key.decode())
                        if user_id not in potential_partners:
                            potential_partners.append(user_id)
                for the_key in r.keys('da:monitor:chatpartners:*'):
                    user_id = re.sub(r'^.*chatpartners:', '', the_key.decode())
                    if user_id not in potential_partners:
                        for chat_key in r.hgetall(the_key):
                            if chat_key.decode() == chat_session_key:
                                potential_partners.append(user_id)
            if len(potential_partners) > 0:
                if chatstatus == 'ringing':
                    lkey = 'da:ready:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(
                        the_user_id)
                    pipe = r.pipeline()
                    failure = True
                    for user_id in potential_partners:
                        for the_key in r.keys('da:monitor:available:' + str(user_id)):
                            pipe.rpush(lkey, the_key.decode())
                            failure = False
                    if peer_ok:
                        for the_key in r.keys('da:interviewsession:uid:' + str(session_id) + ':i:' + str(
                                yaml_filename) + ':userid:*'):
                            the_key = the_key.decode()
                            if the_key != chat_session_key:
                                pipe.rpush(lkey, the_key)
                                failure = False
                    if failure:
                        if peer_ok:
                            chatstatus = 'ready'
                        else:
                            chatstatus = 'waiting'
                        update_session(yaml_filename, chatstatus=chatstatus)
                        obj['chatstatus'] = chatstatus
                    else:
                        pipe.expire(lkey, 60)
                        pipe.execute()
                        chatstatus = 'ready'
                        update_session(yaml_filename, chatstatus=chatstatus)
                        obj['chatstatus'] = chatstatus
                elif chatstatus == 'on':
                    if len(potential_partners) > 0:
                        already_connected_to_help = False
                        for user_id in potential_partners:
                            for the_key in r.hgetall('da:monitor:chatpartners:' + str(user_id)):
                                if the_key.decode() == chat_session_key:
                                    already_connected_to_help = True
                        if not already_connected_to_help:
                            for user_id in potential_partners:
                                mon_sid = r.get('da:monitor:available:' + str(user_id))
                                if mon_sid is None:
                                    continue
                                mon_sid = mon_sid.decode()
                                int_sid = r.get('da:interviewsession:uid:' + str(session_id) + ':i:' + str(
                                    yaml_filename) + ':userid:' + str(the_user_id))
                                if int_sid is None:
                                    continue
                                int_sid = int_sid.decode()
                                r.publish(mon_sid, json.dumps(
                                    dict(messagetype='chatready', uid=session_id, i=yaml_filename, userid=the_user_id,
                                         secret=secret, sid=int_sid)))
                                r.publish(int_sid, json.dumps(dict(messagetype='chatpartner', sid=mon_sid)))
                                break
                if chatstatus in ('waiting', 'hangup'):
                    chatstatus = 'standby'
                    update_session(yaml_filename, chatstatus=chatstatus)
                    obj['chatstatus'] = chatstatus
            else:
                if peer_ok:
                    if chatstatus == 'ringing':
                        lkey = 'da:ready:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(
                            the_user_id)
                        pipe = r.pipeline()
                        failure = True
                        for the_key in r.keys('da:interviewsession:uid:' + str(session_id) + ':i:' + str(
                                yaml_filename) + ':userid:*'):
                            the_key = the_key.decode()
                            if the_key != chat_session_key:
                                pipe.rpush(lkey, the_key)
                                failure = False
                        if not failure:
                            pipe.expire(lkey, 6000)
                            pipe.execute()
                        chatstatus = 'ready'
                        update_session(yaml_filename, chatstatus=chatstatus)
                        obj['chatstatus'] = chatstatus
                    elif chatstatus in ('waiting', 'hangup'):
                        chatstatus = 'standby'
                        update_session(yaml_filename, chatstatus=chatstatus)
                        obj['chatstatus'] = chatstatus
                else:
                    if chatstatus in ('standby', 'ready', 'ringing', 'hangup'):
                        chatstatus = 'waiting'
                        update_session(yaml_filename, chatstatus=chatstatus)
                        obj['chatstatus'] = chatstatus
            if peer_ok:
                for sess_key in r.keys('da:session:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:*'):
                    if sess_key.decode() != key:
                        num_peers += 1
        help_available = len(potential_partners)
        html_key = 'da:html:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
        if old_chatstatus != chatstatus:
            html = r.get(html_key)
            if html is not None:
                html_obj = json.loads(html.decode())
                if 'browser_title' in html_obj:
                    obj['browser_title'] = html_obj['browser_title']
                obj['blocked'] = bool(r.exists(
                    'da:block:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)))
                r.publish('da:monitor', json.dumps(dict(messagetype='sessionupdate', key=key, session=obj)))
            else:
                logmessage("checkin: the html was not found at " + str(html_key))
        pipe = r.pipeline()
        pipe.set(key, pickle.dumps(obj))
        pipe.expire(key, 60)
        pipe.expire(html_key, 60)
        pipe.execute()
        ocontrol_key = 'da:control:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
        ocontrol = r.get(ocontrol_key)
        observer_control = not bool(ocontrol is None)
        parameters = request.form.get('raw_parameters', None)
        if parameters is not None:
            key = 'da:input:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
            r.publish(key, parameters)
        worker_key = 'da:worker:uid:' + str(session_id) + ':i:' + str(yaml_filename) + ':userid:' + str(the_user_id)
        worker_len = r.llen(worker_key)
        if worker_len > 0:
            workers_inspected = 0
            while workers_inspected <= worker_len:
                worker_id = r.lpop(worker_key)
                if worker_id is not None:
                    try:
                        result = docassemble.webapp.worker.workerapp.AsyncResult(id=worker_id)
                        if result.ready():
                            if isinstance(result.result, ReturnValue):
                                commands.append(dict(value=result.result.value, extra=result.result.extra))
                        else:
                            r.rpush(worker_key, worker_id)
                    except Exception as errstr:
                        logmessage("checkin: got error " + str(errstr))
                        r.rpush(worker_key, worker_id)
                workers_inspected += 1
        if peer_ok or help_ok:
            return jsonify_with_cache(success=True, chat_status=chatstatus, num_peers=num_peers,
                                      help_available=help_available, phone=call_forwarding_message,
                                      observerControl=observer_control, commands=commands, checkin_code=checkin_code)
        return jsonify_with_cache(success=True, chat_status=chatstatus, phone=call_forwarding_message,
                                  observerControl=observer_control, commands=commands, checkin_code=checkin_code)
    return jsonify_with_cache(success=False)


@app.before_first_request
def setup_celery():
    docassemble.webapp.worker.workerapp.set_current()


@app.before_request
def setup_variables():
    docassemble.base.functions.reset_local_variables()


@app.after_request
def apply_security_headers(response):
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000'
    if 'embed' in g:
        return response
    response.headers["X-Content-Type-Options"] = 'nosniff'
    response.headers["X-XSS-Protection"] = '1'
    if daconfig.get('allow embedding', False) is not True:
        response.headers["X-Frame-Options"] = 'SAMEORIGIN'
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self';"
    elif daconfig.get('cross site domains', []):
        response.headers["Content-Security-Policy"] = "frame-ancestors 'self' " + ' '.join(
            daconfig['cross site domains']) + ';'
    return response


@app.route("/", methods=['GET'])
def rootindex():
    if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
        return redirect(url_for('user.login'))
    url = daconfig.get('root redirect url', None)
    if url is not None:
        return redirect(url)
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        if 'default interview' not in daconfig and len(daconfig['dispatch']):
            return redirect(url_for('interview.interview_start'))
        yaml_filename = final_default_yaml_filename
    if COOKIELESS_SESSIONS:
        return html_index()
    the_args = {}
    for key, val in request.args.items():
        the_args[key] = val
    the_args['i'] = yaml_filename
    request.args = the_args
    return index(refer=['root'])


def fixstr(data):
    return bytearray(data, encoding='utf-8').decode('utf-8', 'ignore').encode("utf-8")


@app.template_filter('word')
def word_filter(text):
    return docassemble.base.functions.word(str(text))


@app.context_processor
def utility_processor():
    def user_designator(the_user):
        if the_user.email:
            return the_user.email
        else:
            return re.sub(r'.*\$', '', the_user.social_id)

    if 'language' in session:
        docassemble.base.functions.set_language(session['language'])
        lang = session['language']
    elif 'Accept-Language' in request.headers:
        langs = docassemble.base.functions.parse_accept_language(request.headers['Accept-Language'])
        if len(langs) > 0:
            docassemble.base.functions.set_language(langs[0])
            lang = langs[0]
        else:
            docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
            lang = DEFAULT_LANGUAGE
    else:
        docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
        lang = DEFAULT_LANGUAGE

    def in_debug():
        return DEBUG

    return dict(word=docassemble.base.functions.word, in_debug=in_debug, user_designator=user_designator,
                get_part=get_part, current_language=lang)


def decode_dict(the_dict):
    out_dict = {}
    for k, v in the_dict.items():
        out_dict[k.decode()] = v.decode()
    return out_dict


@app.route('/monitor', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'advocate'])
def monitor():
    if not app.config['ENABLE_MONITOR']:
        return ('File not found', 404)
    setup_translation()
    if request.method == 'GET' and needs_to_change_password():
        return redirect(url_for('user.change_password', next=url_for('monitor')))
    session['monitor'] = 1
    if 'user_id' not in session:
        session['user_id'] = current_user.id
    phone_number_key = 'da:monitor:phonenumber:' + str(session['user_id'])
    default_phone_number = r.get(phone_number_key)
    if default_phone_number is None:
        default_phone_number = ''
    else:
        default_phone_number = default_phone_number.decode()
    sub_role_key = 'da:monitor:userrole:' + str(session['user_id'])
    if r.exists(sub_role_key):
        subscribed_roles = decode_dict(r.hgetall(sub_role_key))
        r.expire(sub_role_key, 2592000)
    else:
        subscribed_roles = {}
    key = 'da:monitor:available:' + str(current_user.id)
    if r.exists(key):
        daAvailableForChat = 'true'
    else:
        daAvailableForChat = 'false'
    call_forwarding_on = 'false'
    if twilio_config is not None:
        forwarding_phone_number = twilio_config['name']['default'].get('number', None)
        if forwarding_phone_number is not None:
            call_forwarding_on = 'true'
    script = "\n" + '    <script type="text/javascript" src="' + url_for('static', filename='app/socket.io.min.js',
                                                                         v=da_version) + '"></script>' + "\n" + """    <script type="text/javascript">
      var daAudioContext = null;
      var daSocket;
      var daSoundBuffer = Object();
      var daShowingNotif = false;
      var daUpdatedSessions = Object();
      var daUserid = """ + str(current_user.id) + """;
      var daPhoneOnMessage = """ + json.dumps(word("The user can call you.  Click to cancel.")) + """;
      var daPhoneOffMessage = """ + json.dumps(word("Click if you want the user to be able to call you.")) + """;
      var daSessions = Object();
      var daAvailRoles = Object();
      var daChatPartners = Object();
      var daPhonePartners = Object();
      var daNewPhonePartners = Object();
      var daTermPhonePartners = Object();
      var daUsePhone = """ + call_forwarding_on + """;
      var daSubscribedRoles = """ + json.dumps(subscribed_roles) + """;
      var daAvailableForChat = """ + daAvailableForChat + """;
      var daPhoneNumber = """ + json.dumps(default_phone_number) + """;
      var daFirstTime = 1;
      var daUpdateMonitorInterval = null;
      var daNotificationsEnabled = false;
      var daControlling = Object();
      var daBrowserTitle = """ + json.dumps(word('Monitor')) + """;
      window.daGotConfirmation = function(key){
          //console.log("Got confirmation in parent for key " + key);
          // daControlling[key] = 2;
          // var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          // $("#listelement" + skey).find("a").each(function(){
          //     if ($(this).data('name') == "stopcontrolling"){
          //         $(this).removeClass('dainvisible');
          //         console.log("Found it");
          //     }
          // });
      }
      function daFaviconRegular(){
        var link = document.querySelector("link[rel*='shortcut icon'") || document.createElement('link');
        link.type = 'image/x-icon';
        link.rel = 'shortcut icon';
        link.href = '""" + url_for('files.favicon', nocache="1") + """';
        document.getElementsByTagName('head')[0].appendChild(link);
      }
      function daFaviconAlert(){
        var link = document.querySelector("link[rel*='shortcut icon'") || document.createElement('link');
        link.type = 'image/x-icon';
        link.rel = 'shortcut icon';
        link.href = '""" + url_for('static', filename='app/chat.ico', v=da_version) + """?nocache=1';
        document.getElementsByTagName('head')[0].appendChild(link);
      }
      function daTopMessage(message){
          var newDiv = document.createElement('div');
          $(newDiv).addClass("datop-alert col-xs-10 col-sm-7 col-md-6 col-lg-5 dacol-centered");
          $(newDiv).html(message)
          $(newDiv).css("display", "none");
          $(newDiv).appendTo($(daTargetDiv));
          $(newDiv).slideDown();
          setTimeout(function(){
            $(newDiv).slideUp(300, function(){
              $(newDiv).remove();
            });
          }, 2000);
      }
      window.daAbortControlling = function(key){
          daTopMessage(""" + json.dumps(word("That screen is already being controlled by another operator")) + """);
          daStopControlling(key);
      }
      window.daStopControlling = function(key){
          //console.log("Got daStopControlling in parent for key " + key);
          // if (daControlling.hasOwnProperty(key)){
          //   delete daControlling[key];
          // }
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          $("#listelement" + skey).find("a").each(function(){
              if ($(this).data('name') == "stopcontrolling"){
                  $(this).click();
                  //console.log("Found it");
              }
          });
      }
      function daOnError(){
          console.log('daOnError');
      }
      function daLoadSoundBuffer(key, url_a, url_b){
          //console.log("daLoadSoundBuffer");
          var pos = 0;
          if (daAudioContext == null){
              return;
          }
          var request = new XMLHttpRequest();
          request.open('GET', url_a, true);
          request.responseType = 'arraybuffer';
          request.onload = function(){
              daAudioContext.decodeAudioData(request.response, function(buffer){
                  if (!buffer){
                      if (pos == 1){
                          console.error('daLoadSoundBuffer: error decoding file data');
                          return;
                      }
                      else {
                          pos = 1;
                          console.info('daLoadSoundBuffer: error decoding file data, trying next source');
                          request.open("GET", url_b, true);
                          return request.send();
                      }
                  }
                  daSoundBuffer[key] = buffer;
              },
              function(error){
                  if (pos == 1){
                      console.error('daLoadSoundBuffer: decodeAudioData error');
                      return;
                  }
                  else{
                      pos = 1;
                      console.info('daLoadSoundBuffer: decodeAudioData error, trying next source');
                      request.open("GET", url_b, true);
                      return request.send();
                  }
              });
          }
          request.send();
      }
      function daPlaySound(key) {
          //console.log("daPlaySound");
          var buffer = daSoundBuffer[key];
          if (!daAudioContext || !buffer){
              return;
          }
          var source = daAudioContext.createBufferSource();
          source.buffer = buffer;
          source.connect(daAudioContext.destination);
          source.start(0);
      }
      function daCheckNotifications(){
          //console.log("daCheckNotifications");
          if (daNotificationsEnabled){
              return;
          }
          if (!("Notification" in window)) {
              daNotificationsEnabled = false;
              return;
          }
          if (Notification.permission === "granted") {
              daNotificationsEnabled = true;
              return;
          }
          if (Notification.permission !== 'denied') {
              Notification.requestPermission(function (permission) {
                  if (permission === "granted") {
                      daNotificationsEnabled = true;
                  }
              });
          }
      }
      function daNotifyOperator(key, mode, message) {
          //console.log("daNotifyOperator: " + key + " " + mode + " " + message);
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          if (mode == "chat"){
            daPlaySound('newmessage');
          }
          else{
            daPlaySound('newconversation');
          }
          if ($("#listelement" + skey).offset().top > $(window).scrollTop() + $(window).height()){
            if (mode == "chat"){
              $("#chat-message-below").html(""" + json.dumps(word("New message below")) + """);
            }
            else{
              $("#chat-message-below").html(""" + json.dumps(word("New conversation below")) + """);
            }
            //$("#chat-message-below").data('key', key);
            $("#chat-message-below").slideDown();
            daShowingNotif = true;
            daMarkAsUpdated(key);
          }
          else if ($("#listelement" + skey).offset().top + $("#listelement" + skey).height() < $(window).scrollTop() + 32){
            if (mode == "chat"){
              $("#chat-message-above").html(""" + json.dumps(word("New message above")) + """);
            }
            else{
              $("#chat-message-above").html(""" + json.dumps(word("New conversation above")) + """);
            }
            //$("#chat-message-above").data('key', key);
            $("#chat-message-above").slideDown();
            daShowingNotif = true;
            daMarkAsUpdated(key);
          }
          else{
            //console.log("It is visible");
          }
          if (!daNotificationsEnabled){
              //console.log("Browser will not enable notifications")
              return;
          }
          if (!("Notification" in window)) {
              return;
          }
          if (Notification.permission === "granted") {
              var notification = new Notification(message);
          }
          else if (Notification.permission !== 'denied') {
              Notification.requestPermission(function (permission) {
                  if (permission === "granted") {
                      var notification = new Notification(message);
                      daNotificationsEnabled = true;
                  }
              });
          }
      }
      function daPhoneNumberOk(){
          //console.log("daPhoneNumberOk");
          var phoneNumber = $("#daPhoneNumber").val();
          if (phoneNumber == '' || phoneNumber.match(/^\+?[1-9]\d{1,14}$/)){
              return true;
          }
          else{
              return false;
          }
      }
      function daCheckPhone(){
          //console.log("daCheckPhone");
          $("#daPhoneNumber").val($("#daPhoneNumber").val().replace(/ \-/g, ''));
          var the_number = $("#daPhoneNumber").val();
          if (the_number != '' && the_number[0] != '+'){
              $("#daPhoneNumber").val('+' + the_number);
          }
          if (daPhoneNumberOk()){
              $("#daPhoneNumber").removeClass("is-invalid");
              $("#daPhoneError").addClass("dainvisible");
              daPhoneNumber = $("#daPhoneNumber").val();
              if (daPhoneNumber == ''){
                  daPhoneNumber = null;
              }
              else{
                  $(".phone").removeClass("dainvisible");
              }
              $("#daPhoneSaved").removeClass("dainvisible");
              setTimeout(function(){
                  $("#daPhoneSaved").addClass("dainvisible");
              }, 2000);
          }
          else{
              $("#daPhoneNumber").addClass("is-invalid");
              $("#daPhoneError").removeClass("dainvisible");
              daPhoneNumber = null;
              $(".phone").addClass("dainvisible");
          }
      }
      function daAllSessions(uid, yaml_filename){
          //console.log("daAllSessions");
          var prefix = 'da:session:uid:' + uid + ':i:' + yaml_filename + ':userid:';
          var output = Array();
          for (var key in daSessions){
              if (daSessions.hasOwnProperty(key) && key.indexOf(prefix) == 0){
                  output.push(key);
              }
          }
          return(output);
      }
      function daScrollChat(key){
          var chatScroller = $(key).find('ul').first();
          if (chatScroller.length){
              var height = chatScroller[0].scrollHeight;
              chatScroller.animate({scrollTop: height}, 800);
          }
          else{
              console.log("daScrollChat: error")
          }
      }
      function daScrollChatFast(key){
          var chatScroller = $(key).find('ul').first();
          if (chatScroller.length){
            var height = chatScroller[0].scrollHeight;
              //console.log("Scrolling to " + height + " where there are " + chatScroller[0].childElementCount + " children");
              chatScroller.scrollTop(height);
            }
          else{
              console.log("daScrollChatFast: error")
          }
      }
      function daDoUpdateMonitor(){
          //console.log("daDoUpdateMonitor with " + daAvailableForChat);
          if (daPhoneNumberOk()){
            daPhoneNumber = $("#daPhoneNumber").val();
            if (daPhoneNumber == ''){
              daPhoneNumber = null;
            }
          }
          else{
            daPhoneNumber = null;
          }
          daSocket.emit('updatemonitor', {available_for_chat: daAvailableForChat, phone_number: daPhoneNumber, subscribed_roles: daSubscribedRoles, phone_partners_to_add: daNewPhonePartners, phone_partners_to_terminate: daTermPhonePartners});
      }
      function daUpdateMonitor(){
          //console.log("daUpdateMonitor with " + daAvailableForChat);
          if (daUpdateMonitorInterval != null){
              clearInterval(daUpdateMonitorInterval);
          }
          daDoUpdateMonitor();
          daUpdateMonitorInterval = setInterval(daDoUpdateMonitor, """ + str(CHECKIN_INTERVAL) + """);
          //console.log("daUpdateMonitor");
      }
      function daIsHidden(ref){
          if ($(ref).length){
              if (($(ref).offset().top + $(ref).height() < $(window).scrollTop() + 32)){
                  return -1;
              }
              else if ($(ref).offset().top > $(window).scrollTop() + $(window).height()){
                  return 1;
              }
              else{
                  return 0;
              }
          }
          else{
              return 0;
          }
      }
      function daMarkAsUpdated(key){
          //console.log("daMarkAsUpdated with " + key);
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          if (daIsHidden("#listelement" + skey)){
              daUpdatedSessions["#listelement" + skey] = 1;
          }
      }
      function daActivateChatArea(key){
          //console.log("daActivateChatArea with " + key);
from docassemble.base.logger import set_logger
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          if (!$("#chatarea" + skey).find('input').first().is(':focus')){
            $("#listelement" + skey).addClass("da-new-message");
            if (daBrowserTitle == document.title){
              document.title = '* ' + daBrowserTitle;
              daFaviconAlert();
            }
          }
          daMarkAsUpdated(key);
          $("#chatarea" + skey).removeClass('dainvisible');
          $("#chatarea" + skey).find('input, button').prop("disabled", false);
          $("#chatarea" + skey).find('ul').html('');
          daSocket.emit('chat_log', {key: key});
      }
      function daDeActivateChatArea(key){
          //console.log("daActivateChatArea with " + key);
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          $("#chatarea" + skey).find('input, button').prop("disabled", true);
          $("#listelement" + skey).removeClass("da-new-message");
          if (document.title != daBrowserTitle){
              document.title = daBrowserTitle;
              daFaviconRegular();
          }
      }
      function daUndrawSession(key){
          //console.log("Undrawing...");
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          var xButton = document.createElement('a');
          var xButtonIcon = document.createElement('i');
          $(xButton).addClass("dacorner-remove");
          $(xButtonIcon).addClass("fas fa-times-circle");
          $(xButtonIcon).appendTo($(xButton));
          $("#listelement" + skey).addClass("list-group-item-danger");
          $("#session" + skey).find("a").remove();
          $("#session" + skey).find("span").first().html(""" + json.dumps(word("offline")) + """);
          $("#session" + skey).find("span").first().removeClass('""" + app.config['BUTTON_STYLE'] + """info');
          $("#session" + skey).find("span").first().addClass('""" + app.config['BUTTON_STYLE'] + """danger');
          $(xButton).click(function(){
              $("#listelement" + skey).slideUp(300, function(){
                  $("#listelement" + skey).remove();
                  daCheckIfEmpty();
              });
          });
          $(xButton).appendTo($("#session" + skey));
          $("#chatarea" + skey).find('input, button').prop("disabled", true);
          var theIframe = $("#iframe" + skey).find('iframe')[0];
          if (theIframe){
              $(theIframe).contents().find('body').addClass("dainactive");
              if (theIframe.contentWindow && theIframe.contentWindow.daTurnOffControl){
                  theIframe.contentWindow.daTurnOffControl();
              }
          }
          if (daControlling.hasOwnProperty(key)){
              delete daControlling[key];
          }
          delete daSessions[key];
      }
      function daPublishChatLog(uid, yaml_filename, userid, mode, messages, scroll){
          //console.log("daPublishChatLog with " + uid + " " + yaml_filename + " " + userid + " " + mode + " " + messages);
          //console.log("daPublishChatLog: scroll is " + scroll);
          var keys;
          //if (mode == 'peer' || mode == 'peerhelp'){
          //    keys = daAllSessions(uid, yaml_filename);
          //}
          //else{
              keys = ['da:session:uid:' + uid + ':i:' + yaml_filename + ':userid:' + userid];
          //}
          for (var i = 0; i < keys.length; ++i){
              key = keys[i];
              var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
              var chatArea = $("#chatarea" + skey).find('ul').first();
              if (messages.length > 0){
                $(chatArea).removeClass('dainvisible');
              }
              for (var i = 0; i < messages.length; ++i){
                  var message = messages[i];
                  var newLi = document.createElement('li');
                  $(newLi).addClass("list-group-item");
                  if (message.is_self){
                      $(newLi).addClass("list-group-item-primary dalistright");
                  }
                  else{
                      $(newLi).addClass("list-group-item-secondary dalistleft");
                  }
                  $(newLi).html(message.message);
                  $(newLi).appendTo(chatArea);
              }
              if (messages.length > 0 && scroll){
                  daScrollChatFast("#chatarea" + skey);
              }
          }
      }
      function daCheckIfEmpty(){
          if ($("#monitorsessions").find("li").length > 0){
              $("#emptylist").addClass("dainvisible");
          }
          else{
              $("#emptylist").removeClass("dainvisible");
          }
      }
      function daDrawSession(key, obj){
          //console.log("daDrawSession with " + key);
          var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
          var the_html;
          var wants_to_chat;
          if (obj.chatstatus != 'off'){ //obj.chatstatus == 'waiting' || obj.chatstatus == 'standby' || obj.chatstatus == 'ringing' || obj.chatstatus == 'ready' || obj.chatstatus == 'on' || obj.chatstatus == 'observeonly'
              wants_to_chat = true;
          }
          if (wants_to_chat){
              the_html = obj.browser_title + ' &mdash; '
              if (obj.hasOwnProperty('first_name')){
                the_html += obj.first_name + ' ' + obj.last_name;
              }
              else{
                the_html += """ + json.dumps(word("anonymous visitor") + ' ') + """ + obj.temp_user_id;
              }
          }
          var theListElement;
          var sessionDiv;
          var theIframeContainer;
          var theChatArea;
          if ($("#session" + skey).length && !(key in daSessions)){
              $("#listelement" + skey).removeClass("list-group-item-danger");
              $("#iframe" + skey).find('iframe').first().contents().find('body').removeClass("dainactive");
          }
          daSessions[key] = 1;
          if ($("#session" + skey).length){
              theListElement = $("#listelement" + skey).first();
              sessionDiv = $("#session" + skey).first();
              //controlDiv = $("#control" + skey).first();
              theIframeContainer = $("#iframe" + skey).first();
              theChatArea = $("#chatarea" + skey).first();
              $(sessionDiv).empty();
              if (obj.chatstatus == 'on' && key in daChatPartners && $("#chatarea" + skey).find('button').first().prop("disabled") == true){
                  daActivateChatArea(key);
              }
          }
          else{
              var theListElement = document.createElement('li');
              $(theListElement).addClass('list-group-item');
              $(theListElement).attr('id', "listelement" + key);
              var sessionDiv = document.createElement('div');
              $(sessionDiv).attr('id', "session" + key);
              $(sessionDiv).addClass('da-chat-session');
              $(sessionDiv).addClass('p-1');
              $(sessionDiv).appendTo($(theListElement));
              $(theListElement).appendTo("#monitorsessions");
              // controlDiv = document.createElement('div');
              // $(controlDiv).attr('id', "control" + key);
              // $(controlDiv).addClass("dachatcontrol dainvisible da-chat-session");
              // $(controlDiv).appendTo($(theListElement));
              theIframeContainer = document.createElement('div');
              $(theIframeContainer).addClass("daobserver-container dainvisible");
              $(theIframeContainer).attr('id', 'iframe' + key);
              var theIframe = document.createElement('iframe');
              $(theIframe).addClass("daobserver");
              $(theIframe).attr('name', 'iframe' + key);
              $(theIframe).appendTo($(theIframeContainer));
              $(theIframeContainer).appendTo($(theListElement));
              var theChatArea = document.createElement('div');
              $(theChatArea).addClass('monitor-chat-area dainvisible');
              $(theChatArea).html('<div class="row"><div class="col-md-12"><ul class="list-group dachatbox" id="daCorrespondence"><\/ul><\/div><\/div><form autocomplete="off"><div class="row"><div class="col-md-12"><div class="input-group"><input type="text" class="form-control daChatMessage" disabled=""><button role="button" class="btn """ + \
             app.config['BUTTON_STYLE'] + """secondary daChatButton" type="button" disabled="">""" + word("Send") + """<\/button><\/div><\/div><\/div><\/form>');
              $(theChatArea).attr('id', 'chatarea' + key);
              var submitter = function(){
                  //console.log("I am the submitter and I am submitting " + key);
                  var input = $(theChatArea).find("input").first();
                  var message = input.val().trim();
                  if (message == null || message == ""){
                      //console.log("Message was blank");
                      return false;
                  }
                  daSocket.emit('chatmessage', {key: key, data: input.val()});
                  input.val('');
                  return false;
              };
              $(theChatArea).find("button").click(submitter);
              $(theChatArea).find("input").bind('keypress keydown keyup', function(e){
                  var theCode = e.which || e.keyCode;
                  if(theCode == 13) { submitter(); e.preventDefault(); }
              });
              $(theChatArea).find("input").focus(function(){
                  $(theListElement).removeClass("da-new-message");
                  if (document.title != daBrowserTitle){
                      document.title = daBrowserTitle;
                      daFaviconRegular();
                  }
              });
              $(theChatArea).appendTo($(theListElement));
              if (obj.chatstatus == 'on' && key in daChatPartners){
                  daActivateChatArea(key);
              }
          }
          var theText = document.createElement('span');
          $(theText).addClass('da-chat-title-label');
          theText.innerHTML = the_html;
          var statusLabel = document.createElement('span');
          $(statusLabel).addClass("badge bg-info da-chat-status-label");
          $(statusLabel).html(obj.chatstatus == 'observeonly' ? 'off' : obj.chatstatus);
          $(statusLabel).appendTo($(sessionDiv));
          if (daUsePhone){
            var phoneButton = document.createElement('a');
            var phoneIcon = document.createElement('i');
            $(phoneIcon).addClass("fas fa-phone");
            $(phoneIcon).appendTo($(phoneButton));
            $(phoneButton).addClass("btn phone");
            $(phoneButton).data('name', 'phone');
            if (key in daPhonePartners){
              $(phoneButton).addClass("phone-on """ + app.config['BUTTON_STYLE'] + """success");
              $(phoneButton).attr('title', daPhoneOnMessage);
            }
            else{
              $(phoneButton).addClass("phone-off """ + app.config['BUTTON_STYLE'] + """secondary");
              $(phoneButton).attr('title', daPhoneOffMessage);
            }
            $(phoneButton).attr('tabindex', 0);
            $(phoneButton).addClass('daobservebutton')
            $(phoneButton).appendTo($(sessionDiv));
            $(phoneButton).attr('href', '#');
            if (daPhoneNumber == null){
              $(phoneButton).addClass("dainvisible");
            }
            $(phoneButton).click(function(e){
              e.preventDefault();
              if ($(this).hasClass("phone-off") && daPhoneNumber != null){
                $(this).removeClass("phone-off");
                $(this).removeClass(""" + '"' + app.config['BUTTON_STYLE'] + """secondary");
                $(this).addClass("phone-on");
                $(this).addClass(""" + '"' + app.config['BUTTON_STYLE'] + """success");
                $(this).attr('title', daPhoneOnMessage);
                daPhonePartners[key] = 1;
                daNewPhonePartners[key] = 1;
                if (key in daTermPhonePartners){
                  delete daTermPhonePartners[key];
                }
              }
              else{
                $(this).removeClass("phone-on");
                $(this).removeClass(""" + '"' + app.config['BUTTON_STYLE'] + """success");
                $(this).addClass("phone-off");
                $(this).addClass(""" + '"' + app.config['BUTTON_STYLE'] + """secondary");
                $(this).attr('title', daPhoneOffMessage);
                if (key in daPhonePartners){
                  delete daPhonePartners[key];
                }
                if (key in daNewPhonePartners){
                  delete daNewPhonePartners[key];
                }
                daTermPhonePartners[key] = 1;
              }
              daUpdateMonitor();
              return false;
            });
          }
          var unblockButton = document.createElement('a');
          $(unblockButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """info daobservebutton");
          $(unblockButton).data('name', 'unblock');
          if (!obj.blocked){
              $(unblockButton).addClass("dainvisible");
          }
          $(unblockButton).html(""" + json.dumps(word("Unblock")) + """);
          $(unblockButton).attr('href', '#');
          $(unblockButton).appendTo($(sessionDiv));
          var blockButton = document.createElement('a');
          $(blockButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """danger daobservebutton");
          if (obj.blocked){
              $(blockButton).addClass("dainvisible");
          }
          $(blockButton).html(""" + json.dumps(word("Block")) + """);
          $(blockButton).attr('href', '#');
          $(blockButton).data('name', 'block');
          $(blockButton).appendTo($(sessionDiv));
          $(blockButton).click(function(e){
              $(unblockButton).removeClass("dainvisible");
              $(this).addClass("dainvisible");
              daDeActivateChatArea(key);
              daSocket.emit('block', {key: key});
              e.preventDefault();
              return false;
          });
          $(unblockButton).click(function(e){
              $(blockButton).removeClass("dainvisible");
              $(this).addClass("dainvisible");
              daSocket.emit('unblock', {key: key});
              e.preventDefault();
              return false;
          });
          var joinButton = document.createElement('a');
          $(joinButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """warning daobservebutton");
          $(joinButton).html(""" + json.dumps(word("Join")) + """);
          $(joinButton).attr('href', """ + json.dumps(url_for('interview.visit_interview') + '?') + """ + $.param({i: obj.i, uid: obj.uid, userid: obj.userid}));
          $(joinButton).data('name', 'join');
          $(joinButton).attr('target', '_blank');
          $(joinButton).appendTo($(sessionDiv));
          if (wants_to_chat){
              var openButton = document.createElement('a');
              $(openButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """primary daobservebutton");
              $(openButton).attr('href', """ + json.dumps(url_for('admin.observer') + '?') + """ + $.param({i: obj.i, uid: obj.uid, userid: obj.userid}));
              //$(openButton).attr('href', 'about:blank');
              $(openButton).attr('id', 'observe' + key);
              $(openButton).attr('target', 'iframe' + key);
              $(openButton).html(""" + json.dumps(word("Observe")) + """);
              $(openButton).data('name', 'open');
              $(openButton).appendTo($(sessionDiv));
              var stopObservingButton = document.createElement('a');
              $(stopObservingButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """secondary daobservebutton dainvisible");
              $(stopObservingButton).html(""" + json.dumps(word("Stop Observing")) + """);
              $(stopObservingButton).attr('href', '#');
              $(stopObservingButton).data('name', 'stopObserving');
              $(stopObservingButton).appendTo($(sessionDiv));
              var controlButton = document.createElement('a');
              $(controlButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """info daobservebutton");
              $(controlButton).html(""" + json.dumps(word("Control")) + """);
              $(controlButton).attr('href', '#');
              $(controlButton).data('name', 'control');
              $(controlButton).appendTo($(sessionDiv));
              var stopControllingButton = document.createElement('a');
              $(stopControllingButton).addClass("btn """ + app.config['BUTTON_STYLE'] + """secondary daobservebutton dainvisible");
              $(stopControllingButton).html(""" + json.dumps(word("Stop Controlling")) + """);
              $(stopControllingButton).attr('href', '#');
              $(stopControllingButton).data('name', 'stopcontrolling');
              $(stopControllingButton).appendTo($(sessionDiv));
              $(controlButton).click(function(event){
                  event.preventDefault();
                  //console.log("Controlling...");
                  $(this).addClass("dainvisible");
                  $(stopControllingButton).removeClass("dainvisible");
                  $(stopObservingButton).addClass("dainvisible");
                  var theIframe = $("#iframe" + skey).find('iframe')[0];
                  if (theIframe != null && theIframe.contentWindow){
                      theIframe.contentWindow.daTurnOnControl();
                  }
                  else{
                      console.log("Cannot turn on control");
                  }
                  daControlling[key] = 1;
                  return false;
              });
              $(stopControllingButton).click(function(event){
                  //console.log("Got click on stopControllingButton");
                  event.preventDefault();
                  var theIframe = $("#iframe" + skey).find('iframe')[0];
                  if (theIframe != null && theIframe.contentWindow && theIframe.contentWindow.daTurnOffControl){
                      theIframe.contentWindow.daTurnOffControl();
                  }
                  else{
                      console.log("Cannot turn off control");
                      return false;
                  }
                  //console.log("Stop controlling...");
                  $(this).addClass("dainvisible");
                  $(controlButton).removeClass("dainvisible");
                  $(stopObservingButton).removeClass("dainvisible");
                  if (daControlling.hasOwnProperty(key)){
                      delete daControlling[key];
                  }
                  return false;
              });
              $(openButton).click(function(event){
                  //console.log("Observing..");
                  $(this).addClass("dainvisible");
                  $(stopObservingButton).removeClass("dainvisible");
                  $("#iframe" + skey).removeClass("dainvisible");
                  $(controlButton).removeClass("dainvisible");
                  return true;
              });
              $(stopObservingButton).click(function(e){
                  //console.log("Unobserving...");
                  $(this).addClass("dainvisible");
                  $(openButton).removeClass("dainvisible");
                  $(controlButton).addClass("dainvisible");
                  $(stopObservingButton).addClass("dainvisible");
                  $(stopControllingButton).addClass("dainvisible");
                  var theIframe = $("#iframe" + skey).find('iframe')[0];
                  if (daControlling.hasOwnProperty(key)){
                      delete daControlling[key];
                      if (theIframe != null && theIframe.contentWindow && theIframe.contentWindow.daTurnOffControl){
                          //console.log("Calling daTurnOffControl in iframe");
                          theIframe.contentWindow.daTurnOffControl();
                      }
                  }
                  if (theIframe != null && theIframe.contentWindow){
                      //console.log("Deleting the iframe");
                      theIframe.contentWindow.document.open();
                      theIframe.contentWindow.document.write("");
                      theIframe.contentWindow.document.close();
                  }
                  $("#iframe" + skey).slideUp(400, function(){
                      $(this).css("display", "").addClass("dainvisible");
                  });
                  e.preventDefault();
                  return false;
              });
              if ($(theIframeContainer).hasClass("dainvisible")){
                  $(openButton).removeClass("dainvisible");
                  $(stopObservingButton).addClass("dainvisible");
                  $(controlButton).addClass("dainvisible");
                  $(stopControllingButton).addClass("dainvisible");
                  if (daControlling.hasOwnProperty(key)){
                      delete daControlling[key];
                  }
              }
              else{
                  $(openButton).addClass("dainvisible");
                  if (daControlling.hasOwnProperty(key)){
                      $(stopObservingButton).addClass("dainvisible");
                      $(controlButton).addClass("dainvisible");
                      $(stopControllingButton).removeClass("dainvisible");
                  }
                  else{
                      $(stopObservingButton).removeClass("dainvisible");
                      $(controlButton).removeClass("dainvisible");
                      $(stopControllingButton).addClass("dainvisible");
                  }
              }
          }
          $(theText).appendTo($(sessionDiv));
          if (obj.chatstatus == 'on' && key in daChatPartners && $("#chatarea" + skey).hasClass('dainvisible')){
              daActivateChatArea(key);
          }
          if ((obj.chatstatus != 'on' || !(key in daChatPartners)) && $("#chatarea" + skey).find('button').first().prop("disabled") == false){
              daDeActivateChatArea(key);
          }
          else if (obj.blocked){
              daDeActivateChatArea(key);
          }
      }
      function daOnScrollResize(){
          if (document.title != daBrowserTitle){
              document.title = daBrowserTitle;
              daFaviconRegular();
          }
          if (!daShowingNotif){
              return true;
          }
          var obj = Array();
          for (var key in daUpdatedSessions){
              if (daUpdatedSessions.hasOwnProperty(key)){
                  obj.push(key);
              }
          }
          var somethingAbove = false;
          var somethingBelow = false;
          var firstElement = -1;
          var lastElement = -1;
          for (var i = 0; i < obj.length; ++i){
              var result = daIsHidden(obj[i]);
              if (result == 0){
                  delete daUpdatedSessions[obj[i]];
              }
              else if (result < 0){
                  var top = $(obj[i]).offset().top;
                  somethingAbove = true;
                  if (firstElement == -1 || top < firstElement){
                      firstElement = top;
                  }
              }
              else if (result > 0){
                  var top = $(obj[i]).offset().top;
                  somethingBelow = true;
                  if (lastElement == -1 || top > lastElement){
                      lastElement = top;
                  }
              }
          }
          if (($("#chat-message-above").is(":visible")) && !somethingAbove){
              $("#chat-message-above").hide();
          }
          if (($("#chat-message-below").is(":visible")) && !somethingBelow){
              $("#chat-message-below").hide();
          }
          if (!(somethingAbove || somethingBelow)){
              daShowingNotif = false;
          }
          return true;
      }
      $(document).ready(function(){
          //console.log("document ready");
          try {
              window.AudioContext = window.AudioContext || window.webkitAudioContext;
              daAudioContext = new AudioContext();
          }
          catch(e) {
              console.log('Web Audio API is not supported in this browser');
          }
          daLoadSoundBuffer('newmessage', '""" + url_for('static', filename='sounds/notification-click-on.mp3',
                                                         v=da_version) + """', '""" + url_for('static',
                                                                                              filename='sounds/notification-click-on.ogg',
                                                                                              v=da_version) + """');
          daLoadSoundBuffer('newconversation', '""" + url_for('static', filename='sounds/notification-stapler.mp3',
                                                              v=da_version) + """', '""" + url_for('static',
                                                                                                   filename='sounds/notification-stapler.ogg',
                                                                                                   v=da_version) + """');
          daLoadSoundBuffer('signinout', '""" + url_for('static', filename='sounds/notification-snap.mp3',
                                                        v=da_version) + """', '""" + url_for('static',
                                                                                             filename='sounds/notification-snap.ogg',
                                                                                             v=da_version) + """');
          if (location.protocol === 'http:' || document.location.protocol === 'http:'){
              daSocket = io.connect('http://' + document.domain + '/monitor', {path: '""" + ROOT + """ws/socket.io'});
          }
          if (location.protocol === 'https:' || document.location.protocol === 'https:'){
              daSocket = io.connect('https://' + document.domain + '/monitor', {path: '""" + ROOT + """ws/socket.io'});
          }
          //console.log("socket is " + daSocket)
          if (typeof daSocket !== 'undefined') {
              daSocket.on('connect', function() {
                  //console.log("Connected!");
                  daUpdateMonitor();
              });
              daSocket.on('terminate', function() {
                  console.log("monitor: terminating socket");
                  daSocket.disconnect();
              });
              daSocket.on('disconnect', function() {
                  //console.log("monitor: disconnected socket");
                  //daSocket = null;
              });
              daSocket.on('refreshsessions', function(data) {
                  daUpdateMonitor();
              });
              // daSocket.on('abortcontroller', function(data) {
              //     console.log("Got abortcontroller message for " + data.key);
              // });
              daSocket.on('chatready', function(data) {
                  var key = 'da:session:uid:' + data.uid + ':i:' + data.i + ':userid:' + data.userid
                  //console.log('chatready: ' + key);
                  daActivateChatArea(key);
                  daNotifyOperator(key, "chatready", """ + json.dumps(word("New chat connection from")) + """ + ' ' + data.name)
              });
              daSocket.on('chatstop', function(data) {
                  var key = 'da:session:uid:' + data.uid + ':i:' + data.i + ':userid:' + data.userid
                  //console.log('chatstop: ' + key);
                  if (key in daChatPartners){
                      delete daChatPartners[key];
                  }
                  daDeActivateChatArea(key);
              });
              daSocket.on('chat_log', function(arg) {
                  //console.log('chat_log: ' + arg.userid);
                  daPublishChatLog(arg.uid, arg.i, arg.userid, arg.mode, arg.data, arg.scroll);
              });
              daSocket.on('block', function(arg) {
                  //console.log("back from blocking " + arg.key);
                  daUpdateMonitor();
              });
              daSocket.on('unblock', function(arg) {
                  //console.log("back from unblocking " + arg.key);
                  daUpdateMonitor();
              });
              daSocket.on('chatmessage', function(data) {
                  //console.log("chatmessage");
                  var keys;
                  if (data.data.mode == 'peer' || data.data.mode == 'peerhelp'){
                    keys = daAllSessions(data.uid, data.i);
                  }
                  else{
                    keys = ['da:session:uid:' + data.uid + ':i:' + data.i + ':userid:' + data.userid];
                  }
                  for (var i = 0; i < keys.length; ++i){
                    key = keys[i];
                    var skey = key.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1');
                    //console.log("Received chat message for #chatarea" + skey);
                    var chatArea = $("#chatarea" + skey).find('ul').first();
                    var newLi = document.createElement('li');
                    $(newLi).addClass("list-group-item");
                    if (data.data.is_self){
                      $(newLi).addClass("list-group-item-primary dalistright");
                    }
                    else{
                      $(newLi).addClass("list-group-item-secondary dalistleft");
                    }
                    $(newLi).html(data.data.message);
                    $(newLi).appendTo(chatArea);
                    daScrollChat("#chatarea" + skey);
                    if (data.data.is_self){
                      $("#listelement" + skey).removeClass("da-new-message");
                      if (document.title != daBrowserTitle){
                        document.title = daBrowserTitle;
                        daFaviconRegular();
                      }
                    }
                    else{
                      if (!$("#chatarea" + skey).find('input').first().is(':focus')){
                        $("#listelement" + skey).addClass("da-new-message");
                        if (daBrowserTitle == document.title){
                          document.title = '* ' + daBrowserTitle;
                          daFaviconAlert();
                        }
                      }
                      if (data.data.hasOwnProperty('temp_user_id')){
                        daNotifyOperator(key, "chat", """ + json.dumps(word("anonymous visitor")) + """ + ' ' + data.data.temp_user_id + ': ' + data.data.message);
                      }
                      else{
                        if (data.data.first_name && data.data.first_name != ''){
                          daNotifyOperator(key, "chat", data.data.first_name + ' ' + data.data.last_name + ': ' + data.data.message);
                        }
                        else{
                          daNotifyOperator(key, "chat", data.data.email + ': ' + data.data.message);
                        }
                      }
                    }
                  }
              });
              daSocket.on('sessionupdate', function(data) {
                  //console.log("Got session update: " + data.session.chatstatus);
                  daDrawSession(data.key, data.session);
                  daCheckIfEmpty();
              });
              daSocket.on('updatemonitor', function(data) {
                  //console.log("Got update monitor response");
                  //console.log("updatemonitor: chat partners are: " + data.chatPartners);
                  daChatPartners = data.chatPartners;
                  daNewPhonePartners = Object();
                  daTermPhonePartners = Object();
                  daPhonePartners = data.phonePartners;
                  var newSubscribedRoles = Object();
                  for (var key in data.subscribedRoles){
                      if (data.subscribedRoles.hasOwnProperty(key)){
                          newSubscribedRoles[key] = 1;
                      }
                  }
                  for (var i = 0; i < data.availRoles.length; ++i){
                      var key = data.availRoles[i];
                      var skey = key.replace(/(:|\.|\[|\]|,|=|\/| )/g, '\\\\$1');
                      if ($("#role" + skey).length == 0){
                          var div = document.createElement('div');
                          $(div).addClass("form-check form-check-inline");
                          var label = document.createElement('label');
                          $(label).addClass('form-check-label');
                          $(label).attr('for', "role" + key);
                          var input = document.createElement('input');
                          $(input).addClass('form-check-input');
                          var text = document.createTextNode(key);
                          $(input).attr('type', 'checkbox');
                          $(input).attr('id', "role" + key);
                          if (key in newSubscribedRoles){
                              $(input).prop('checked', true);
                          }
                          else{
                              $(input).prop('checked', false);
                          }
                          $(input).val(key);
                          $(text).appendTo($(label));
                          $(input).appendTo($(div));
                          $(label).appendTo($(div));
                          $(div).appendTo($("#monitorroles"));
                          $(input).change(function(){
                              var key = $(this).val();
                              //console.log("change to " + key);
                              if ($(this).is(":checked")) {
                                  //console.log("it is checked");
                                  daSubscribedRoles[key] = 1;
                              }
                              else{
                                  //console.log("it is not checked");
                                  if (key in daSubscribedRoles){
                                      delete daSubscribedRoles[key];
                                  }
                              }
                              daUpdateMonitor();
                          });
                      }
                      else{
                          var input = $("#role" + skey).first();
                          if (key in newSubscribedRoles){
                              $(input).prop('checked', true);
                          }
                          else{
                              $(input).prop('checked', false);
                          }
                      }
                  }
                  daSubscribedRoles = newSubscribedRoles;
                  newDaSessions = Object();
                  for (var key in data.sessions){
                      if (data.sessions.hasOwnProperty(key)){
                          var user_id = key.replace(/^.*:userid:/, '');
                          if (true || user_id != daUserid){
                              var obj = data.sessions[key];
                              newDaSessions[key] = obj;
                              daDrawSession(key, obj);
                          }
                      }
                  }
                  var toDelete = Array();
                  var numSessions = 0;
                  for (var key in daSessions){
                      if (daSessions.hasOwnProperty(key)){
                          numSessions++;
                          if (!(key in newDaSessions)){
                              toDelete.push(key);
                          }
                      }
                  }
                  for (var i = 0; i < toDelete.length; ++i){
                      var key = toDelete[i];
                      daUndrawSession(key);
                  }
                  if ($("#monitorsessions").find("li").length > 0){
                      $("#emptylist").addClass("dainvisible");
                  }
                  else{
                      $("#emptylist").removeClass("dainvisible");
                  }
              });
          }
          if (daAvailableForChat){
              $("#daNotAvailable").addClass("dainvisible");
              daCheckNotifications();
          }
          else{
              $("#daAvailable").addClass("dainvisible");
          }
          $("#daAvailable").click(function(event){
              $("#daAvailable").addClass("dainvisible");
              $("#daNotAvailable").removeClass("dainvisible");
              daAvailableForChat = false;
              //console.log("daAvailableForChat: " + daAvailableForChat);
              daUpdateMonitor();
              daPlaySound('signinout');
          });
          $("#daNotAvailable").click(function(event){
              daCheckNotifications();
              $("#daNotAvailable").addClass("dainvisible");
              $("#daAvailable").removeClass("dainvisible");
              daAvailableForChat = true;
              //console.log("daAvailableForChat: " + daAvailableForChat);
              daUpdateMonitor();
              daPlaySound('signinout');
          });
          $( window ).bind('unload', function() {
            if (typeof daSocket !== 'undefined'){
              daSocket.emit('terminate');
            }
          });
          if (daUsePhone){
            $("#daPhoneInfo").removeClass("dainvisible");
            $("#daPhoneNumber").val(daPhoneNumber);
            $("#daPhoneNumber").change(daCheckPhone);
            $("#daPhoneNumber").bind('keypress keydown keyup', function(e){
              var theCode = e.which || e.keyCode;
              if(theCode == 13) { $(this).blur(); e.preventDefault(); }
            });
          }
          $(window).on('scroll', daOnScrollResize);
          $(window).on('resize', daOnScrollResize);
          $(".da-chat-notifier").click(function(e){
              //var key = $(this).data('key');
              var direction = 0;
              if ($(this).attr('id') == "chat-message-above"){
                  direction = -1;
              }
              else{
                  direction = 1;
              }
              var target = -1;
              var targetElement = null;
              for (var key in daUpdatedSessions){
                  if (daUpdatedSessions.hasOwnProperty(key)){
                      var top = $(key).offset().top;
                      if (direction == -1){
                          if (target == -1 || top < target){
                              target = top;
                              targetElement = key;
                          }
                      }
                      else{
                          if (target == -1 || top > target){
                              target = top;
                              targetElement = key;
                          }
                      }
                  }
              }
              if (target >= 0){
                  $("html, body").animate({scrollTop: target - 60}, 500, function(){
                      $(targetElement).find("input").first().focus();
                  });
              }
              e.preventDefault();
              return false;
          });
      });
    </script>"""
    response = make_response(
        render_template('pages/monitor.html', version_warning=None, bodyclass='daadminbody', extra_js=Markup(script),
                        tab_title=word('Monitor'), page_title=word('Monitor')), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@app.route('/config', methods=['GET', 'POST'])
@login_required
@roles_required(['admin'])
def config_page():
    setup_translation()
    form = ConfigForm(request.form)
    content = None
    ok = True
    if request.method == 'POST':
        if form.submit.data and form.config_content.data:
            try:
                yaml.load(form.config_content.data, Loader=yaml.FullLoader)
            except Exception as errMess:
                ok = False
                content = form.config_content.data
                errMess = word(
                    "Configuration not updated.  There was a syntax error in the configuration YAML.") + '<pre>' + str(
                    errMess) + '</pre>'
                flash(str(errMess), 'error')
                logmessage('config_page: ' + str(errMess))
            if ok:
                if cloud is not None:
                    key = cloud.get_key('config.yml')
                    key.set_contents_from_string(form.config_content.data)
                with open(daconfig['config file'], 'w', encoding='utf-8') as fp:
                    fp.write(form.config_content.data)
                    flash(word('The configuration file was saved.'), 'success')
                # session['restart'] = 1
                return redirect(url_for('util.restart_page'))
        elif form.cancel.data:
            flash(word('Configuration not updated.'), 'info')
            return redirect(url_for('interview.interview_list'))
        else:
            flash(word('Configuration not updated.  There was an error.'), 'error')
            return redirect(url_for('interview.interview_list'))
    if ok:
        with open(daconfig['config file'], 'r', encoding='utf-8') as fp:
            content = fp.read()
    if content is None:
        return ('File not found', 404)
    (disk_total, disk_used, disk_free) = shutil.disk_usage(daconfig['config file'])
    if keymap:
        kbOpt = 'keyMap: "' + keymap + '", cursorBlinkRate: 0, '
        kbLoad = '<script src="' + url_for('static', filename="codemirror/keymap/" + keymap + ".js",
                                           v=da_version) + '"></script>\n    '
    else:
        kbOpt = ''
        kbLoad = ''
    python_version = daconfig.get('python version', word('Unknown'))
    system_version = daconfig.get('system version', word('Unknown'))
    if python_version == system_version:
        version = word("Version ") + str(python_version)
    else:
        version = word("Version ") + str(python_version) + ' (Python); ' + str(system_version) + ' (' + word(
            'system') + ')'
    response = make_response(render_template('pages/config.html',
                                             underlying_python_version=re.sub(r' \(.*', '', sys.version,
                                                                              flags=re.DOTALL),
                                             free_disk_space=humanize.naturalsize(disk_free),
                                             config_errors=docassemble.base.config.errors,
                                             config_messages=docassemble.base.config.env_messages,
                                             version_warning=version_warning, version=version, bodyclass='daadminbody',
                                             tab_title=word('Configuration'), page_title=word('Configuration'),
                                             extra_css=Markup('\n    <link href="' + url_for('static',
                                                                                             filename='codemirror/lib/codemirror.css',
                                                                                             v=da_version) + '" rel="stylesheet">\n    <link href="' + url_for(
                                                 'static', filename='codemirror/addon/search/matchesonscrollbar.css',
                                                 v=da_version) + '" rel="stylesheet">\n    <link href="' + url_for(
                                                 'static', filename='codemirror/addon/display/fullscreen.css',
                                                 v=da_version) + '" rel="stylesheet">\n    <link href="' + url_for(
                                                 'static', filename='codemirror/addon/scroll/simplescrollbars.css',
                                                 v=da_version) + '" rel="stylesheet">\n    <link href="' + url_for(
                                                 'static', filename='app/pygments.min.css',
                                                 v=da_version) + '" rel="stylesheet">'), extra_js=Markup(
            '\n    <script src="' + url_for('static', filename="codemirror/lib/codemirror.js",
                                            v=da_version) + '"></script>\n    <script src="' + url_for('static',
                                                                                                       filename="codemirror/addon/search/searchcursor.js",
                                                                                                       v=da_version) + '"></script>\n    <script src="' + url_for(
                'static', filename="codemirror/addon/scroll/annotatescrollbar.js",
                v=da_version) + '"></script>\n    <script src="' + url_for('static',
                                                                           filename="codemirror/addon/search/matchesonscrollbar.js",
                                                                           v=da_version) + '"></script>\n    <script src="' + url_for(
                'static', filename="codemirror/addon/display/fullscreen.js",
                v=da_version) + '"></script>\n    <script src="' + url_for('static',
                                                                           filename="codemirror/addon/edit/matchbrackets.js",
                                                                           v=da_version) + '"></script>\n    <script src="' + url_for(
                'static', filename="codemirror/mode/yaml/yaml.js",
                v=da_version) + '"></script>\n    ' + kbLoad + '<script>\n      daTextArea=document.getElementById("config_content");\n      daTextArea.value = JSON.parse(atob("' + safeid(
                json.dumps(
                    content)) + '"));\n      var daCodeMirror = CodeMirror.fromTextArea(daTextArea, {mode: "yaml", ' + kbOpt + 'tabSize: 2, tabindex: 70, autofocus: true, lineNumbers: true, matchBrackets: true});\n      daCodeMirror.setOption("extraKeys", { Tab: function(cm) { var spaces = Array(cm.getOption("indentUnit") + 1).join(" "); cm.replaceSelection(spaces); }, "F11": function(cm) { cm.setOption("fullScreen", !cm.getOption("fullScreen")); }, "Esc": function(cm) { if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false); }});\n      daCodeMirror.setOption("coverGutterNextToScrollbar", true);\n    </script>'),
                                             form=form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@app.route('/view_source', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def view_source():
    setup_translation()
    source_path = request.args.get('i', None)
    current_project = get_current_project()
    if source_path is None:
        logmessage("view_source: no source path")
        return ('File not found', 404)
    try:
        if re.search(r':', source_path):
            source = docassemble.base.parse.interview_source_from_string(source_path)
        else:
            try:
                source = docassemble.base.parse.interview_source_from_string(
                    'docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + source_path)
            except:
                source = docassemble.base.parse.interview_source_from_string(source_path)
    except Exception as errmess:
        logmessage("view_source: no source: " + str(errmess))
        return ('File not found', 404)
    header = source_path
    response = make_response(
        render_template('pages/view_source.html', version_warning=None, bodyclass='daadminbody', tab_title="Source",
                        page_title="Source", extra_css=Markup(
                '\n    <link href="' + url_for('static', filename='app/pygments.min.css') + '" rel="stylesheet">'),
                        header=header, contents=Markup(
                highlight(source.content, YamlLexer(), HtmlFormatter(cssclass="highlight dafullheight")))), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def get_branches_of_repo(giturl):
    repo_name = re.sub(r'/*$', '', giturl)
    m = re.search(r'//(.+):x-oauth-basic@github.com', repo_name)
    if m:
        access_token = m.group(1)
    else:
        access_token = None
    repo_name = re.sub(r'^http.*github.com/', '', repo_name)
    repo_name = re.sub(r'.*@github.com:', '', repo_name)
    repo_name = re.sub(r'.git$', '', repo_name)
    if app.config['USE_GITHUB']:
        github_auth = r.get('da:using_github:userid:' + str(current_user.id))
    else:
        github_auth = None
    if github_auth and access_token is None:
        storage = RedisCredStorage(app='github')
        credentials = storage.get()
        if not credentials or credentials.invalid:
            http = httplib2.Http()
        else:
            http = credentials.authorize(httplib2.Http())
    else:
        http = httplib2.Http()
    the_url = "https://api.github.com/repos/" + repo_name + '/branches'
    branches = []
    if access_token:
        resp, content = http.request(the_url, "GET", headers=dict(Authorization="token " + access_token))
    else:
        resp, content = http.request(the_url, "GET")
    if int(resp['status']) == 200:
        branches.extend(json.loads(content.decode()))
        while True:
            next_link = get_next_link(resp)
            if next_link:
                if access_token:
                    resp, content = http.request(next_link, "GET", headers=dict(Authorization="token " + access_token))
                else:
                    resp, content = http.request(next_link, "GET")
                if int(resp['status']) != 200:
                    raise Exception(repo_name + " fetch failed")
                else:
                    branches.extend(json.loads(content.decode()))
            else:
                break
        return branches
    raise Exception(the_url + " fetch failed on first try; got " + str(resp['status']))


@app.errorhandler(404)
def page_not_found_error(the_error):
    return render_template('pages/404.html'), 404


@app.errorhandler(Exception)
def server_error(the_error):
    setup_translation()
    if hasattr(the_error, 'interview') and the_error.interview.debug and hasattr(the_error, 'interview_status'):
        the_history = get_history(the_error.interview, the_error.interview_status)
    else:
        the_history = None
    the_vars = None
    if the_logger is not None:
        the_logger.error("Page failed to load", exc_info=the_error)
    else:
        if isinstance(the_error, DAError):
            errmess = str(the_error)
            the_trace = None
            logmessage(errmess)
        elif isinstance(the_error, TemplateError):
            errmess = str(the_error)
            if hasattr(the_error, 'name') and the_error.name is not None:
                errmess += "\nName: " + str(the_error.name)
            if hasattr(the_error, 'filename') and the_error.filename is not None:
                errmess += "\nFilename: " + str(the_error.filename)
            if hasattr(the_error, 'docx_context'):
                errmess += "\n\nContext:\n" + "\n".join(map(lambda x: "  " + x, the_error.docx_context))
            the_trace = traceback.format_exc()
            try:
                logmessage(errmess)
            except:
                logmessage("Could not log the error message")
        else:
            try:
                errmess = str(type(the_error).__name__) + ": " + str(the_error)
            except:
                errmess = str(type(the_error).__name__)
            if hasattr(the_error, 'traceback'):
                the_trace = the_error.traceback
            else:
                the_trace = traceback.format_exc()
            if hasattr(docassemble.base.functions.this_thread,
                       'misc') and 'current_field' in docassemble.base.functions.this_thread.misc:
                errmess += "\nIn field index number " + str(docassemble.base.functions.this_thread.misc['current_field'])
            if hasattr(the_error, 'da_line_with_error'):
                errmess += "\nIn line: " + str(the_error.da_line_with_error)

            logmessage(the_trace)
    if isinstance(the_error, DAError):
        error_code = the_error.error_code
    elif isinstance(the_error, werkzeug.exceptions.HTTPException):
        error_code = the_error.code
    else:
        error_code = 501
    if hasattr(the_error, 'user_dict'):
        the_vars = the_error.user_dict
    if hasattr(the_error, 'interview'):
        special_error_markdown = the_error.interview.consolidated_metadata.get('error help', None)
        if isinstance(special_error_markdown, dict):
            language = docassemble.base.functions.get_language()
            if language in special_error_markdown:
                special_error_markdown = special_error_markdown[language]
            elif '*' in special_error_markdown:
                special_error_markdown = special_error_markdown['*']
            elif DEFAULT_LANGUAGE in special_error_markdown:
                special_error_markdown = special_error_markdown[DEFAULT_LANGUAGE]
            else:
                special_error_markdown = None
    else:
        special_error_markdown = None
    if special_error_markdown is None:
        special_error_markdown = daconfig.get('error help', None)
    if special_error_markdown is not None:
        special_error_html = docassemble.base.util.markdown_to_html(special_error_markdown)
    else:
        special_error_html = None
    flask_logtext = []
    if os.path.exists(LOGFILE):
        with open(LOGFILE, encoding='utf-8') as the_file:
            for line in the_file:
                if re.match('Exception', line):
                    flask_logtext = []
                flask_logtext.append(line)
    orig_errmess = errmess
    errmess = noquote(errmess)
    if re.search(r'\n', errmess):
        errmess = '<pre>' + errmess + '</pre>'
    else:
        errmess = '<blockquote class="blockquote">' + errmess + '</blockquote>'
    script = """
    <script>
      var daGlobalEval = eval;
      var daMessageLog = JSON.parse(atob(""" + json.dumps(
        safeid(json.dumps(docassemble.base.functions.get_message_log()))) + """));
      function flash(message, priority){
        if (priority == null){
          priority = 'info'
        }
        if (!$("#daflash").length){
          $(daTargetDiv).append('<div class="datopcenter col-sm-7 col-md-6 col-lg-5" id="daflash"></div>');
        }
        $("#daflash").append('<div class="da-alert alert alert-' + priority + ' daalert-interlocutory alert-dismissible fade show" role="alert">' + message + '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"><\/button><\/div>');
        if (priority == 'success'){
          setTimeout(function(){
            $("#daflash .alert-success").hide(300, function(){
              $(self).remove();
            });
          }, 3000);
        }
      }
      var da_flash = flash;
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
      $( document ).ready(function() {
        $("#da-retry").on('click', function(e){
          location.reload();
          e.preventDefault();
          return false;
        });
        daShowNotifications();
      });
    </script>"""
    error_notification(the_error, message=errmess, history=the_history, trace=the_trace, the_request=request,
                       the_vars=the_vars)
    if (request.path.endswith('/interview') or request.path.endswith('/start') or request.path.endswith(
            '/run')) and 'in error' not in session and docassemble.base.functions.this_thread.interview is not None and 'error action' in docassemble.base.functions.this_thread.interview.consolidated_metadata and docassemble.base.functions.interview_path() is not None:
        session['in error'] = True
        return index(action_argument={
            'action': docassemble.base.functions.this_thread.interview.consolidated_metadata['error action'],
            'arguments': dict(error_message=orig_errmess)}, refer=['error'])
    show_debug = not bool((not DEBUG) and isinstance(the_error, DAError))
    if int(int(error_code) / 100) == 4:
        show_debug = False
    if error_code == 404:
        the_template = 'pages/404.html'
    else:
        the_template = 'pages/501.html'
    try:
        yaml_filename = docassemble.base.functions.interview_path()
    except:
        yaml_filename = None
    show_retry = request.path.endswith('/interview') or request.path.endswith('/start') or request.path.endswith('/run')
    return render_template(the_template, verbose=daconfig.get('verbose error messages', True), version_warning=None,
                           tab_title=word("Error"), page_title=word("Error"), error=errmess,
                           historytext=str(the_history), logtext=str(the_trace), extra_js=Markup(script),
                           special_error=special_error_html, show_debug=show_debug, yaml_filename=yaml_filename,
                           show_retry=show_retry), error_code


@app.route('/reqdev', methods=['GET', 'POST'])
@login_required
def request_developer():
    setup_translation()
    if not app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    form = RequestDeveloperForm(request.form)
    recipients = []
    if request.method == 'POST':
        for user in db.session.execute(
                select(UserModel.id, UserModel.email).join(UserRoles, UserModel.id == UserRoles.user_id).join(Role,
                                                                                                              UserRoles.role_id == Role.id).where(
                    and_(UserModel.active == True, Role.name == 'admin'))):
            if user.email not in recipients:
                recipients.append(user.email)
        body = "User " + str(current_user.email) + " (" + str(
            current_user.id) + ") has requested developer privileges.\n\n"
        if form.reason.data:
            body += "Reason given: " + str(form.reason.data) + "\n\n"
        body += "Go to " + url_for('edit_user_profile_page', id=current_user.id,
                                   _external=True) + " to change the user's privileges."
        msg = Message("Request for developer account from " + str(current_user.email), recipients=recipients, body=body)
        if len(recipients) == 0:
            flash(word('No administrators could be found.'), 'error')
        else:
            try:
                da_send_mail(msg)
                flash(word('Your request was submitted.'), 'success')
            except:
                flash(word('We were unable to submit your request.'), 'error')
        return redirect(url_for('user.profile'))
    return render_template('users/request_developer.html', version_warning=None, bodyclass='daadminbody',
                           tab_title=word("Developer Access"), page_title=word("Developer Access"), form=form)


def docx_variable_fix(variable):
    variable = re.sub(r'\\', '', variable)
    variable = re.sub(r'^([A-Za-z\_][A-Za-z\_0-9]*).*', r'\1', variable)
    return variable


def sanitize(default):
    default = re.sub(r'\n?\r\n?', "\n", str(default))
    if re.search(r'[\#\!\?\:\n\r\"\'\[\]\{\}]+', default):
        return "|\n" + docassemble.base.functions.indent(default, by=10)
    return default


def read_fields(filename, orig_file_name, input_format, output_format):
    if output_format == 'yaml':
        if input_format == 'pdf':
            fields = docassemble.base.pdftk.read_fields(filename)
            fields_seen = set()
            if fields is None:
                raise Exception(word("Error: no fields could be found in the file"))
            fields_output = "---\nquestion: " + word(
                "Here is your document.") + "\nevent: " + 'some_event' + "\nattachment:" + "\n  - name: " + \
                            os.path.splitext(orig_file_name)[0] + "\n    filename: " + os.path.splitext(orig_file_name)[
                                0] + "\n    pdf template file: " + re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_',
                                                                          orig_file_name) + "\n    fields:\n"
            for field, default, pageno, rect, field_type, export_value in fields:
                if field not in fields_seen:
                    fields_output += '      - "' + str(field) + '": ' + sanitize(default) + "\n"
                    fields_seen.add(field)
            fields_output += "---"
            return fields_output
        if input_format == 'docx' or input_format == 'markdown':
            if input_format == 'docx':
                result_file = word_to_markdown(filename, 'docx')
                if result_file is None:
                    raise Exception(word("Error: no fields could be found in the file"))
                with open(result_file.name, 'r', encoding='utf-8') as fp:
                    result = fp.read()
            elif input_format == 'markdown':
                with open(filename, 'r', encoding='utf-8') as fp:
                    result = fp.read()
            fields = set()
            for variable in re.findall(r'{{[pr] \s*([^\}\s]+)\s*}}', result):
                fields.add(docx_variable_fix(variable))
            for variable in re.findall(r'{{\s*([^\}\s]+)\s*}}', result):
                fields.add(docx_variable_fix(variable))
            for variable in re.findall(r'{%[a-z]* for [A-Za-z\_][A-Za-z0-9\_]* in *([^\} ]+) *%}', result):
                fields.add(docx_variable_fix(variable))
            if len(fields) == 0:
                raise Exception(word("Error: no fields could be found in the file"))
            fields_output = "---\nquestion: " + word(
                "Here is your document.") + "\nevent: " + 'some_event' + "\nattachment:" + "\n  - name: " + \
                            os.path.splitext(orig_file_name)[0] + "\n    filename: " + os.path.splitext(orig_file_name)[
                                0] + "\n    docx template file: " + re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_',
                                                                           orig_file_name) + "\n    fields:\n"
            for field in fields:
                fields_output += '      "' + field + '": ' + "Something\n"
            fields_output += "---"
            return fields_output
    if output_format == 'json':
        if input_format == 'pdf':
            default_text = word("something")
            output = dict(fields=[], default_values={}, types={}, locations={}, export_values={})
            fields = docassemble.base.pdftk.read_fields(filename)
            if fields is not None:
                fields_seen = set()
                for field, default, pageno, rect, field_type, export_value in fields:
                    real_default = str(default)
                    if real_default == default_text:
                        real_default = ''
                    if field not in fields_seen:
                        output['fields'].append(str(field))
                        output['default_values'][field] = real_default
                        output['types'][field] = re.sub(r"'", r'', str(field_type))
                        output['locations'][field] = dict(page=int(pageno), box=rect)
                        output['export_values'][field] = export_value
            return json.dumps(output, sort_keys=True, indent=2)
        if input_format == 'docx' or input_format == 'markdown':
            if input_format == 'docx':
                result_file = word_to_markdown(filename, 'docx')
                if result_file is None:
                    return json.dumps(dict(fields=[]), indent=2)
                with open(result_file.name, 'r', encoding='utf-8') as fp:
                    result = fp.read()
            elif input_format == 'markdown':
                with open(filename, 'r', encoding='utf-8') as fp:
                    result = fp.read()
            fields = set()
            for variable in re.findall(r'{{ *([^\} ]+) *}}', result):
                fields.add(docx_variable_fix(variable))
            for variable in re.findall(r'{%[a-z]* for [A-Za-z\_][A-Za-z0-9\_]* in *([^\} ]+) *%}', result):
                fields.add(docx_variable_fix(variable))
            return json.dumps(dict(fields=list(fields)), sort_keys=True, indent=2)


@app.route('/utilities', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def utilities():
    setup_translation()
    form = Utilities(request.form)
    fields_output = None
    word_box = None
    uses_null = False
    file_type = None
    if request.method == 'GET' and needs_to_change_password():
        return redirect(url_for('user.change_password', next=url_for('utilities')))
    if request.method == 'POST':
        if 'language' in request.form:
            language = request.form['language']
            result = {}
            result[language] = {}
            existing = docassemble.base.functions.word_collection.get(language, {})
            if 'google' in daconfig and 'api key' in daconfig['google'] and daconfig['google']['api key']:
                try:
                    service = googleapiclient.discovery.build('translate', 'v2',
                                                              developerKey=daconfig['google']['api key'])
                    use_google_translate = True
                except:
                    logmessage("utilities: attempt to call Google Translate failed")
                    use_google_translate = False
            else:
                use_google_translate = False
            words_to_translate = []
            for the_word in base_words:
                if the_word in existing and existing[the_word] is not None:
                    result[language][the_word] = existing[the_word]
                    continue
                words_to_translate.append(the_word)
            chunk_limit = daconfig.get('google translate words at a time', 20)
            chunks = []
            interim_list = []
            while len(words_to_translate):
                the_word = words_to_translate.pop(0)
                interim_list.append(the_word)
                if len(interim_list) >= chunk_limit:
                    chunks.append(interim_list)
                    interim_list = []
            if len(interim_list) > 0:
                chunks.append(interim_list)
            for chunk in chunks:
                if use_google_translate:
                    try:
                        resp = service.translations().list(
                            source='en',
                            target=language,
                            q=chunk
                        ).execute()
                    except Exception as errstr:
                        logmessage("utilities: translation failed: " + str(errstr))
                        resp = None
                    if isinstance(resp, dict) and 'translations' in resp and isinstance(resp['translations'],
                                                                                        list) and len(
                        resp['translations']) == len(chunk):
                        for index in range(len(chunk)):
                            if isinstance(resp['translations'][index], dict) and 'translatedText' in \
                                    resp['translations'][index]:
                                result[language][chunk[index]] = re.sub(r'&#39;', r"'", str(
                                    resp['translations'][index]['translatedText']))
                            else:
                                result[language][chunk[index]] = 'XYZNULLXYZ'
                                uses_null = True
                    else:
                        for the_word in chunk:
                            result[language][the_word] = 'XYZNULLXYZ'
                        uses_null = True
                else:
                    for the_word in chunk:
                        result[language][the_word] = 'XYZNULLXYZ'
                    uses_null = True
            if form.systemfiletype.data == 'YAML':
                word_box = ruamel.yaml.safe_dump(result, default_flow_style=False, default_style='"',
                                                 allow_unicode=True, width=1000)
                word_box = re.sub(r'"XYZNULLXYZ"', r'null', word_box)
            elif form.systemfiletype.data == 'XLSX':
                temp_file = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
                xlsx_filename = language + "-words.xlsx"
                workbook = xlsxwriter.Workbook(temp_file.name)
                worksheet = workbook.add_worksheet()
                bold = workbook.add_format({'bold': 1, 'num_format': '@'})
                text = workbook.add_format({'num_format': '@'})
                text.set_align('top')
                wrapping = workbook.add_format({'num_format': '@'})
                wrapping.set_align('top')
                wrapping.set_text_wrap()
                # wrapping.set_locked(False)
                numb = workbook.add_format()
                numb.set_align('top')
                worksheet.write('A1', 'orig_lang', bold)
                worksheet.write('B1', 'tr_lang', bold)
                worksheet.write('C1', 'orig_text', bold)
                worksheet.write('D1', 'tr_text', bold)
                worksheet.set_column(0, 0, 10)
                worksheet.set_column(1, 1, 10)
                worksheet.set_column(2, 2, 55)
                worksheet.set_column(3, 3, 55)
                row = 1
                for key, val in result[language].items():
                    worksheet.write_string(row, 0, 'en', text)
                    worksheet.write_string(row, 1, language, text)
                    worksheet.write_string(row, 2, key, wrapping)
                    worksheet.write_string(row, 3, val, wrapping)
                    row += 1
                workbook.close()
                response = send_file(temp_file.name,
                                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                     as_attachment=True, attachment_filename=xlsx_filename)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            elif form.systemfiletype.data == 'XLIFF 1.2':
                temp_file = tempfile.NamedTemporaryFile(suffix='.xlf', delete=False)
                xliff_filename = language + "-words.xlf"
                xliff = ET.Element('xliff')
                xliff.set('xmlns', 'urn:oasis:names:tc:xliff:document:1.2')
                xliff.set('version', '1.2')
                the_file = ET.SubElement(xliff, 'file')
                the_file.set('source-language', 'en')
                the_file.set('target-language', language)
                the_file.set('datatype', 'plaintext')
                the_file.set('original', 'self')
                the_file.set('id', 'f1')
                the_file.set('xml:space', 'preserve')
                body = ET.SubElement(the_file, 'body')
                indexno = 1
                for key, val in result[language].items():
                    trans_unit = ET.SubElement(body, 'trans-unit')
                    trans_unit.set('id', str(indexno))
                    trans_unit.set('xml:space', 'preserve')
                    source = ET.SubElement(trans_unit, 'source')
                    source.set('xml:space', 'preserve')
                    target = ET.SubElement(trans_unit, 'target')
                    target.set('xml:space', 'preserve')
                    source.text = key
                    target.text = val
                    indexno += 1
                temp_file.write(ET.tostring(xliff))
                temp_file.close()
                response = send_file(temp_file.name, mimetype='application/xml', as_attachment=True,
                                     attachment_filename=xliff_filename)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            elif form.systemfiletype.data == 'XLIFF 2.0':
                temp_file = tempfile.NamedTemporaryFile(suffix='.xlf', delete=False)
                xliff_filename = language + "-words.xlf"
                xliff = ET.Element('xliff')
                xliff.set('xmlns', 'urn:oasis:names:tc:xliff:document:2.0')
                xliff.set('version', '2.0')
                xliff.set('srcLang', 'en')
                xliff.set('trgLang', language)
                file_index = 1
                the_file = ET.SubElement(xliff, 'file')
                the_file.set('id', 'f1')
                the_file.set('original', 'self')
                the_file.set('xml:space', 'preserve')
                unit = ET.SubElement(the_file, 'unit')
                unit.set('id', "docassemble_phrases")
                indexno = 1
                for key, val in result[language].items():
                    segment = ET.SubElement(unit, 'segment')
                    segment.set('id', str(indexno))
                    segment.set('xml:space', 'preserve')
                    source = ET.SubElement(segment, 'source')
                    source.set('xml:space', 'preserve')
                    target = ET.SubElement(segment, 'target')
                    target.set('xml:space', 'preserve')
                    source.text = key
                    target.text = val
                    indexno += 1
                temp_file.write(ET.tostring(xliff))
                temp_file.close()
                response = send_file(temp_file.name, mimetype='application/xml', as_attachment=True,
                                     attachment_filename=xliff_filename)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
        if 'pdfdocxfile' in request.files and request.files['pdfdocxfile'].filename:
            filename = secure_filename(request.files['pdfdocxfile'].filename)
            extension, mimetype = get_ext_and_mimetype(filename)
            if mimetype == 'application/pdf':
                file_type = 'pdf'
                pdf_file = tempfile.NamedTemporaryFile(mode="wb", suffix=".pdf", delete=True)
                the_file = request.files['pdfdocxfile']
                the_file.save(pdf_file.name)
                try:
                    fields_output = read_fields(pdf_file.name, the_file.filename, 'pdf', 'yaml')
                except Exception as err:
                    fields_output = str(err)
                pdf_file.close()
            elif mimetype == 'application/vnd.openxmlformats-officedocument.wordprocessingml.document':
                file_type = 'docx'
                docx_file = tempfile.NamedTemporaryFile(mode="wb", suffix=".docx", delete=True)
                the_file = request.files['pdfdocxfile']
                the_file.save(docx_file.name)
                try:
                    fields_output = read_fields(docx_file.name, the_file.filename, 'docx', 'yaml')
                except Exception as err:
                    fields_output = str(err)
                docx_file.close()
        if form.officeaddin_submit.data:
            resp = make_response(
                render_template('pages/officemanifest.xml', office_app_version=form.officeaddin_version.data,
                                guid=str(uuid.uuid4())))
            resp.headers['Content-type'] = 'text/xml; charset=utf-8'
            resp.headers['Content-Disposition'] = 'attachment; filename="manifest.xml"'
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            return resp
    extra_js = """
    <script>
      $('#pdfdocxfile').on('change', function(){
        var fileName = $(this).val();
        fileName = fileName.replace(/.*\\\\/, '');
        fileName = fileName.replace(/.*\\//, '');
        $(this).next('.custom-file-label').html(fileName);
      });
    </script>"""
    form.systemfiletype.choices = [('YAML', 'YAML'), ('XLSX', 'XLSX'), ('XLIFF 1.2', 'XLIFF 1.2'),
                                   ('XLIFF 2.0', 'XLIFF 2.0')]
    form.systemfiletype.data = 'YAML'
    form.filetype.choices = [('XLSX', 'XLSX'), ('XLIFF 1.2', 'XLIFF 1.2'), ('XLIFF 2.0', 'XLIFF 2.0')]
    form.filetype.data = 'XLSX'
    response = make_response(
        render_template('pages/utilities.html', extra_js=Markup(extra_js), version_warning=version_warning,
                        bodyclass='daadminbody', tab_title=word("Utilities"), page_title=word("Utilities"), form=form,
                        fields=fields_output, word_box=word_box, uses_null=uses_null, file_type=file_type,
                        interview_placeholder=word("E.g., docassemble.demo:data/questions/questions.yml"),
                        language_placeholder=word("E.g., es, fr, it")), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


# @app.route('/save', methods=['GET', 'POST'])
# def save_for_later():
#     if current_user.is_authenticated and not current_user.is_anonymous:
#         return render_template('pages/save_for_later.html', interview=sdf)
#     secret = request.cookies.get('secret', None)

@app.route('/after_reset', methods=['GET', 'POST'])
def after_reset():
    # logmessage("after_reset")
    response = redirect(url_for('user.login'))
    if 'newsecret' in session:
        # logmessage("after_reset: fixing cookie")
        response.set_cookie('secret', session['newsecret'], httponly=True, secure=app.config['SESSION_COOKIE_SECURE'],
                            samesite=app.config['SESSION_COOKIE_SAMESITE'])
        del session['newsecret']
    return response


# @app.before_request
# def reset_thread_local():
#     docassemble.base.functions.reset_thread_local()

# @app.after_request
# def remove_temporary_files(response):
#     docassemble.base.functions.close_files()
#     return response


def fix_group_id(the_package, the_file, the_group_id):
    if the_package == '_global':
        group_id_to_use = the_group_id
    else:
        group_id_to_use = the_package
        if re.search(r'^data/', the_file):
            group_id_to_use += ':' + the_file
        else:
            group_id_to_use += ':data/sources/ml-' + the_file + '.json'
        group_id_to_use += ':' + the_group_id
    return group_id_to_use


def get_corresponding_interview(the_package, the_file):
    # logmessage("get_corresponding_interview: " + the_package + " " + the_file)
    interview = None
    if re.match(r'docassemble.playground[0-9]+', the_package):
        separator = ':'
    else:
        separator = ':data/questions/'
    for interview_file in (the_package + separator + the_file + '.yml', the_package + separator + the_file + '.yaml',
                           the_package + separator + 'examples/' + the_file + '.yml'):
        # logmessage("Looking for " + interview_file)
        try:
            interview = docassemble.base.interview_cache.get_interview(interview_file)
            break
        except Exception as the_err:
            # logmessage("There was an exception looking for " + interview_file + ": " + str(the_err))
            continue
    return interview


def ml_prefix(the_package, the_file):
    the_prefix = the_package
    if re.search(r'^data/', the_file):
        the_prefix += ':' + the_file
    else:
        the_prefix += ':data/sources/ml-' + the_file + '.json'
    return the_prefix


@app.route('/train', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer', 'trainer'])
def train():
    setup_translation()
    the_package = request.args.get('package', None)
    if the_package is not None:
        if the_package.startswith('_'):
            the_package = '_' + werkzeug.utils.secure_filename(the_package)
        else:
            the_package = werkzeug.utils.secure_filename(the_package)
    the_file = request.args.get('file', None)
    if the_file is not None:
        if the_file.startswith('_'):
            the_file = '_' + secure_filename_spaces_ok(the_file)
        else:
            the_file = secure_filename_spaces_ok(the_file)
    the_group_id = request.args.get('group_id', None)
    show_all = int(request.args.get('show_all', 0))
    form = TrainingForm(request.form)
    uploadform = TrainingUploadForm(request.form)
    if request.method == 'POST' and the_package is not None and the_file is not None:
        if the_package == '_global':
            the_prefix = ''
        else:
            the_prefix = ml_prefix(the_package, the_file)
        json_file = None
        if the_package != '_global' and uploadform.usepackage.data == 'yes':
            the_file = docassemble.base.functions.package_data_filename(the_prefix)
            if the_file is None or not os.path.isfile(the_file):
                flash(word("Error reading JSON file from package.  File did not exist."), 'error')
                return redirect(
                    url_for('train', package=the_package, file=the_file, group_id=the_group_id, show_all=show_all))
            json_file = open(the_file, 'r', encoding='utf-8')
        if uploadform.usepackage.data == 'no' and 'jsonfile' in request.files and request.files['jsonfile'].filename:
            json_file = tempfile.NamedTemporaryFile(prefix="datemp", suffix=".json")
            request.files['jsonfile'].save(json_file.name)
            json_file.seek(0)
        if json_file is not None:
            try:
                href = json.load(json_file)
            except:
                flash(word("Error reading JSON file.  Not a valid JSON file."), 'error')
                return redirect(
                    url_for('train', package=the_package, file=the_file, group_id=the_group_id, show_all=show_all))
            json_file.close()
            if not isinstance(href, dict):
                flash(word("Error reading JSON file.  The JSON file needs to contain a dictionary at the root level."),
                      'error')
                return redirect(
                    url_for('train', package=the_package, file=the_file, group_id=the_group_id, show_all=show_all))
            nowtime = datetime.datetime.utcnow()
            for group_id, train_list in href.items():
                if not isinstance(train_list, list):
                    logmessage("train: could not import part of JSON file.  Items in dictionary must be lists.")
                    continue
                if uploadform.importtype.data == 'replace':
                    db.session.execute(delete(MachineLearning).filter_by(group_id=the_prefix + ':' + group_id))
                    db.session.commit()
                    for entry in train_list:
                        if 'independent' in entry:
                            depend = entry.get('dependent', None)
                            if depend is not None:
                                new_entry = MachineLearning(group_id=the_prefix + ':' + group_id,
                                                            independent=codecs.encode(
                                                                pickle.dumps(entry['independent']), 'base64').decode(),
                                                            dependent=codecs.encode(pickle.dumps(depend),
                                                                                    'base64').decode(), modtime=nowtime,
                                                            create_time=nowtime, active=True,
                                                            key=entry.get('key', None))
                            else:
                                new_entry = MachineLearning(group_id=the_prefix + ':' + group_id,
                                                            independent=codecs.encode(
                                                                pickle.dumps(entry['independent']), 'base64').decode(),
                                                            modtime=nowtime, create_time=nowtime, active=False,
                                                            key=entry.get('key', None))
                            db.session.add(new_entry)
                elif uploadform.importtype.data == 'merge':
                    indep_in_use = set()
                    for record in db.session.execute(
                            select(MachineLearning).filter_by(group_id=the_prefix + ':' + group_id)).scalars():
                        indep = fix_pickle_obj(codecs.decode(bytearray(record.independent, encoding='utf-8'), 'base64'))
                        if indep is not None:
                            indep_in_use.add(indep)
                    for entry in train_list:
                        if 'independent' in entry and entry['independent'] not in indep_in_use:
                            depend = entry.get('dependent', None)
                            if depend is not None:
                                new_entry = MachineLearning(group_id=the_prefix + ':' + group_id,
                                                            independent=codecs.encode(
                                                                pickle.dumps(entry['independent']), 'base64').decode(),
                                                            dependent=codecs.encode(pickle.dumps(depend),
                                                                                    'base64').decode(), modtime=nowtime,
                                                            create_time=nowtime, active=True,
                                                            key=entry.get('key', None))
                            else:
                                new_entry = MachineLearning(group_id=the_prefix + ':' + group_id,
                                                            independent=codecs.encode(
                                                                pickle.dumps(entry['independent']), 'base64').decode(),
                                                            modtime=nowtime, create_time=nowtime, active=False,
                                                            key=entry.get('key', None))
                            db.session.add(new_entry)
            db.session.commit()
            flash(word("Training data were successfully imported."), 'success')
            return redirect(
                url_for('train', package=the_package, file=the_file, group_id=the_group_id, show_all=show_all))
        if form.cancel.data:
            return redirect(url_for('train', package=the_package, file=the_file, show_all=show_all))
        if form.submit.data:
            group_id_to_use = fix_group_id(the_package, the_file, the_group_id)
            post_data = request.form.copy()
            deleted = set()
            for key, val in post_data.items():
                m = re.match(r'delete([0-9]+)', key)
                if not m:
                    continue
                entry_id = int(m.group(1))
                model = docassemble.base.util.SimpleTextMachineLearner(group_id=group_id_to_use)
                model.delete_by_id(entry_id)
                deleted.add('dependent' + m.group(1))
            for key in deleted:
                if key in post_data:
                    del post_data[key]
            for key, val in post_data.items():
                m = re.match(r'dependent([0-9]+)', key)
                if not m:
                    continue
                orig_key = 'original' + m.group(1)
                delete_key = 'delete' + m.group(1)
                if orig_key in post_data and post_data[orig_key] != val and val != '':
                    entry_id = int(m.group(1))
                    model = docassemble.base.util.SimpleTextMachineLearner(group_id=group_id_to_use)
                    model.set_dependent_by_id(entry_id, val)
            if post_data.get('newindependent', '') != '':
                model = docassemble.base.util.SimpleTextMachineLearner(group_id=group_id_to_use)
                if post_data.get('newdependent', '') != '':
                    model.add_to_training_set(post_data['newindependent'], post_data['newdependent'])
                else:
                    model.save_for_classification(post_data['newindependent'])
            return redirect(
                url_for('train', package=the_package, file=the_file, group_id=the_group_id, show_all=show_all))
    if show_all:
        show_all = 1
        show_cond = MachineLearning.id != None
    else:
        show_all = 0
        show_cond = MachineLearning.dependent == None
    package_list = {}
    file_list = {}
    group_id_list = {}
    entry_list = []
    if current_user.has_role('admin', 'developer'):
        playground_package = 'docassemble.playground' + str(current_user.id)
    else:
        playground_package = None
    if the_package is None:
        for record in db.session.execute(
                select(MachineLearning.group_id, db.func.count(MachineLearning.id).label('cnt')).where(
                    show_cond).group_by(MachineLearning.group_id)):
            group_id = record.group_id
            parts = group_id.split(':')
            if is_package_ml(parts):
                if parts[0] not in package_list:
                    package_list[parts[0]] = 0
                package_list[parts[0]] += record.cnt
            else:
                if '_global' not in package_list:
                    package_list['_global'] = 0
                package_list['_global'] += record.cnt
        if not show_all:
            for record in db.session.execute(select(MachineLearning.group_id).group_by(MachineLearning.group_id)):
                parts = record.group_id.split(':')
                if is_package_ml(parts):
                    if parts[0] not in package_list:
                        package_list[parts[0]] = 0
            if '_global' not in package_list:
                package_list['_global'] = 0
        if playground_package and playground_package not in package_list:
            package_list[playground_package] = 0
        package_list = [(x, package_list[x]) for x in sorted(package_list)]
        response = make_response(
            render_template('pages/train.html', version_warning=version_warning, bodyclass='daadminbody',
                            tab_title=word("Train"), page_title=word("Train machine learning models"),
                            the_package=the_package, the_file=the_file, the_group_id=the_group_id,
                            package_list=package_list, file_list=file_list, group_id_list=group_id_list,
                            entry_list=entry_list, show_all=show_all, show_package_list=True,
                            playground_package=playground_package), 200)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    if playground_package and the_package == playground_package:
        the_package_display = word("My Playground")
    else:
        the_package_display = the_package
    if the_file is None:
        file_list = {}
        for record in db.session.execute(
                select(MachineLearning.group_id, db.func.count(MachineLearning.id).label('cnt')).where(
                    and_(MachineLearning.group_id.like(the_package + ':%'), show_cond)).group_by(
                    MachineLearning.group_id)):
            parts = record.group_id.split(':')
            # logmessage("Group id is " + str(parts))
            if not is_package_ml(parts):
                continue
            if re.match(r'data/sources/ml-.*\.json$', parts[1]):
                parts[1] = re.sub(r'^data/sources/ml-|\.json$', '', parts[1])
            if parts[1] not in file_list:
                file_list[parts[1]] = 0
            file_list[parts[1]] += record.cnt
        if not show_all:
            for record in db.session.execute(
                    select(MachineLearning.group_id).where(MachineLearning.group_id.like(the_package + ':%')).group_by(
                        MachineLearning.group_id)):
                parts = record.group_id.split(':')
                # logmessage("Other group id is " + str(parts))
                if not is_package_ml(parts):
                    continue
                if re.match(r'data/sources/ml-.*\.json$', parts[1]):
                    parts[1] = re.sub(r'^data/sources/ml-|\.json$', '', parts[1])
                if parts[1] not in file_list:
                    file_list[parts[1]] = 0
        if playground_package and the_package == playground_package:
            area = SavedFile(current_user.id, fix=False, section='playgroundsources')
            for filename in area.list_of_files():
                # logmessage("hey file is " + str(filename))
                if re.match(r'ml-.*\.json$', filename):
                    short_file_name = re.sub(r'^ml-|\.json$', '', filename)
                    if short_file_name not in file_list:
                        file_list[short_file_name] = 0
        file_list = [(x, file_list[x]) for x in sorted(file_list)]
        response = make_response(
            render_template('pages/train.html', version_warning=version_warning, bodyclass='daadminbody',
                            tab_title=word("Train"), page_title=word("Train machine learning models"),
                            the_package=the_package, the_package_display=the_package_display, the_file=the_file,
                            the_group_id=the_group_id, package_list=package_list, file_list=file_list,
                            group_id_list=group_id_list, entry_list=entry_list, show_all=show_all, show_file_list=True),
            200)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    if the_group_id is None:
        the_prefix = ml_prefix(the_package, the_file)
        the_package_file = docassemble.base.functions.package_data_filename(the_prefix)
        package_file_available = bool(the_package_file is not None and os.path.isfile(the_package_file))
        if 'download' in request.args and request.args['download']:
            output = {}
            if the_package == '_global':
                json_filename = 'ml-global.json'
                for record in db.session.execute(
                        select(MachineLearning.id, MachineLearning.group_id, MachineLearning.independent,
                               MachineLearning.dependent, MachineLearning.key)):
                    if is_package_ml(record.group_id.split(':')):
                        continue
                    if record.group_id not in output:
                        output[record.group_id] = []
                    if record.dependent is None:
                        the_dependent = None
                    else:
                        the_dependent = fix_pickle_obj(
                            codecs.decode(bytearray(record.dependent, encoding='utf-8'), 'base64'))
                    the_independent = fix_pickle_obj(
                        codecs.decode(bytearray(record.independent, encoding='utf-8'), 'base64'))
                    try:
                        str(the_independent) + ""
                        str(the_dependent) + ""
                    except Exception as e:
                        logmessage("Bad record: id " + str(record.id) + " where error was " + str(e))
                        continue
                    the_entry = dict(independent=fix_pickle_obj(
                        codecs.decode(bytearray(record.independent, encoding='utf-8'), 'base64')),
                        dependent=the_dependent)
                    if record.key is not None:
                        the_entry['key'] = record.key
                    output[record.group_id].append(the_entry)
            else:
                json_filename = 'ml-' + the_file + '.json'
                prefix = ml_prefix(the_package, the_file)
                for record in db.session.execute(
                        select(MachineLearning.group_id, MachineLearning.independent, MachineLearning.dependent,
                               MachineLearning.key).where(MachineLearning.group_id.like(prefix + ':%'))):
                    parts = record.group_id.split(':')
                    if not is_package_ml(parts):
                        continue
                    if parts[2] not in output:
                        output[parts[2]] = []
                    if record.dependent is None:
                        the_dependent = None
                    else:
                        the_dependent = fix_pickle_obj(
                            codecs.decode(bytearray(record.dependent, encoding='utf-8'), 'base64'))
                    the_entry = dict(independent=fix_pickle_obj(
                        codecs.decode(bytearray(record.independent, encoding='utf-8'), 'base64')),
                        dependent=the_dependent)
                    if record.key is not None:
                        the_entry['key'] = record.key
                    output[parts[2]].append(the_entry)
            if len(output) > 0:
                the_json_file = tempfile.NamedTemporaryFile(mode='w', prefix="datemp", suffix=".json", delete=False,
                                                            encoding='utf-8')
                json.dump(output, the_json_file, sort_keys=True, indent=2)
                response = send_file(the_json_file, mimetype='application/json', as_attachment=True,
                                     attachment_filename=json_filename)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            else:
                flash(word("No data existed in training set.  JSON file not created."), "error")
                return redirect(url_for('train', package=the_package, file=the_file, show_all=show_all))
        if the_package == '_global':
            for record in db.session.execute(
                    select(MachineLearning.group_id, db.func.count(MachineLearning.id).label('cnt')).where(
                        show_cond).group_by(MachineLearning.group_id)):
                if is_package_ml(record.group_id.split(':')):
                    continue
                if record.group_id not in group_id_list:
                    group_id_list[record.group_id] = 0
                group_id_list[record.group_id] += record.cnt
            if not show_all:
                for record in db.session.execute(select(MachineLearning.group_id).group_by(MachineLearning.group_id)):
                    if is_package_ml(record.group_id.split(':')):
                        continue
                    if record.group_id not in group_id_list:
                        group_id_list[record.group_id] = 0
        else:
            the_prefix = ml_prefix(the_package, the_file)
            # logmessage("My prefix is " + the_prefix)
            for record in db.session.execute(
                    select(MachineLearning.group_id, db.func.count(MachineLearning.id).label('cnt')).where(
                        and_(MachineLearning.group_id.like(the_prefix + ':%'), show_cond)).group_by(
                        MachineLearning.group_id)):
                parts = record.group_id.split(':')
                if not is_package_ml(parts):
                    continue
                if parts[2] not in group_id_list:
                    group_id_list[parts[2]] = 0
                group_id_list[parts[2]] += record.cnt
            if not show_all:
                for record in db.session.execute(select(MachineLearning.group_id).where(
                        MachineLearning.group_id.like(the_prefix + ':%')).group_by(MachineLearning.group_id)):
                    parts = record.group_id.split(':')
                    if not is_package_ml(parts):
                        continue
                    if parts[2] not in group_id_list:
                        group_id_list[parts[2]] = 0
        if the_package != '_global' and not re.search(r'^data/', the_file):
            interview = get_corresponding_interview(the_package, the_file)
            if interview is not None and len(interview.mlfields):
                for saveas in interview.mlfields:
                    if 'ml_group' in interview.mlfields[saveas] and not interview.mlfields[saveas][
                        'ml_group'].uses_mako:
                        the_saveas = interview.mlfields[saveas]['ml_group'].original_text
                    else:
                        the_saveas = saveas
                    if not re.search(r':', the_saveas):
                        if the_saveas not in group_id_list:
                            group_id_list[the_saveas] = 0
        group_id_list = [(x, group_id_list[x]) for x in sorted(group_id_list)]
        extra_js = """
    <script>
      $( document ).ready(function() {
        $("#showimport").click(function(e){
          $("#showimport").hide();
          $("#hideimport").show();
          $("#importcontrols").show('fast');
          e.preventDefault();
          return false;
        });
        $("#hideimport").click(function(e){
          $("#showimport").show();
          $("#hideimport").hide();
          $("#importcontrols").hide('fast');
          e.preventDefault();
          return false;
        });
        $("input[type=radio][name=usepackage]").on('change', function(e) {
          if ($(this).val() == 'no'){
            $("#uploadinput").show();
          }
          else{
            $("#uploadinput").hide();
          }
          e.preventDefault();
          return false;
        });
      });
    </script>"""
        response = make_response(
            render_template('pages/train.html', extra_js=Markup(extra_js), version_warning=version_warning,
                            bodyclass='daadminbody', tab_title=word("Train"),
                            page_title=word("Train machine learning models"), the_package=the_package,
                            the_package_display=the_package_display, the_file=the_file, the_group_id=the_group_id,
                            package_list=package_list, file_list=file_list, group_id_list=group_id_list,
                            entry_list=entry_list, show_all=show_all, show_group_id_list=True,
                            package_file_available=package_file_available, the_package_location=the_prefix,
                            uploadform=uploadform), 200)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    else:
        group_id_to_use = fix_group_id(the_package, the_file, the_group_id)
        model = docassemble.base.util.SimpleTextMachineLearner(group_id=group_id_to_use)
        for record in db.session.execute(
                select(MachineLearning.id, MachineLearning.group_id, MachineLearning.key, MachineLearning.info,
                       MachineLearning.independent, MachineLearning.dependent, MachineLearning.create_time,
                       MachineLearning.modtime, MachineLearning.active).where(
                    and_(MachineLearning.group_id == group_id_to_use, show_cond))):
            new_entry = dict(id=record.id, group_id=record.group_id, key=record.key, independent=fix_pickle_obj(
                codecs.decode(bytearray(record.independent, encoding='utf-8'),
                              'base64')) if record.independent is not None else None, dependent=fix_pickle_obj(
                codecs.decode(bytearray(record.dependent, encoding='utf-8'),
                              'base64')) if record.dependent is not None else None, info=fix_pickle_obj(
                codecs.decode(bytearray(record.info, encoding='utf-8'), 'base64')) if record.info is not None else None,
                             create_type=record.create_time, modtime=record.modtime, active=MachineLearning.active)
            if new_entry['dependent'] is None and new_entry['active'] is True:
                new_entry['active'] = False
            if isinstance(new_entry['independent'], DADict) or isinstance(new_entry['independent'], dict):
                new_entry['independent_display'] = '<div class="damldatacontainer">' + '<br>'.join([
                    '<span class="damldatakey">' + str(
                        key) + '</span>: <span class="damldatavalue">' + str(
                        val) + ' (' + str(
                        val.__class__.__name__) + ')</span>'
                    for key, val in
                    new_entry[
                        'independent'].items()]) + '</div>'
                new_entry['type'] = 'data'
            else:
                new_entry['type'] = 'text'
            if new_entry['dependent'] is None:
                new_entry['predictions'] = model.predict(new_entry['independent'], probabilities=True)
                if len(new_entry['predictions']) == 0:
                    new_entry['predictions'] = None
                elif len(new_entry['predictions']) > 10:
                    new_entry['predictions'] = new_entry['predictions'][0:10]
                if new_entry['predictions'] is not None:
                    new_entry['predictions'] = [(prediction, '%d%%' % (100.0 * probability)) for prediction, probability
                                                in new_entry['predictions']]
            else:
                new_entry['predictions'] = None
            if new_entry['info'] is not None:
                if isinstance(new_entry['info'], DAFile):
                    image_file_list = [new_entry['info']]
                elif isinstance(new_entry['info'], DAFileList):
                    image_file_list = new_entry['info']
                else:
                    logmessage("train: info is not a DAFile or DAFileList")
                    continue
                new_entry['image_files'] = []
                for image_file in image_file_list:
                    if not isinstance(image_file, DAFile):
                        logmessage("train: file is not a DAFile")
                        continue
                    if not image_file.ok:
                        logmessage("train: file does not have a number")
                        continue
                    if image_file.extension not in ('pdf', 'png', 'jpg', 'jpeg', 'gif'):
                        logmessage("train: file did not have a recognizable image type")
                        continue
                    doc_url = get_url_from_file_reference(image_file)
                    if image_file.extension == 'pdf':
                        image_url = get_url_from_file_reference(image_file, size="screen", page=1, ext='pdf')
                    else:
                        image_url = doc_url
                    new_entry['image_files'].append(dict(doc_url=doc_url, image_url=image_url))
            entry_list.append(new_entry)
        if len(entry_list) == 0:
            record = db.session.execute(select(MachineLearning.independent).where(
                and_(MachineLearning.group_id == group_id_to_use, MachineLearning.independent != None))).first()
            if record is not None:
                sample_indep = fix_pickle_obj(codecs.decode(bytearray(record.independent, encoding='utf-8'), 'base64'))
            else:
                sample_indep = None
        else:
            sample_indep = entry_list[0]['independent']
        is_data = bool(isinstance(sample_indep, DADict) or isinstance(sample_indep, dict))
        choices = {}
        for record in db.session.execute(
                select(MachineLearning.dependent, db.func.count(MachineLearning.id).label('cnt')).where(
                    and_(MachineLearning.group_id == group_id_to_use)).group_by(MachineLearning.dependent)):
            # logmessage("There is a choice")
            if record.dependent is None:
                continue
            key = fix_pickle_obj(codecs.decode(bytearray(record.dependent, encoding='utf-8'), 'base64'))
            if key is not None:
                choices[key] = record.cnt
        if len(choices) > 0:
            # logmessage("There are choices")
            choices = [(x, choices[x]) for x in sorted(choices, key=operator.itemgetter(0), reverse=False)]
        else:
            # logmessage("There are no choices")
            choices = None
        extra_js = """
    <script>
      $( document ).ready(function(){
        $("button.prediction").click(function(){
          if (!($("#dependent" + $(this).data("id-number")).prop('disabled'))){
            $("#dependent" + $(this).data("id-number")).val($(this).data("prediction"));
          }
        });
        $("select.trainer").change(function(){
          var the_number = $(this).data("id-number");
          if (the_number == "newdependent"){
            $("#newdependent").val($(this).val());
          }
          else{
            $("#dependent" + the_number).val($(this).val());
          }
        });
        $("div.dadelete-observation input").change(function(){
          var the_number = $(this).data("id-number");
          if ($(this).is(':checked')){
            $("#dependent" + the_number).prop('disabled', true);
            $("#selector" + the_number).prop('disabled', true);
          }
          else{
            $("#dependent" + the_number).prop('disabled', false);
            $("#selector" + the_number).prop('disabled', false);
          }
        });
      });
    </script>"""
        response = make_response(
            render_template('pages/train.html', extra_js=Markup(extra_js), form=form, version_warning=version_warning,
                            bodyclass='daadminbody', tab_title=word("Train"),
                            page_title=word("Train machine learning models"), the_package=the_package,
                            the_package_display=the_package_display, the_file=the_file, the_group_id=the_group_id,
                            entry_list=entry_list, choices=choices, show_all=show_all, show_entry_list=True,
                            is_data=is_data), 200)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response


@user_logged_in.connect_via(app)
def _on_user_login(sender, user, **extra):
    update_last_login(user)
    login_or_register(sender, user, 'login', **extra)


@user_changed_password.connect_via(app)
def _on_password_change(sender, user, **extra):
    fix_secret(user=user)


@user_registered.connect_via(app)
def on_register_hook(sender, user, **extra):
    # why did I not just import it globally?
    # from docassemble.webapp.users.models import Role
    user_invite = extra.get('user_invite', None)
    this_user_role = None
    if user_invite is not None:
        this_user_role = db.session.execute(select(Role).filter_by(id=user_invite.role_id)).scalar()
    if this_user_role is None:
        this_user_role = db.session.execute(select(Role).filter_by(name='user')).scalar()
    roles_to_remove = []
    for role in user.roles:
        roles_to_remove.append(role)
    for role in roles_to_remove:
        user.roles.remove(role)
    user.roles.append(this_user_role)
    db.session.commit()
    update_last_login(user)
    login_or_register(sender, user, 'register', **extra)


@app.route("/fax_callback", methods=['POST'])
@csrf.exempt
def fax_callback():
    if twilio_config is None:
        logmessage("fax_callback: Twilio not enabled")
        return ('', 204)
    post_data = request.form.copy()
    if 'FaxSid' not in post_data or 'AccountSid' not in post_data:
        logmessage("fax_callback: FaxSid and/or AccountSid missing")
        return ('', 204)
    tconfig = None
    for config_name, config_info in twilio_config['name'].items():
        if 'account sid' in config_info and config_info['account sid'] == post_data['AccountSid']:
            tconfig = config_info
    if tconfig is None:
        logmessage(
            "fax_callback: account sid of fax callback did not match any account sid in the Twilio configuration")
    if 'fax' not in tconfig or tconfig['fax'] in (False, None):
        logmessage("fax_callback: fax feature not enabled")
        return ('', 204)
    params = {}
    for param in (
            'FaxSid', 'From', 'To', 'RemoteStationId', 'FaxStatus', 'ApiVersion', 'OriginalMediaUrl', 'NumPages',
            'MediaUrl',
            'ErrorCode', 'ErrorMessage'):
        params[param] = post_data.get(param, None)
    the_key = 'da:faxcallback:sid:' + post_data['FaxSid']
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps(params))
    pipe.expire(the_key, 86400)
    pipe.execute()
    return ('', 204)


@app.route("/clicksend_fax_callback", methods=['POST'])
@csrf.exempt
def clicksend_fax_callback():
    if clicksend_config is None or fax_provider != 'clicksend':
        logmessage("clicksend_fax_callback: Clicksend not enabled")
        return ('', 204)
    post_data = request.form.copy()
    if 'message_id' not in post_data:
        logmessage("clicksend_fax_callback: message_id missing")
        return ('', 204)
    the_key = 'da:faxcallback:sid:' + post_data['message_id']
    the_json = r.get(the_key)
    try:
        params = json.loads(the_json)
    except:
        logmessage("clicksend_fax_callback: existing fax record could not be found")
        return ('', 204)
    for param in (
            'timestamp_send', 'timestamp', 'message_id', 'status', 'status_code', 'status_text', 'error_code',
            'error_text',
            'custom_string', 'user_id', 'subaccount_id', 'message_type'):
        params[param] = post_data.get(param, None)
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps(params))
    pipe.expire(the_key, 86400)
    pipe.execute()
    return ('', 204)


@app.route("/telnyx_fax_callback", methods=['POST'])
@csrf.exempt
def telnyx_fax_callback():
    if telnyx_config is None:
        logmessage("telnyx_fax_callback: Telnyx not enabled")
        return ('', 204)
    data = request.get_json(silent=True)
    try:
        the_id = data['data']['payload']['fax_id']
    except:
        logmessage("telnyx_fax_callback: fax_id not found")
        return ('', 204)
    the_key = 'da:faxcallback:sid:' + str(the_id)
    the_json = r.get(the_key)
    try:
        params = json.loads(the_json)
    except:
        logmessage("telnyx_fax_callback: existing fax record could not be found")
        return ('', 204)
    try:
        params['status'] = data['data']['payload']['status']
        if params['status'] == 'failed' and 'failure_reason' in data['data']['payload']:
            params['status'] += ': ' + data['data']['payload']['failure_reason']
            logmessage("telnyx_fax_callback: failure because " + data['data']['payload']['failure_reason'])
    except:
        logmessage("telnyx_fax_callback: could not find status")
    try:
        params['latest_update_time'] = data['data']['occurred_at']
    except:
        logmessage("telnyx_fax_callback: could not update latest_update_time")
    if 'status' in params and params['status'] == 'delivered':
        try:
            params['page_count'] = data['data']['payload']['page_count']
        except:
            logmessage("telnyx_fax_callback: could not update page_count")
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps(params))
    pipe.expire(the_key, 86400)
    pipe.execute()
    return ('', 204)


@app.route("/voice", methods=['POST', 'GET'])
@csrf.exempt
def voice():
    docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
    resp = twilio.twiml.voice_response.VoiceResponse()
    if twilio_config is None:
        logmessage("voice: ignoring call to voice because Twilio not enabled")
        return Response(str(resp), mimetype='text/xml')
    if 'voice' not in twilio_config['name']['default'] or twilio_config['name']['default']['voice'] in (False, None):
        logmessage("voice: ignoring call to voice because voice feature not enabled")
        return Response(str(resp), mimetype='text/xml')
    if "AccountSid" not in request.form or request.form["AccountSid"] != twilio_config['name']['default'].get(
            'account sid', None):
        logmessage("voice: request to voice did not authenticate")
        return Response(str(resp), mimetype='text/xml')
    for item in request.form:
        logmessage("voice: item " + str(item) + " is " + str(request.form[item]))
    with resp.gather(action=url_for("digits_endpoint"), finishOnKey='#', method="POST", timeout=10, numDigits=5) as gg:
        gg.say(word("Please enter the four digit code, followed by the pound sign."))

    # twilio_config = daconfig.get('twilio', None)
    # if twilio_config is None:
    #     logmessage("Could not get twilio configuration")
    #     return
    # twilio_caller_id = twilio_config.get('number', None)
    # if "To" in request.form and request.form["To"] != '':
    #     dial = resp.dial(callerId=twilio_caller_id)
    #     if phone_pattern.match(request.form["To"]):
    #         dial.number(request.form["To"])
    #     else:
    #         dial.client(request.form["To"])
    # else:
    #     resp.say("Thanks for calling!")

    return Response(str(resp), mimetype='text/xml')


@app.route("/digits", methods=['POST', 'GET'])
@csrf.exempt
def digits_endpoint():
    docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
    resp = twilio.twiml.voice_response.VoiceResponse()
    if twilio_config is None:
        logmessage("digits: ignoring call to digits because Twilio not enabled")
        return Response(str(resp), mimetype='text/xml')
    if "AccountSid" not in request.form or request.form["AccountSid"] != twilio_config['name']['default'].get(
            'account sid', None):
        logmessage("digits: request to digits did not authenticate")
        return Response(str(resp), mimetype='text/xml')
    if "Digits" in request.form:
        the_digits = re.sub(r'[^0-9]', '', request.form["Digits"])
        logmessage("digits: got " + str(the_digits))
        phone_number = r.get('da:callforward:' + str(the_digits))
        if phone_number is None:
            resp.say(word("I am sorry.  The code you entered is invalid or expired.  Goodbye."))
            resp.hangup()
        else:
            phone_number = phone_number.decode()
            dial = resp.dial(number=phone_number)
            r.delete('da:callforward:' + str(the_digits))
    else:
        logmessage("digits: no digits received")
        resp.say(word("No access code was entered."))
        resp.hangup()
    return Response(str(resp), mimetype='text/xml')


def sms_body(phone_number, body='question', config='default'):
    if twilio_config is None:
        raise DAError("sms_body: Twilio not enabled")
    if config not in twilio_config['name']:
        raise DAError("sms_body: specified config value, " + str(config) + ", not in Twilio configuration")
    tconfig = twilio_config['name'][config]
    if 'sms' not in tconfig or tconfig['sms'] in (False, None, 0):
        raise DAError("sms_body: sms feature is not enabled in Twilio configuration")
    if 'account sid' not in tconfig:
        raise DAError("sms_body: account sid not in Twilio configuration")
    if 'number' not in tconfig:
        raise DAError("sms_body: phone number not in Twilio configuration")
    if 'doing_sms' in session:
        raise DAError("Cannot call sms_body from within sms_body")
    form = dict(To=tconfig['number'], From=phone_number, Body=body, AccountSid=tconfig['account sid'])
    base_url = url_for('rootindex', _external=True)
    url_root = base_url
    tbackup = docassemble.base.functions.backup_thread_variables()
    sbackup = backup_session()
    session['doing_sms'] = True
    resp = do_sms(form, base_url, url_root, save=False)
    restore_session(sbackup)
    docassemble.base.functions.restore_thread_variables(tbackup)
    if resp is None or len(resp.verbs) == 0 or len(resp.verbs[0].verbs) == 0:
        return None
    return resp.verbs[0].verbs[0].body


@app.route("/sms", methods=['POST'])
@csrf.exempt
def sms():
    form = request.form
    base_url = url_for('rootindex', _external=True)
    url_root = base_url
    resp = do_sms(form, base_url, url_root)
    return Response(str(resp), mimetype='text/xml')


def do_sms(form, base_url, url_root, config='default', save=True):
    docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
    resp = twilio.twiml.messaging_response.MessagingResponse()
    special_messages = []
    if twilio_config is None:
        logmessage("do_sms: ignoring message to sms because Twilio not enabled")
        return resp
    if "AccountSid" not in form or form["AccountSid"] not in twilio_config['account sid']:
        logmessage("do_sms: request to sms did not authenticate")
        return resp
    if "To" not in form or form["To"] not in twilio_config['number']:
        logmessage("do_sms: request to sms ignored because recipient number " + str(
            form.get('To', None)) + " not in configuration, " + str(twilio_config))
        return resp
    tconfig = twilio_config['number'][form["To"]]
    if 'sms' not in tconfig or tconfig['sms'] in (False, None, 0):
        logmessage("do_sms: ignoring message to sms because SMS not enabled")
        return resp
    if "From" not in form or not re.search(r'[0-9]', form["From"]):
        logmessage("do_sms: request to sms ignored because unable to determine caller ID")
        return resp
    if "Body" not in form:
        logmessage("do_sms: request to sms ignored because message had no content")
        return resp
    inp = form['Body'].strip()
    # logmessage("do_sms: received >" + inp + "<")
    key = 'da:sms:client:' + form["From"] + ':server:' + tconfig['number']
    action = None
    action_performed = False
    for try_num in (0, 1):
        sess_contents = r.get(key)
        if sess_contents is None:
            # logmessage("do_sms: received input '" + str(inp) + "' from new user")
            yaml_filename = tconfig.get('default interview', default_yaml_filename)
            if 'dispatch' in tconfig and isinstance(tconfig['dispatch'], dict):
                if inp.lower() in tconfig['dispatch']:
                    yaml_filename = tconfig['dispatch'][inp.lower()]
                    # logmessage("do_sms: using interview from dispatch: " + str(yaml_filename))
            if yaml_filename is None:
                # logmessage("do_sms: request to sms ignored because no interview could be determined")
                return resp
            if (not DEBUG) and (
                    yaml_filename.startswith('docassemble.base') or yaml_filename.startswith('docassemble.demo')):
                raise Exception("do_sms: not authorized to run interviews in docassemble.base or docassemble.demo")
            secret = random_string(16)
            uid = get_unique_name(yaml_filename, secret)
            new_temp_user = TempUser()
            db.session.add(new_temp_user)
            db.session.commit()
            sess_info = dict(yaml_filename=yaml_filename, uid=uid, secret=secret, number=form["From"], encrypted=True,
                             tempuser=new_temp_user.id, user_id=None, session_uid=random_string(10))
            r.set(key, pickle.dumps(sess_info))
            accepting_input = False
        else:
            try:
                sess_info = fix_pickle_obj(sess_contents)
            except:
                logmessage("do_sms: unable to decode session information")
                return resp
            accepting_input = True
        if 'session_uid' not in sess_info:
            sess_info['session_uid'] = random_string(10)
        if inp.lower() in (word('exit'), word('quit')):
            logmessage("do_sms: exiting")
            if save:
                reset_user_dict(sess_info['uid'], sess_info['yaml_filename'], temp_user_id=sess_info['tempuser'])
            r.delete(key)
            return resp
        user = None
        if sess_info['user_id'] is not None:
            user = load_user(sess_info['user_id'])
        if user is None:
            ci = dict(user=dict(is_anonymous=True, is_authenticated=False, email=None, theid=sess_info['tempuser'],
                                the_user_id='t' + str(sess_info['tempuser']), roles=['user'], firstname='SMS',
                                lastname='User', nickname=None, country=None, subdivisionfirst=None,
                                subdivisionsecond=None, subdivisionthird=None, organization=None, timezone=None,
                                location=None, session_uid=sess_info['session_uid'], device_id=form["From"]),
                      session=sess_info['uid'], secret=sess_info['secret'], yaml_filename=sess_info['yaml_filename'],
                      interface='sms', url=base_url, url_root=url_root, encrypted=encrypted, headers={}, clientip=None,
                      method=None, skip=user_dict['_internal']['skip'], sms_sender=form["From"])
        else:
            ci = dict(user=dict(is_anonymous=False, is_authenticated=True, email=user.email, theid=user.id,
                                the_user_id=user.id, roles=user.roles, firstname=user.first_name,
                                lastname=user.last_name, nickname=user.nickname, country=user.country,
                                subdivisionfirst=user.subdivisionfirst, subdivisionsecond=user.subdivisionsecond,
                                subdivisionthird=user.subdivisionthird, organization=user.organization,
                                timezone=user.timezone, location=None, session_uid=sess_info['session_uid'],
                                device_id=form["From"]), session=sess_info['uid'], secret=sess_info['secret'],
                      yaml_filename=sess_info['yaml_filename'], interface='sms', url=base_url, url_root=url_root,
                      encrypted=encrypted, headers={}, clientip=None, method=None, skip=user_dict['_internal']['skip'])
        if action is not None:
            logmessage("do_sms: setting action to " + str(action))
            ci.update(action)
        docassemble.base.functions.this_thread.current_info = ci
        obtain_lock(sess_info['uid'], sess_info['yaml_filename'])
        steps, user_dict, is_encrypted = fetch_user_dict(sess_info['uid'], sess_info['yaml_filename'],
                                                         secret=sess_info['secret'])
        if user_dict is None:
            r.delete(key)
            continue
        break
    encrypted = sess_info['encrypted']
    while True:
        if user_dict.get('multi_user', False) is True and encrypted is True:
            encrypted = False
            update_session(sess_info['yaml_filename'], encrypted=encrypted, uid=sess_info['uid'])
            is_encrypted = encrypted
            r.set(key, pickle.dumps(sess_info))
            if save:
                decrypt_session(sess_info['secret'], user_code=sess_info['uid'], filename=sess_info['yaml_filename'])
        if user_dict.get('multi_user', False) is False and encrypted is False:
            encrypted = True
            update_session(sess_info['yaml_filename'], encrypted=encrypted, uid=sess_info['uid'])
            is_encrypted = encrypted
            r.set(key, pickle.dumps(sess_info))
            if save:
                encrypt_session(sess_info['secret'], user_code=sess_info['uid'], filename=sess_info['yaml_filename'])
        interview = docassemble.base.interview_cache.get_interview(sess_info['yaml_filename'])
        if 'skip' not in user_dict['_internal']:
            user_dict['_internal']['skip'] = {}
        ci['encrypted'] = is_encrypted
        interview_status = docassemble.base.parse.InterviewStatus(current_info=ci)
        interview.assemble(user_dict, interview_status)
        logmessage("do_sms: back from assemble 1; had been seeking variable " + str(interview_status.sought))
        logmessage("do_sms: question is " + interview_status.question.name)
        if action is not None:
            logmessage('do_sms: question is now ' + interview_status.question.name + ' because action')
            sess_info['question'] = interview_status.question.name
            r.set(key, pickle.dumps(sess_info))
        elif 'question' in sess_info and sess_info['question'] != interview_status.question.name:
            if inp not in (word('?'), word('back'), word('question'), word('exit')):
                logmessage("do_sms: blanking the input because question changed from " + str(
                    sess_info['question']) + " to " + str(interview_status.question.name))
                sess_info['question'] = interview_status.question.name
                inp = 'question'
                r.set(key, pickle.dumps(sess_info))

        m = re.search(r'^(' + word('menu') + '|' + word('link') + ')([0-9]+)', inp.lower())
        if m:
            arguments = {}
            selection_type = m.group(1)
            selection_number = int(m.group(2)) - 1
            links = []
            menu_items = []
            sms_info = as_sms(interview_status, user_dict, links=links, menu_items=menu_items)
            target_url = None
            if selection_type == word('menu') and selection_number < len(menu_items):
                (target_url, label) = menu_items[selection_number]
            if selection_type == word('link') and selection_number < len(links):
                (target_url, label) = links[selection_number]
            if target_url is not None:
                uri_params = re.sub(r'^[\?]*\?', r'', target_url)
                for statement in re.split(r'&', uri_params):
                    parts = re.split(r'=', statement)
                    arguments[parts[0]] = parts[1]
            if 'action' in arguments:
                action = json.loads(myb64unquote(urllibunquote(arguments['action'])))
                action_performed = True
                accepting_input = False
                inp = ''
                continue
            break
        if inp.lower() == word('back'):
            if 'skip' in user_dict['_internal'] and len(user_dict['_internal']['skip']):
                max_entry = -1
                for the_entry in user_dict['_internal']['skip'].keys():
                    if the_entry > max_entry:
                        max_entry = the_entry
                if max_entry in user_dict['_internal']['skip']:
                    del user_dict['_internal']['skip'][max_entry]
                if 'command_cache' in user_dict['_internal'] and max_entry in user_dict['_internal']['command_cache']:
                    del user_dict['_internal']['command_cache'][max_entry]
                save_user_dict(sess_info['uid'], user_dict, sess_info['yaml_filename'], secret=sess_info['secret'],
                               encrypt=encrypted, changed=False, steps=steps)
                accepting_input = False
                inp = ''
                continue
            if steps > 1 and interview_status.can_go_back:
                old_user_dict = user_dict
                steps, user_dict, is_encrypted = fetch_previous_user_dict(sess_info['uid'], sess_info['yaml_filename'],
                                                                          secret=sess_info['secret'])
                ci['encrypted'] = is_encrypted
                if 'question' in sess_info:
                    del sess_info['question']
                    r.set(key, pickle.dumps(sess_info))
                accepting_input = False
                inp = ''
                continue
            break
        break
    false_list = [word('no'), word('n'), word('false'), word('f')]
    true_list = [word('yes'), word('y'), word('true'), word('t')]
    inp_lower = inp.lower()
    skip_it = False
    changed = False
    nothing_more = False
    if accepting_input:
        if inp_lower == word('?'):
            sms_info = as_sms(interview_status, user_dict)
            message = ''
            if sms_info['help'] is None:
                message += word('Sorry, no help is available for this question.')
            else:
                message += sms_info['help']
            message += "\n" + word("To read the question again, type question.")
            resp.message(message)
            release_lock(sess_info['uid'], sess_info['yaml_filename'])
            return resp
        if inp_lower == word('question'):
            accepting_input = False
    user_entered_skip = bool(inp_lower == word('skip'))
    if accepting_input:
        saveas = None
        uses_util = False
        uncheck_others = False
        if len(interview_status.question.fields) > 0:
            question = interview_status.question
            if question.question_type == "fields":
                field = None
                next_field = None
                for the_field in interview_status.get_field_list():
                    if hasattr(the_field, 'datatype') and the_field.datatype in ('html', 'note', 'script', 'css'):
                        continue
                    if interview_status.is_empty_mc(the_field):
                        continue
                    if the_field.number in user_dict['_internal']['skip']:
                        continue
                    if field is None:
                        field = the_field
                    elif next_field is None:
                        next_field = the_field
                    else:
                        break
                if field is None:
                    logmessage("do_sms: unclear what field is necessary!")
                    # if 'smsgather' in user_dict['_internal']:
                    #     del user_dict['_internal']['smsgather']
                    field = interview_status.question.fields[0]
                    next_field = None
                saveas = myb64unquote(field.saveas)
            else:
                if hasattr(interview_status.question.fields[0], 'saveas'):
                    saveas = myb64unquote(interview_status.question.fields[0].saveas)
                    logmessage("do_sms: variable to set is " + str(saveas))
                else:
                    saveas = None
                field = interview_status.question.fields[0]
                next_field = None
            if question.question_type == "settrue":
                if inp_lower == word('ok'):
                    data = 'True'
                else:
                    data = None
            elif question.question_type == 'signature':
                filename = 'canvas.png'
                extension = 'png'
                mimetype = 'image/png'
                temp_image_file = tempfile.NamedTemporaryFile(suffix='.' + extension)
                image = Image.new("RGBA", (200, 50))
                image.save(temp_image_file.name, 'PNG')
                (file_number, extension, mimetype) = save_numbered_file(filename, temp_image_file.name,
                                                                        yaml_file_name=sess_info['yaml_filename'],
                                                                        uid=sess_info['uid'])
                saveas_tr = sub_indices(saveas, user_dict)
                if inp_lower == word('x'):
                    the_string = saveas + " = docassemble.base.util.DAFile('" + saveas_tr + "', filename='" + str(
                        filename) + "', number=" + str(file_number) + ", mimetype='" + str(
                        mimetype) + "', extension='" + str(extension) + "')"
                    try:
                        exec('import docassemble.base.util', user_dict)
                        exec(the_string, user_dict)
                        if not changed:
                            steps += 1
                            user_dict['_internal']['steps'] = steps
                            changed = True
                    except Exception as errMess:
                        logmessage("do_sms: error: " + str(errMess))
                        special_messages.append(word("Error") + ": " + str(errMess))
                    skip_it = True
                    data = repr('')
                else:
                    data = None
            elif hasattr(field, 'datatype') and field.datatype in ("ml", "mlarea"):
                try:
                    exec("import docassemble.base.util", user_dict)
                except Exception as errMess:
                    special_messages.append("Error: " + str(errMess))
                if 'ml_train' in interview_status.extras and field.number in interview_status.extras['ml_train']:
                    if not interview_status.extras['ml_train'][field.number]:
                        use_for_training = 'False'
                    else:
                        use_for_training = 'True'
                else:
                    use_for_training = 'True'
                if 'ml_group' in interview_status.extras and field.number in interview_status.extras['ml_group']:
                    data = 'docassemble.base.util.DAModel(' + repr(saveas) + ', group_id=' + repr(
                        interview_status.extras['ml_group'][field.number]) + ', text=' + repr(inp) + ', store=' + repr(
                        interview.get_ml_store()) + ', use_for_training=' + use_for_training + ')'
                else:
                    data = 'docassemble.base.util.DAModel(' + repr(saveas) + ', text=' + repr(inp) + ', store=' + repr(
                        interview.get_ml_store()) + ', use_for_training=' + use_for_training + ')'
            elif hasattr(field, 'datatype') and field.datatype in (
                    "file", "files", "camera", "user", "environment", "camcorder", "microphone"):
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    skip_it = True
                    data = repr('')
                else:
                    files_to_process = []
                    num_media = int(form.get('NumMedia', '0'))
                    fileindex = 0
                    while True:
                        if field.datatype == "file" and fileindex > 0:
                            break
                        if fileindex >= num_media or 'MediaUrl' + str(fileindex) not in form:
                            break
                        # logmessage("mime type is" + form.get('MediaContentType' + str(fileindex), 'Unknown'))
                        mimetype = form.get('MediaContentType' + str(fileindex), 'image/jpeg')
                        extension = re.sub(r'\.', r'', mimetypes.guess_extension(mimetype))
                        if extension == 'jpe':
                            extension = 'jpg'
                        # original_extension = extension
                        # if extension == 'gif':
                        #     extension == 'png'
                        #     mimetype = 'image/png'
                        filename = 'file' + '.' + extension
                        file_number = get_new_file_number(sess_info['uid'], filename,
                                                          yaml_file_name=sess_info['yaml_filename'])
                        saved_file = SavedFile(file_number, extension=extension, fix=True, should_not_exist=True)
                        the_url = form['MediaUrl' + str(fileindex)]
                        saved_file.fetch_url(the_url)
                        process_file(saved_file, saved_file.path, mimetype, extension)
                        files_to_process.append((filename, file_number, mimetype, extension))
                        fileindex += 1
                    if len(files_to_process) > 0:
                        elements = []
                        indexno = 0
                        saveas_tr = sub_indices(saveas, user_dict)
                        for (filename, file_number, mimetype, extension) in files_to_process:
                            elements.append("docassemble.base.util.DAFile(" + repr(
                                saveas_tr + "[" + str(indexno) + "]") + ", filename=" + repr(
                                filename) + ", number=" + str(file_number) + ", mimetype=" + repr(
                                mimetype) + ", extension=" + repr(extension) + ")")
                            indexno += 1
                        the_string = saveas + " = docassemble.base.util.DAFileList(" + repr(
                            saveas_tr) + ", elements=[" + ", ".join(elements) + "])"
                        try:
                            exec('import docassemble.base.util', user_dict)
                            exec(the_string, user_dict)
                            if not changed:
                                steps += 1
                                user_dict['_internal']['steps'] = steps
                                changed = True
                        except Exception as errMess:
                            logmessage("do_sms: error: " + str(errMess))
                            special_messages.append(word("Error") + ": " + str(errMess))
                        skip_it = True
                        data = repr('')
                    else:
                        data = None
                        if interview_status.extras['required'][field.number]:
                            special_messages.append(word("You must attach a file."))
            elif question.question_type == "yesno" or (hasattr(field, 'datatype') and (
                    hasattr(field, 'datatype') and field.datatype == 'boolean' and (
                    hasattr(field, 'sign') and field.sign > 0))):
                if inp_lower in true_list:
                    data = 'True'
                    if question.question_type == "fields" and hasattr(field,
                                                                      'uncheckothers') and field.uncheckothers is not False:
                        uncheck_others = field
                elif inp_lower in false_list:
                    data = 'False'
                else:
                    data = None
            elif question.question_type == "yesnomaybe" or (hasattr(field, 'datatype') and (
                    field.datatype == 'threestate' and (hasattr(field, 'sign') and field.sign > 0))):
                if inp_lower in true_list:
                    data = 'True'
                    if question.question_type == "fields" and hasattr(field,
                                                                      'uncheckothers') and field.uncheckothers is not False:
                        uncheck_others = field
                elif inp_lower in false_list:
                    data = 'False'
                else:
                    data = 'None'
            elif question.question_type == "noyes" or (hasattr(field, 'datatype') and (
                    field.datatype in ('noyes', 'noyeswide') or (
                    field.datatype == 'boolean' and (hasattr(field, 'sign') and field.sign < 0)))):
                if inp_lower in true_list:
                    data = 'False'
                elif inp_lower in false_list:
                    data = 'True'
                    if question.question_type == "fields" and hasattr(field,
                                                                      'uncheckothers') and field.uncheckothers is not False:
                        uncheck_others = field
                else:
                    data = None
            elif question.question_type in ('noyesmaybe', 'noyesmaybe', 'noyeswidemaybe') or (
                    hasattr(field, 'datatype') and field.datatype == 'threestate' and (
                    hasattr(field, 'sign') and field.sign < 0)):
                if inp_lower in true_list:
                    data = 'False'
                elif inp_lower in false_list:
                    data = 'True'
                    if question.question_type == "fields" and hasattr(field,
                                                                      'uncheckothers') and field.uncheckothers is not False:
                        uncheck_others = field
                else:
                    data = 'None'
            elif question.question_type == 'multiple_choice' or hasattr(field, 'choicetype') or (
                    hasattr(field, 'datatype') and field.datatype in (
                    'object', 'object_radio', 'multiselect', 'object_multiselect', 'checkboxes',
                    'object_checkboxes')) or (
                    hasattr(field, 'inputtype') and field.inputtype == 'radio'):
                cdata, choice_list = get_choices_with_abb(interview_status, field, user_dict)
                data = None
                if hasattr(field, 'datatype') and field.datatype in (
                        'multiselect', 'object_multiselect', 'checkboxes', 'object_checkboxes') and saveas is not None:
                    if 'command_cache' not in user_dict['_internal']:
                        user_dict['_internal']['command_cache'] = {}
                    if field.number not in user_dict['_internal']['command_cache']:
                        user_dict['_internal']['command_cache'][field.number] = []
                    docassemble.base.parse.ensure_object_exists(saveas, field.datatype, user_dict,
                                                                commands=user_dict['_internal']['command_cache'][
                                                                    field.number])
                    saveas = saveas + '.gathered'
                    data = 'True'
                if (user_entered_skip or (
                        inp_lower == word('none') and hasattr(field, 'datatype') and field.datatype in (
                        'multiselect', 'object_multiselect', 'checkboxes', 'object_checkboxes'))) and (
                        (hasattr(field, 'disableothers') and field.disableothers) or (
                        hasattr(field, 'datatype') and field.datatype in (
                        'multiselect', 'object_multiselect', 'checkboxes', 'object_checkboxes')) or not (
                        interview_status.extras['required'][field.number] or (
                        question.question_type == 'multiple_choice' and hasattr(field, 'saveas')))):
                    logmessage("do_sms: skip accepted")
                    # user typed 'skip,' or, where checkboxes, 'none.'  Also:
                    # field is skippable, either because it has disableothers, or it is a checkbox field, or
                    # it is not required.  Multiple choice fields with saveas are considered required.
                    if hasattr(field, 'datatype'):
                        if field.datatype in ('object', 'object_radio'):
                            skip_it = True
                            data = repr('')
                        if field.datatype in ('multiselect', 'object_multiselect', 'checkboxes', 'object_checkboxes'):
                            for choice in choice_list:
                                if choice[1] is None:
                                    continue
                                user_dict['_internal']['command_cache'][field.number].append(choice[1] + ' = False')
                        elif (question.question_type == 'multiple_choice' and hasattr(field, 'saveas')) or hasattr(
                                field, 'choicetype'):
                            if user_entered_skip:
                                skip_it = True
                                data = repr('')
                            else:
                                logmessage("do_sms: setting skip_it to True")
                                skip_it = True
                                data = repr('')
                        elif field.datatype == 'integer':
                            data = '0'
                        elif field.datatype in ('number', 'float', 'currency', 'range'):
                            data = '0.0'
                        else:
                            data = repr('')
                    else:
                        data = repr('')
                else:
                    # There is a real value here
                    if hasattr(field, 'datatype') and field.datatype in ('object_multiselect', 'object_checkboxes'):
                        true_values = set()
                        for selection in re.split(r' *[,;] *', inp_lower):
                            for potential_abb, value in cdata['abblower'].items():
                                if selection and selection.startswith(potential_abb):
                                    for choice in choice_list:
                                        if value == choice[0]:
                                            true_values.add(choice[2])
                        the_saveas = myb64unquote(field.saveas)
                        logmessage("do_sms: the_saveas is " + repr(the_saveas))
                        for choice in choice_list:
                            if choice[2] is None:
                                continue
                            if choice[2] in true_values:
                                logmessage("do_sms: " + choice[2] + " is in true_values")
                                the_string = 'if ' + choice[
                                    2] + ' not in ' + the_saveas + '.elements:\n    ' + the_saveas + '.append(' + \
                                             choice[2] + ')'
                            else:
                                the_string = 'if ' + choice[
                                    2] + ' in ' + the_saveas + '.elements:\n    ' + the_saveas + '.remove(' + choice[
                                                 2] + ')'
                            user_dict['_internal']['command_cache'][field.number].append(the_string)
                    elif hasattr(field, 'datatype') and field.datatype in ('multiselect', 'checkboxes'):
                        true_values = set()
                        for selection in re.split(r' *[,;] *', inp_lower):
                            for potential_abb, value in cdata['abblower'].items():
                                if selection and selection.startswith(potential_abb):
                                    for choice in choice_list:
                                        if value == choice[0]:
                                            true_values.add(choice[1])
                        for choice in choice_list:
                            if choice[1] is None:
                                continue
                            if choice[1] in true_values:
                                the_string = choice[1] + ' = True'
                            else:
                                the_string = choice[1] + ' = False'
                            user_dict['_internal']['command_cache'][field.number].append(the_string)
                    else:
                        # regular multiple choice
                        # logmessage("do_sms: user selected " + inp_lower + " and data is " + str(cdata))
                        for potential_abb, value in cdata['abblower'].items():
                            if inp_lower.startswith(potential_abb):
                                # logmessage("do_sms: user selected " + value)
                                for choice in choice_list:
                                    # logmessage("do_sms: considering " + choice[0])
                                    if value == choice[0]:
                                        # logmessage("do_sms: found a match")
                                        saveas = choice[1]
                                        if hasattr(field, 'datatype') and field.datatype in ('object', 'object_radio'):
                                            data = choice[2]
                                        else:
                                            data = repr(choice[2])
                                        break
                                break
            elif hasattr(field, 'datatype') and field.datatype == 'integer':
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    data = repr('')
                    skip_it = True
                else:
                    data = re.sub(r'[^0-9\-\.]', '', inp)
                    if data == '':
                        data = '0'
                    try:
                        the_value = eval("int(" + repr(data) + ")")
                        data = "int(" + repr(data) + ")"
                    except:
                        special_messages.append('"' + inp + '" ' + word("is not a whole number."))
                        data = None
            elif hasattr(field, 'datatype') and field.datatype in ('date', 'datetime'):
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    data = repr('')
                    skip_it = True
                else:
                    try:
                        dateutil.parser.parse(inp)
                        data = "docassemble.base.util.as_datetime(" + repr(inp) + ")"
                        uses_util = True
                    except Exception as the_err:
                        logmessage("do_sms: date validation error was " + str(the_err))
                        if field.datatype == 'date':
                            special_messages.append('"' + inp + '" ' + word("is not a valid date."))
                        else:
                            special_messages.append('"' + inp + '" ' + word("is not a valid date and time."))
                        data = None
            elif hasattr(field, 'datatype') and field.datatype == 'time':
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    data = repr('')
                    skip_it = True
                else:
                    try:
                        dateutil.parser.parse(inp)
                        data = "docassemble.base.util.as_datetime(" + repr(inp) + ").time()"
                        uses_util = True
                    except Exception as the_err:
                        logmessage("do_sms: time validation error was " + str(the_err))
                        special_messages.append('"' + inp + '" ' + word("is not a valid time."))
                        data = None
            elif hasattr(field, 'datatype') and field.datatype == 'range':
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    data = repr('')
                    skip_it = True
                else:
                    data = re.sub(r'[^0-9\-\.]', '', inp)
                    try:
                        the_value = eval("float(" + repr(data) + ")", user_dict)
                        if the_value > int(interview_status.extras['max'][field.number]) or the_value < int(
                                interview_status.extras['min'][field.number]):
                            special_messages.append('"' + inp + '" ' + word("is not within the range."))
                            data = None
                    except:
                        data = None
            elif hasattr(field, 'datatype') and field.datatype in ('number', 'float', 'currency'):
                if user_entered_skip and not interview_status.extras['required'][field.number]:
                    data = repr('')
                    skip_it = True
                else:
                    data = re.sub(r'[^0-9\-\.]', '', inp)
                    if data == '':
                        data = '0.0'
                    try:
                        the_value = eval("float(" + json.dumps(data) + ")", user_dict)
                        data = "float(" + json.dumps(data) + ")"
                    except:
                        special_messages.append('"' + inp + '" ' + word("is not a valid number."))
                        data = None
            else:
                if user_entered_skip:
                    if interview_status.extras['required'][field.number]:
                        data = repr(inp)
                    else:
                        data = repr('')
                        skip_it = True
                else:
                    data = repr(inp)
        else:
            data = None
        if data is None:
            logmessage("do_sms: could not process input: " + inp)
            special_messages.append(word("I do not understand what you mean by") + ' "' + inp + '."')
        else:
            if uses_util:
                exec("import docassemble.base.util", user_dict)
            if uncheck_others:
                for other_field in interview_status.get_field_list():
                    if hasattr(other_field,
                               'datatype') and other_field.datatype == 'boolean' and other_field is not uncheck_others and 'command_cache' in \
                            user_dict['_internal'] and other_field.number in user_dict['_internal']['command_cache']:
                        for command_index in range(len(user_dict['_internal']['command_cache'][other_field.number])):
                            if other_field.sign > 0:
                                user_dict['_internal']['command_cache'][other_field.number][command_index] = re.sub(
                                    r'= True$', '= False',
                                    user_dict['_internal']['command_cache'][other_field.number][command_index])
                            else:
                                user_dict['_internal']['command_cache'][other_field.number][command_index] = re.sub(
                                    r'= False$', '= True',
                                    user_dict['_internal']['command_cache'][other_field.number][command_index])
            the_string = saveas + ' = ' + data
            try:
                if not skip_it:
                    if hasattr(field, 'disableothers') and field.disableothers and hasattr(field, 'saveas'):
                        logmessage("do_sms: disabling others")
                        next_field = None
                    if next_field is not None:
                        if 'command_cache' not in user_dict['_internal']:
                            user_dict['_internal']['command_cache'] = {}
                        if field.number not in user_dict['_internal']['command_cache']:
                            user_dict['_internal']['command_cache'][field.number] = []
                        user_dict['_internal']['command_cache'][field.number].append(the_string)
                        logmessage("do_sms: storing in command cache: " + str(the_string))
                    else:
                        for the_field in interview_status.get_field_list():
                            if interview_status.is_empty_mc(the_field):
                                logmessage("do_sms: a field is empty")
                                the_saveas = myb64unquote(the_field.saveas)
                                if 'command_cache' not in user_dict['_internal']:
                                    user_dict['_internal']['command_cache'] = {}
                                if the_field.number not in user_dict['_internal']['command_cache']:
                                    user_dict['_internal']['command_cache'][the_field.number] = []
                                if hasattr(the_field, 'datatype'):
                                    if the_field.datatype in ('object_multiselect', 'object_checkboxes'):
                                        docassemble.base.parse.ensure_object_exists(the_saveas, the_field.datatype,
                                                                                    user_dict, commands=
                                                                                    user_dict['_internal'][
                                                                                        'command_cache'][
                                                                                        the_field.number])
                                        user_dict['_internal']['command_cache'][the_field.number].append(
                                            the_saveas + '.clear()')
                                        user_dict['_internal']['command_cache'][the_field.number].append(
                                            the_saveas + '.gathered = True')
                                    elif the_field.datatype in ('object', 'object_radio'):
                                        try:
                                            eval(the_saveas, user_dict)
                                        except:
                                            user_dict['_internal']['command_cache'][the_field.number].append(
                                                the_saveas + ' = None')
                                    elif the_field.datatype in ('multiselect', 'checkboxes'):
                                        docassemble.base.parse.ensure_object_exists(the_saveas, the_field.datatype,
                                                                                    user_dict, commands=
                                                                                    user_dict['_internal'][
                                                                                        'command_cache'][
                                                                                        the_field.number])
                                        user_dict['_internal']['command_cache'][the_field.number].append(
                                            the_saveas + '.gathered = True')
                                    else:
                                        user_dict['_internal']['command_cache'][the_field.number].append(
                                            the_saveas + ' = None')
                                else:
                                    user_dict['_internal']['command_cache'][the_field.number].append(
                                        the_saveas + ' = None')
                        if 'command_cache' in user_dict['_internal']:
                            for field_num in sorted(user_dict['_internal']['command_cache'].keys()):
                                for pre_string in user_dict['_internal']['command_cache'][field_num]:
                                    logmessage("do_sms: doing command cache: " + pre_string)
                                    exec(pre_string, user_dict)
                        logmessage("do_sms: doing regular: " + the_string)
                        exec(the_string, user_dict)
                        if not changed:
                            steps += 1
                            user_dict['_internal']['steps'] = steps
                            changed = True
                if next_field is None:
                    if skip_it:
                        # Run the commands that we have been storing up
                        if 'command_cache' in user_dict['_internal']:
                            for field_num in sorted(user_dict['_internal']['command_cache'].keys()):
                                for pre_string in user_dict['_internal']['command_cache'][field_num]:
                                    logmessage("do_sms: doing command cache: " + pre_string)
                                    exec(pre_string, user_dict)
                            if not changed:
                                steps += 1
                                user_dict['_internal']['steps'] = steps
                                changed = True
                    logmessage("do_sms: next_field is None")
                    if 'skip' in user_dict['_internal']:
                        user_dict['_internal']['skip'].clear()
                    if 'command_cache' in user_dict['_internal']:
                        user_dict['_internal']['command_cache'].clear()
                    # if 'sms_variable' in interview_status.current_info:
                    #     del interview_status.current_info['sms_variable']
                else:
                    logmessage("do_sms: next_field is not None")
                    user_dict['_internal']['skip'][field.number] = True
                    # user_dict['_internal']['smsgather'] = interview_status.sought
                # if 'smsgather' in user_dict['_internal'] and user_dict['_internal']['smsgather'] == saveas:
                #     #logmessage("do_sms: deleting " + user_dict['_internal']['smsgather'])
                #     del user_dict['_internal']['smsgather']
            except Exception as the_err:
                logmessage("do_sms: failure to set variable with " + the_string)
                logmessage("do_sms: error was " + str(the_err))
                release_lock(sess_info['uid'], sess_info['yaml_filename'])
                # if 'uid' in session:
                #    del session['uid']
                return resp
        if changed and next_field is None and question.name not in user_dict['_internal']['answers']:
            logmessage("do_sms: setting internal answers for " + str(question.name))
            question.mark_as_answered(user_dict)
        interview.assemble(user_dict, interview_status)
        logmessage("do_sms: back from assemble 2; had been seeking variable " + str(interview_status.sought))
        logmessage("do_sms: question is now " + str(interview_status.question.name))
        sess_info['question'] = interview_status.question.name
        r.set(key, pickle.dumps(sess_info))
    else:
        logmessage("do_sms: not accepting input.")
    if interview_status.question.question_type in ("restart", "exit", "logout", "exit_logout", "new_session"):
        logmessage("do_sms: exiting because of restart or exit")
        if save:
            obtain_lock(sess_info['uid'], sess_info['yaml_filename'])
            reset_user_dict(sess_info['uid'], sess_info['yaml_filename'], temp_user_id=sess_info['tempuser'])
            release_lock(sess_info['uid'], sess_info['yaml_filename'])
        r.delete(key)
        if interview_status.question.question_type in ('restart', 'new_session'):
            sess_info = dict(yaml_filename=sess_info['yaml_filename'],
                             uid=get_unique_name(sess_info['yaml_filename'], sess_info['secret']),
                             secret=sess_info['secret'], number=form["From"], encrypted=True,
                             tempuser=sess_info['tempuser'], user_id=None)
            r.set(key, pickle.dumps(sess_info))
            form = dict(To=form['To'], From=form['From'], AccountSid=form['AccountSid'], Body=word('question'))
            return do_sms(form, base_url, url_root, config=config, save=True)
    else:
        if not interview_status.can_go_back:
            user_dict['_internal']['steps_offset'] = steps
        # I had commented this out in do_sms(), but not in index()
        # user_dict['_internal']['answers'] = {}
        # Why do this?
        if (not interview_status.followed_mc) and len(user_dict['_internal']['answers']):
            user_dict['_internal']['answers'].clear()
        # if interview_status.question.name and interview_status.question.name in user_dict['_internal']['answers']:
        #     del user_dict['_internal']['answers'][interview_status.question.name]
        # logmessage("do_sms: " + as_sms(interview_status, user_dict))
        # twilio_client = TwilioRestClient(tconfig['account sid'], tconfig['auth token'])
        # message = twilio_client.messages.create(to=form["From"], from_=form["To"], body=as_sms(interview_status, user_dict))
        logmessage("do_sms: calling as_sms")
        sms_info = as_sms(interview_status, user_dict)
        qoutput = sms_info['question']
        if sms_info['next'] is not None:
            logmessage("do_sms: next variable is " + sms_info['next'])
            if interview_status.sought is None:
                logmessage("do_sms: sought variable is None")
            # user_dict['_internal']['smsgather'] = interview_status.sought
        if (accepting_input or changed or action_performed or sms_info['next'] is not None) and save:
            save_user_dict(sess_info['uid'], user_dict, sess_info['yaml_filename'], secret=sess_info['secret'],
                           encrypt=encrypted, changed=changed, steps=steps)
        for special_message in special_messages:
            qoutput = re.sub(r'XXXXMESSAGE_AREAXXXX', "\n" + special_message + 'XXXXMESSAGE_AREAXXXX', qoutput)
        qoutput = re.sub(r'XXXXMESSAGE_AREAXXXX', '', qoutput)
        if user_dict.get('multi_user', False) is True and encrypted is True:
            encrypted = False
            update_session(sess_info['yaml_filename'], encrypted=encrypted, uid=sess_info['uid'])
            is_encrypted = encrypted
            r.set(key, pickle.dumps(sess_info))
            if save:
                decrypt_session(sess_info['secret'], user_code=sess_info['uid'], filename=sess_info['yaml_filename'])
        if user_dict.get('multi_user', False) is False and encrypted is False:
            encrypted = True
            update_session(sess_info['yaml_filename'], encrypted=encrypted, uid=sess_info['uid'])
            is_encrypted = encrypted
            r.set(key, pickle.dumps(sess_info))
            if save:
                encrypt_session(sess_info['secret'], user_code=sess_info['uid'], filename=sess_info['yaml_filename'])
        if len(interview_status.attachments) > 0:
            with resp.message(qoutput) as m:
                media_count = 0
                for attachment in interview_status.attachments:
                    if media_count >= 9:
                        break
                    for doc_format in attachment['formats_to_use']:
                        if media_count >= 9:
                            break
                        if doc_format not in ('pdf', 'rtf'):
                            continue
                        filename = attachment['filename'] + '.' + docassemble.base.parse.extension_of_doc_format[
                            doc_format]
                        url = url_for('files.serve_stored_file', _external=True, uid=sess_info['uid'],
                                      number=attachment['file'][doc_format], filename=attachment['filename'],
                                      extension=docassemble.base.parse.extension_of_doc_format[doc_format])
                        m.media(url)
                        media_count += 1
        else:
            resp.message(qoutput)
    release_lock(sess_info['uid'], sess_info['yaml_filename'])
    return resp


def get_user_list(include_inactive=False, start_id=None):
    if not (current_user.is_authenticated and current_user.has_role_or_permission('admin', 'advocate',
                                                                                  permissions=['access_user_info',
                                                                                               'create_user'])):
        raise Exception("You do not have sufficient privileges to access information about other users")
    user_length = 0
    user_list = []
    while True:
        there_are_more = False
        filter_list = []
        if start_id is not None:
            filter_list.append(UserModel.id > start_id)
        if not include_inactive:
            filter_list.append(UserModel.active == True)
        the_users = select(UserModel).options(db.joinedload(UserModel.roles))
        if len(filter_list) > 0:
            the_users = the_users.where(*filter_list)
        the_users = the_users.order_by(UserModel.id).limit(PAGINATION_LIMIT_PLUS_ONE)
        results_in_query = 0
        for user in db.session.execute(the_users).unique().scalars():
            results_in_query += 1
            if results_in_query == PAGINATION_LIMIT_PLUS_ONE:
                there_are_more = True
                break
            start_id = user.id
            if user.social_id.startswith('disabled$'):
                continue
            if user_length == PAGINATION_LIMIT:
                there_are_more = True
                break
            user_info = {}
            user_info['privileges'] = []
            for role in user.roles:
                user_info['privileges'].append(role.name)
            for attrib in ('id', 'email', 'first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond',
                           'subdivisionthird', 'organization', 'timezone', 'language'):
                user_info[attrib] = getattr(user, attrib)
            if include_inactive:
                user_info['active'] = getattr(user, 'active')
            user_list.append(user_info)
            user_length += 1
        if user_length == PAGINATION_LIMIT or results_in_query < PAGINATION_LIMIT_PLUS_ONE:
            break
    if not there_are_more:
        start_id = None
    return (user_list, start_id)


@app.route('/translation_file', methods=['POST'])
@login_required
@roles_required(['admin', 'developer'])
def translation_file():
    setup_translation()
    form = Utilities(request.form)
    yaml_filename = form.interview.data
    if yaml_filename is None or not re.search(r'\S', yaml_filename):
        flash(word("You must provide an interview filename"), 'error')
        return redirect(url_for('utilities'))
    tr_lang = form.tr_language.data
    if tr_lang is None or not re.search(r'\S', tr_lang):
        flash(word("You must provide a language"), 'error')
        return redirect(url_for('utilities'))
    try:
        interview_source = docassemble.base.parse.interview_source_from_string(yaml_filename)
    except DAError:
        flash(word("Invalid interview"), 'error')
        return redirect(url_for('utilities'))
    interview_source.update()
    interview_source.translating = True
    interview = interview_source.get_interview()
    tr_cache = {}
    if len(interview.translations) > 0:
        for item in interview.translations:
            if item.lower().endswith(".xlsx"):
                the_xlsx_file = docassemble.base.functions.package_data_filename(item)
                if not os.path.isfile(the_xlsx_file):
                    continue
                df = pandas.read_excel(the_xlsx_file, na_values=['NaN', '-NaN', '#NA', '#N/A'], keep_default_na=False)
                invalid = False
                for column_name in (
                        'interview', 'question_id', 'index_num', 'hash', 'orig_lang', 'tr_lang', 'orig_text',
                        'tr_text'):
                    if column_name not in df.columns:
                        invalid = True
                        break
                if invalid:
                    continue
                for indexno in df.index:
                    try:
                        assert df['interview'][indexno]
                        assert df['question_id'][indexno]
                        assert df['index_num'][indexno] >= 0
                        assert df['hash'][indexno]
                        assert df['orig_lang'][indexno]
                        assert df['tr_lang'][indexno]
                        assert df['orig_text'][indexno] != ''
                        assert df['tr_text'][indexno] != ''
                        if isinstance(df['orig_text'][indexno], float):
                            assert not math.isnan(df['orig_text'][indexno])
                        if isinstance(df['tr_text'][indexno], float):
                            assert not math.isnan(df['tr_text'][indexno])
                    except:
                        continue
                    the_dict = {'interview': str(df['interview'][indexno]),
                                'question_id': str(df['question_id'][indexno]), 'index_num': df['index_num'][indexno],
                                'hash': str(df['hash'][indexno]), 'orig_lang': str(df['orig_lang'][indexno]),
                                'tr_lang': str(df['tr_lang'][indexno]), 'orig_text': str(df['orig_text'][indexno]),
                                'tr_text': str(df['tr_text'][indexno])}
                    if df['orig_text'][indexno] not in tr_cache:
                        tr_cache[df['orig_text'][indexno]] = {}
                    if df['orig_lang'][indexno] not in tr_cache[df['orig_text'][indexno]]:
                        tr_cache[df['orig_text'][indexno]][df['orig_lang'][indexno]] = {}
                    tr_cache[df['orig_text'][indexno]][df['orig_lang'][indexno]][df['tr_lang'][indexno]] = the_dict
            elif item.lower().endswith(".xlf") or item.lower().endswith(".xliff"):
                the_xlf_file = docassemble.base.functions.package_data_filename(item)
                if not os.path.isfile(the_xlf_file):
                    continue
                tree = ET.parse(the_xlf_file)
                root = tree.getroot()
                indexno = 1
                if root.attrib['version'] == "1.2":
                    for the_file in root.iter('{urn:oasis:names:tc:xliff:document:1.2}file'):
                        source_lang = the_file.attrib.get('source-language', 'en')
                        target_lang = the_file.attrib.get('target-language', 'en')
                        source_filename = the_file.attrib.get('original', yaml_filename)
                        for transunit in the_file.iter('{urn:oasis:names:tc:xliff:document:1.2}trans-unit'):
                            orig_text = ''
                            tr_text = ''
                            for source in transunit.iter('{urn:oasis:names:tc:xliff:document:1.2}source'):
                                if source.text:
                                    orig_text += source.text
                                for mrk in source:
                                    orig_text += mrk.text
                                    if mrk.tail:
                                        orig_text += mrk.tail
                            for target in transunit.iter('{urn:oasis:names:tc:xliff:document:1.2}target'):
                                if target.text:
                                    tr_text += target.text
                                for mrk in target:
                                    tr_text += mrk.text
                                    if mrk.tail:
                                        tr_text += mrk.tail
                            if orig_text == '' or tr_text == '':
                                continue
                            the_dict = {'interview': source_filename, 'question_id': 'Unknown' + str(indexno),
                                        'index_num': transunit.attrib.get('id', str(indexno)),
                                        'hash': hashlib.md5(orig_text.encode('utf-8')).hexdigest(),
                                        'orig_lang': source_lang, 'tr_lang': target_lang, 'orig_text': orig_text,
                                        'tr_text': tr_text}
                            if orig_text not in tr_cache:
                                tr_cache[orig_text] = {}
                            if source_lang not in tr_cache[orig_text]:
                                tr_cache[orig_text][source_lang] = {}
                            tr_cache[orig_text][source_lang][target_lang] = the_dict
                            indexno += 1
                elif root.attrib['version'] == "2.0":
                    source_lang = root.attrib['srcLang']
                    target_lang = root.attrib['trgLang']
                    for the_file in root.iter('{urn:oasis:names:tc:xliff:document:2.0}file'):
                        source_filename = the_file.attrib.get('original', yaml_filename)
                        for unit in the_file.iter('{urn:oasis:names:tc:xliff:document:2.0}unit'):
                            question_id = unit.attrib.get('id', 'Unknown' + str(indexno))
                            for segment in unit.iter('{urn:oasis:names:tc:xliff:document:2.0}segment'):
                                orig_text = ''
                                tr_text = ''
                                for source in transunit.iter('{urn:oasis:names:tc:xliff:document:2.0}source'):
                                    if source.text:
                                        orig_text += source.text
                                    for mrk in source:
                                        orig_text += mrk.text
                                        if mrk.tail:
                                            orig_text += mrk.tail
                                for target in transunit.iter('{urn:oasis:names:tc:xliff:document:2.0}target'):
                                    if target.text:
                                        tr_text += target.text
                                    for mrk in target:
                                        tr_text += mrk.text
                                        if mrk.tail:
                                            tr_text += mrk.tail
                                if orig_text == '' or tr_text == '':
                                    continue
                                the_dict = {'interview': source_filename, 'question_id': question_id,
                                            'index_num': segment.attrib.get('id', str(indexno)),
                                            'hash': hashlib.md5(orig_text.encode('utf-8')).hexdigest(),
                                            'orig_lang': source_lang, 'tr_lang': target_lang, 'orig_text': orig_text,
                                            'tr_text': tr_text}
                                if orig_text not in tr_cache:
                                    tr_cache[orig_text] = {}
                                if source_lang not in tr_cache[orig_text]:
                                    tr_cache[orig_text][source_lang] = {}
                                tr_cache[orig_text][source_lang][target_lang] = the_dict
                                indexno += 1
    if form.filetype.data == 'XLSX':
        temp_file = tempfile.NamedTemporaryFile(suffix='.xlsx', delete=False)
        xlsx_filename = docassemble.base.functions.space_to_underscore(
            os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + tr_lang + ".xlsx"
        workbook = xlsxwriter.Workbook(temp_file.name)
        worksheet = workbook.add_worksheet()
        bold = workbook.add_format({'bold': 1})
        text = workbook.add_format()
        text.set_align('top')
        fixedcell = workbook.add_format()
        fixedcell.set_align('top')
        fixedcell.set_text_wrap()
        fixedunlockedcell = workbook.add_format()
        fixedunlockedcell.set_align('top')
        fixedunlockedcell.set_text_wrap()
        # fixedunlockedcell.set_locked(False)
        fixed = workbook.add_format()
        fixedone = workbook.add_format()
        fixedone.set_bold()
        fixedone.set_font_color('green')
        fixedtwo = workbook.add_format()
        fixedtwo.set_bold()
        fixedtwo.set_font_color('blue')
        fixedunlocked = workbook.add_format()
        fixedunlockedone = workbook.add_format()
        fixedunlockedone.set_bold()
        fixedunlockedone.set_font_color('green')
        fixedunlockedtwo = workbook.add_format()
        fixedunlockedtwo.set_bold()
        fixedunlockedtwo.set_font_color('blue')
        wholefixed = workbook.add_format()
        wholefixed.set_align('top')
        wholefixed.set_text_wrap()
        wholefixedone = workbook.add_format()
        wholefixedone.set_bold()
        wholefixedone.set_font_color('green')
        wholefixedone.set_align('top')
        wholefixedone.set_text_wrap()
        wholefixedtwo = workbook.add_format()
        wholefixedtwo.set_bold()
        wholefixedtwo.set_font_color('blue')
        wholefixedtwo.set_align('top')
        wholefixedtwo.set_text_wrap()
        wholefixedunlocked = workbook.add_format()
        wholefixedunlocked.set_align('top')
        wholefixedunlocked.set_text_wrap()
        # wholefixedunlocked.set_locked(False)
        wholefixedunlockedone = workbook.add_format()
        wholefixedunlockedone.set_bold()
        wholefixedunlockedone.set_font_color('green')
        wholefixedunlockedone.set_align('top')
        wholefixedunlockedone.set_text_wrap()
        # wholefixedunlockedone.set_locked(False)
        wholefixedunlockedtwo = workbook.add_format()
        wholefixedunlockedtwo.set_bold()
        wholefixedunlockedtwo.set_font_color('blue')
        wholefixedunlockedtwo.set_align('top')
        wholefixedunlockedtwo.set_text_wrap()
        # wholefixedunlockedtwo.set_locked(False)
        numb = workbook.add_format()
        numb.set_align('top')
        worksheet.write('A1', 'interview', bold)
        worksheet.write('B1', 'question_id', bold)
        worksheet.write('C1', 'index_num', bold)
        worksheet.write('D1', 'hash', bold)
        worksheet.write('E1', 'orig_lang', bold)
        worksheet.write('F1', 'tr_lang', bold)
        worksheet.write('G1', 'orig_text', bold)
        worksheet.write('H1', 'tr_text', bold)
        # options = {
        #     'objects':               False,
        #     'scenarios':             False,
        #     'format_cells':          False,
        #     'format_columns':        False,
        #     'format_rows':           False,
        #     'insert_columns':        False,
        #     'insert_rows':           True,
        #     'insert_hyperlinks':     False,
        #     'delete_columns':        False,
        #     'delete_rows':           True,
        #     'select_locked_cells':   True,
        #     'sort':                  True,
        #     'autofilter':            True,
        #     'pivot_tables':          False,
        #     'select_unlocked_cells': True,
        # }
        # worksheet.protect('', options)
        worksheet.set_column(0, 0, 25)
        worksheet.set_column(1, 1, 15)
        worksheet.set_column(2, 2, 12)
        worksheet.set_column(6, 6, 75)
        worksheet.set_column(6, 7, 75)
        row = 1
        seen = []
        for question in interview.all_questions:
            if not hasattr(question, 'translations'):
                continue
            language = question.language
            if language == '*':
                language = question.from_source.get_language()
            if language == '*':
                language = interview.default_language
            if language == tr_lang:
                continue
            indexno = 0
            if hasattr(question, 'id'):
                question_id = question.id
            else:
                question_id = question.name
            for item in question.translations:
                if item in seen:
                    continue
                if item in tr_cache and language in tr_cache[item] and tr_lang in tr_cache[item][language]:
                    tr_text = str(tr_cache[item][language][tr_lang]['tr_text'])
                else:
                    tr_text = ''
                worksheet.write_string(row, 0, question.from_source.get_name(), text)
                worksheet.write_string(row, 1, question_id, text)
                worksheet.write_number(row, 2, indexno, numb)
                worksheet.write_string(row, 3, hashlib.md5(item.encode('utf-8')).hexdigest(), text)
                worksheet.write_string(row, 4, language, text)
                worksheet.write_string(row, 5, tr_lang, text)
                mako = mako_parts(item)
                if len(mako) == 0:
                    worksheet.write_string(row, 6, '', wholefixed)
                elif len(mako) == 1:
                    if mako[0][1] == 0:
                        worksheet.write_string(row, 6, item, wholefixed)
                    elif mako[0][1] == 1:
                        worksheet.write_string(row, 6, item, wholefixedone)
                    elif mako[0][1] == 2:
                        worksheet.write_string(row, 6, item, wholefixedtwo)
                else:
                    parts = [row, 6]
                    for part in mako:
                        if part[1] == 0:
                            parts.extend([fixed, part[0]])
                        elif part[1] == 1:
                            parts.extend([fixedone, part[0]])
                        elif part[1] == 2:
                            parts.extend([fixedtwo, part[0]])
                    parts.append(fixedcell)
                    worksheet.write_rich_string(*parts)
                mako = mako_parts(tr_text)
                if len(mako) == 0:
                    worksheet.write_string(row, 7, '', wholefixedunlocked)
                elif len(mako) == 1:
                    if mako[0][1] == 0:
                        worksheet.write_string(row, 7, tr_text, wholefixedunlocked)
                    elif mako[0][1] == 1:
                        worksheet.write_string(row, 7, tr_text, wholefixedunlockedone)
                    elif mako[0][1] == 2:
                        worksheet.write_string(row, 7, tr_text, wholefixedunlockedtwo)
                else:
                    parts = [row, 7]
                    for part in mako:
                        if part[1] == 0:
                            parts.extend([fixedunlocked, part[0]])
                        elif part[1] == 1:
                            parts.extend([fixedunlockedone, part[0]])
                        elif part[1] == 2:
                            parts.extend([fixedunlockedtwo, part[0]])
                    parts.append(fixedunlockedcell)
                    worksheet.write_rich_string(*parts)
                num_lines = item.count('\n')
                # if num_lines > 25:
                #    num_lines = 25
                if num_lines > 0:
                    worksheet.set_row(row, 15 * (num_lines + 1))
                indexno += 1
                row += 1
                seen.append(item)
        for item in tr_cache:
            if item in seen or language not in tr_cache[item] or tr_lang not in tr_cache[item][language]:
                continue
            worksheet.write_string(row, 0, tr_cache[item][language][tr_lang]['interview'], text)
            worksheet.write_string(row, 1, tr_cache[item][language][tr_lang]['question_id'], text)
            worksheet.write_number(row, 2, 1000 + tr_cache[item][language][tr_lang]['index_num'], numb)
            worksheet.write_string(row, 3, tr_cache[item][language][tr_lang]['hash'], text)
            worksheet.write_string(row, 4, tr_cache[item][language][tr_lang]['orig_lang'], text)
            worksheet.write_string(row, 5, tr_cache[item][language][tr_lang]['tr_lang'], text)
            mako = mako_parts(tr_cache[item][language][tr_lang]['orig_text'])
            if len(mako) == 1:
                if mako[0][1] == 0:
                    worksheet.write_string(row, 6, tr_cache[item][language][tr_lang]['orig_text'], wholefixed)
                elif mako[0][1] == 1:
                    worksheet.write_string(row, 6, tr_cache[item][language][tr_lang]['orig_text'], wholefixedone)
                elif mako[0][1] == 2:
                    worksheet.write_string(row, 6, tr_cache[item][language][tr_lang]['orig_text'], wholefixedtwo)
            else:
                parts = [row, 6]
                for part in mako:
                    if part[1] == 0:
                        parts.extend([fixed, part[0]])
                    elif part[1] == 1:
                        parts.extend([fixedone, part[0]])
                    elif part[1] == 2:
                        parts.extend([fixedtwo, part[0]])
                parts.append(fixedcell)
                worksheet.write_rich_string(*parts)
            mako = mako_parts(tr_cache[item][language][tr_lang]['tr_text'])
            if len(mako) == 1:
                if mako[0][1] == 0:
                    worksheet.write_string(row, 7, tr_cache[item][language][tr_lang]['tr_text'], wholefixedunlocked)
                elif mako[0][1] == 1:
                    worksheet.write_string(row, 7, tr_cache[item][language][tr_lang]['tr_text'], wholefixedunlockedone)
                elif mako[0][1] == 2:
                    worksheet.write_string(row, 7, tr_cache[item][language][tr_lang]['tr_text'], wholefixedunlockedtwo)
            else:
                parts = [row, 7]
                for part in mako:
                    if part[1] == 0:
                        parts.extend([fixedunlocked, part[0]])
                    elif part[1] == 1:
                        parts.extend([fixedunlockedone, part[0]])
                    elif part[1] == 2:
                        parts.extend([fixedunlockedtwo, part[0]])
                parts.append(fixedunlockedcell)
                worksheet.write_rich_string(*parts)
            num_lines = tr_cache[item][language][tr_lang]['orig_text'].count('\n')
            if num_lines > 0:
                worksheet.set_row(row, 15 * (num_lines + 1))
            row += 1
        workbook.close()
        response = send_file(temp_file.name,
                             mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                             as_attachment=True, attachment_filename=xlsx_filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    if form.filetype.data.startswith('XLIFF'):
        seen = set()
        translations = {}
        xliff_files = []
        if form.filetype.data == 'XLIFF 1.2':
            for question in interview.all_questions:
                if not hasattr(question, 'translations'):
                    continue
                language = question.language
                if language == '*':
                    language = interview_source.language
                if language == '*':
                    language = DEFAULT_LANGUAGE
                if language == tr_lang:
                    continue
                question_id = question.name
                lang_combo = (language, tr_lang)
                if lang_combo not in translations:
                    translations[lang_combo] = []
                for item in question.translations:
                    if item in seen:
                        continue
                    if item in tr_cache and language in tr_cache[item] and tr_lang in tr_cache[item][language]:
                        tr_text = str(tr_cache[item][language][tr_lang]['tr_text'])
                    else:
                        tr_text = ''
                    orig_mako = mako_parts(item)
                    tr_mako = mako_parts(tr_text)
                    translations[lang_combo].append([orig_mako, tr_mako])
                    seen.add(item)
            for lang_combo, translation_list in translations.items():
                temp_file = tempfile.NamedTemporaryFile(suffix='.xlf', delete=False)
                if len(translations) > 1:
                    xlf_filename = docassemble.base.functions.space_to_underscore(
                        os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + lang_combo[
                                       0] + "_" + lang_combo[1] + ".xlf"
                else:
                    xlf_filename = docassemble.base.functions.space_to_underscore(
                        os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + lang_combo[
                                       1] + ".xlf"
                xliff = ET.Element('xliff')
                xliff.set('xmlns', 'urn:oasis:names:tc:xliff:document:1.2')
                xliff.set('version', '1.2')
                indexno = 1
                the_file = ET.SubElement(xliff, 'file')
                the_file.set('id', 'f1')
                the_file.set('original', yaml_filename)
                the_file.set('xml:space', 'preserve')
                the_file.set('source-language', lang_combo[0])
                the_file.set('target-language', lang_combo[1])
                body = ET.SubElement(the_file, 'body')
                for item in translation_list:
                    transunit = ET.SubElement(body, 'trans-unit')
                    transunit.set('id', str(indexno))
                    transunit.set('xml:space', 'preserve')
                    source = ET.SubElement(transunit, 'source')
                    source.set('xml:space', 'preserve')
                    target = ET.SubElement(transunit, 'target')
                    target.set('xml:space', 'preserve')
                    last_elem = None
                    for (elem, i) in ((source, 0), (target, 1)):
                        if len(item[i]) == 0:
                            elem.text = ''
                        elif len(item[i]) == 1 and item[i][0][1] == 0:
                            elem.text = item[i][0][0]
                        else:
                            for part in item[i]:
                                if part[1] == 0:
                                    if last_elem is None:
                                        if elem.text is None:
                                            elem.text = ''
                                        elem.text += part[0]
                                    else:
                                        if last_elem.tail is None:
                                            last_elem.tail = ''
                                        last_elem.tail += part[0]
                                else:
                                    mrk = ET.SubElement(elem, 'mrk')
                                    mrk.set('xml:space', 'preserve')
                                    mrk.set('mtype', 'protected')
                                    mrk.text = part[0]
                                    last_elem = mrk
                    indexno += 1
                temp_file.write(ET.tostring(xliff))
                temp_file.close()
                xliff_files.append([temp_file, xlf_filename])
        elif form.filetype.data == 'XLIFF 2.0':
            for question in interview.all_questions:
                if not hasattr(question, 'translations'):
                    continue
                language = question.language
                if language == '*':
                    language = interview_source.language
                if language == '*':
                    language = DEFAULT_LANGUAGE
                if language == tr_lang:
                    continue
                question_id = question.name
                lang_combo = (language, tr_lang)
                if lang_combo not in translations:
                    translations[lang_combo] = {}
                filename = question.from_source.get_name()
                if filename not in translations[lang_combo]:
                    translations[lang_combo][filename] = {}
                if question_id not in translations[lang_combo][filename]:
                    translations[lang_combo][filename][question_id] = []
                for item in question.translations:
                    if item in seen:
                        continue
                    if item in tr_cache and language in tr_cache[item] and tr_lang in tr_cache[item][language]:
                        tr_text = str(tr_cache[item][language][tr_lang]['tr_text'])
                    else:
                        tr_text = ''
                    orig_mako = mako_parts(item)
                    tr_mako = mako_parts(tr_text)
                    translations[lang_combo][filename][question_id].append([orig_mako, tr_mako])
                    seen.add(item)
            for lang_combo, translations_by_filename in translations.items():
                temp_file = tempfile.NamedTemporaryFile(suffix='.xlf', delete=False)
                if len(translations) > 1:
                    xlf_filename = docassemble.base.functions.space_to_underscore(
                        os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + lang_combo[
                                       0] + "_" + lang_combo[1] + ".xlf"
                else:
                    xlf_filename = docassemble.base.functions.space_to_underscore(
                        os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + lang_combo[
                                       1] + ".xlf"
                xliff = ET.Element('xliff')
                xliff.set('xmlns', 'urn:oasis:names:tc:xliff:document:2.0')
                xliff.set('version', '2.0')
                xliff.set('srcLang', lang_combo[0])
                xliff.set('trgLang', lang_combo[1])
                file_index = 1
                indexno = 1
                for filename, translations_by_question in translations_by_filename.items():
                    the_file = ET.SubElement(xliff, 'file')
                    the_file.set('id', 'f' + str(file_index))
                    the_file.set('original', filename)
                    the_file.set('xml:space', 'preserve')
                    for question_id, translation_list in translations_by_question.items():
                        unit = ET.SubElement(the_file, 'unit')
                        unit.set('id', question_id)
                        for item in translation_list:
                            segment = ET.SubElement(unit, 'segment')
                            segment.set('id', str(indexno))
                            segment.set('xml:space', 'preserve')
                            source = ET.SubElement(segment, 'source')
                            source.set('xml:space', 'preserve')
                            target = ET.SubElement(segment, 'target')
                            target.set('xml:space', 'preserve')
                            last_elem = None
                            for (elem, i) in ((source, 0), (target, 1)):
                                if len(item[i]) == 0:
                                    elem.text = ''
                                elif len(item[i]) == 1 and item[i][0][1] == 0:
                                    elem.text = item[i][0][0]
                                else:
                                    for part in item[i]:
                                        if part[1] == 0:
                                            if last_elem is None:
                                                if elem.text is None:
                                                    elem.text = ''
                                                elem.text += part[0]
                                            else:
                                                if last_elem.tail is None:
                                                    last_elem.tail = ''
                                                last_elem.tail += part[0]
                                        else:
                                            mrk = ET.SubElement(elem, 'mrk')
                                            mrk.set('xml:space', 'preserve')
                                            mrk.set('translate', 'no')
                                            mrk.text = part[0]
                                            last_elem = mrk
                            indexno += 1
                    file_index += 1
                temp_file.write(ET.tostring(xliff))
                temp_file.close()
                xliff_files.append([temp_file, xlf_filename])
        else:
            flash(word("Bad file format"), 'error')
            return redirect(url_for('utilities'))
        if len(xliff_files) == 1:
            response = send_file(xliff_files[0][0].name, mimetype='application/xml', as_attachment=True,
                                 attachment_filename=xliff_files[0][1])
        else:
            zip_file = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
            zip_file_name = docassemble.base.functions.space_to_underscore(
                os.path.splitext(os.path.basename(re.sub(r'.*:', '', yaml_filename)))[0]) + "_" + tr_lang + ".zip"
            with zipfile.ZipFile(zip_file, mode='w') as zf:
                for item in xliff_files:
                    info = zipfile.ZipInfo(item[1])
                    with open(item[0].name, 'rb') as fp:
                        zf.writestr(info, fp.read())
                zf.close()
            response = send_file(zip_file.name, mimetype='application/xml', as_attachment=True,
                                 attachment_filename=zip_file_name)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    flash(word("Bad file format"), 'error')
    return redirect(url_for('utilities'))


@app.route('/api/user_list', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_user_list():
    if not api_verify(request, roles=['admin', 'advocate'], permissions=['access_user_info']):
        return jsonify_with_status("Access denied.", 403)
    include_inactive = true_or_false(request.args.get('include_inactive', False))
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
        except:
            start_id = None
    else:
        start_id = None
    try:
        (user_list, start_id) = get_user_list(include_inactive=include_inactive, start_id=start_id)
    except Exception as err:
        return jsonify_with_status(str(err), 400)
    if start_id is None:
        next_id = None
    else:
        next_id = safeid(str(start_id))
    return jsonify(dict(next_id=next_id, items=user_list))


@app.route('/api/fields', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_fields():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['template_parse']):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    output_format = post_data.get('format', 'json')
    if output_format not in ('json', 'yaml'):
        return jsonify_with_status("Invalid output format.", 400)
    if 'template' not in request.files:
        return jsonify_with_status("File not included.", 400)
    the_files = request.files.getlist('template')
    if not the_files:
        return jsonify_with_status("File not included.", 400)
    for the_file in the_files:
        filename = secure_filename(the_file.filename)
        temp_file = tempfile.NamedTemporaryFile(prefix="datemp", delete=False)
        the_file.save(temp_file.name)
        try:
            input_format = os.path.splitext(filename.lower())[1][1:]
        except:
            input_format = 'bin'
        if input_format == 'md':
            input_format = 'markdown'
        if input_format not in ('docx', 'markdown', 'pdf'):
            return jsonify_with_status("Invalid input format.", 400)
        try:
            output = read_fields(temp_file.name, filename, input_format, output_format)
        except Exception as err:
            logmessage("api_fields: got error " + err.__class__.__name__ + ": " + str(err))
            if output_format == 'yaml':
                return jsonify_with_status("No fields could be found.", 400)
            else:
                return jsonify(dict(fields=[]))
        break
    if output_format == 'yaml':
        response = make_response(output.encode('utf-8'), '200 OK')
        response.headers['Content-type'] = 'text/plain; charset=utf-8'
    else:
        response = make_response(output.encode('utf-8'), 200)
        response.headers['Content-Type'] = 'application/json; charset=utf-8'
    return response


@app.route('/api/privileges', methods=['GET', 'DELETE', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'POST', 'HEAD'], automatic_options=True)
def api_privileges():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if request.method == 'GET':
        try:
            return jsonify(get_privileges_list())
        except Exception as err:
            return jsonify_with_status(str(err), 400)
    if request.method == 'DELETE':
        if not current_user.has_role_or_permission('admin', permissions=['edit_privileges']):
            return jsonify_with_status("Access denied.", 403)
        if 'privilege' not in request.args:
            return jsonify_with_status("A privilege name must be provided.", 400)
        try:
            remove_privilege(request.args['privilege'])
        except Exception as err:
            return jsonify_with_status(str(err), 400)
        return ('', 204)
    if request.method == 'POST':
        if not current_user.has_role_or_permission('admin', permissions=['edit_privileges']):
            return jsonify_with_status("Access denied.", 403)
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        if 'privilege' not in post_data:
            return jsonify_with_status("A privilege name must be provided.", 400)
        try:
            add_privilege(post_data['privilege'])
        except Exception as err:
            return jsonify_with_status(str(err), 400)
        return ('', 204)


def get_permissions_of_privilege(privilege):
    if not current_user.has_role_or_permission('admin', 'developer', permissions=['access_privileges']):
        raise Exception('You do not have sufficient privileges to inspect privileges.')
    if privilege == 'admin':
        return copy.copy(PERMISSIONS_LIST)
    if privilege == 'developer':
        return ['demo_interviews', 'template_parse', 'interview_data']
    if privilege == 'advocate':
        return ['access_user_info', 'access_sessions', 'edit_sessions']
    if privilege == 'cron':
        return []
    if privilege in docassemble.base.config.allowed:
        return list(docassemble.base.config.allowed[privilege])
    return []


def add_privilege(privilege):
    if not current_user.has_role_or_permission('admin', permissions=['edit_privileges']):
        raise Exception('You do not have sufficient privileges to add a privilege.')
    role_names = get_privileges_list()
    if privilege in role_names:
        raise Exception("The given privilege already exists.")
    db.session.add(Role(name=privilege))
    db.session.commit()


def remove_privilege(privilege):
    if not current_user.has_role_or_permission('admin', permissions=['edit_privileges']):
        raise Exception('You do not have sufficient privileges to delete a privilege.')
    if privilege in ['user', 'admin', 'developer', 'advocate', 'cron']:
        raise Exception('The specified privilege is built-in and cannot be deleted.')
    user_role = db.session.execute(select(Role).filter_by(name='user')).scalar()
    role = db.session.execute(select(Role).filter_by(name=privilege)).scalar()
    if role is None:
        raise Exception('The privilege ' + str(privilege) + ' did not exist.')
    db.session.delete(role)
    db.session.commit()


@app.route('/api/secret', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_get_secret():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    username = request.args.get('username', None)
    password = request.args.get('password', None)
    if username is None or password is None:
        return jsonify_with_status("A username and password must be supplied", 400)
    try:
        secret = get_secret(str(username), str(password))
    except Exception as err:
        return jsonify_with_status(str(err), 403)
    return jsonify(secret)


def get_secret(username, password, case_sensitive=False):
    if case_sensitive:
        user = db.session.execute(select(UserModel).filter_by(email=username)).scalar()
    else:
        username = re.sub(r'\%', '', username)
        user = db.session.execute(select(UserModel).where(UserModel.email.ilike(username))).scalar()
    if user is None:
        raise Exception("Username not known")
    if app.config['USE_MFA'] and user.otp_secret is not None:
        raise Exception("Secret will not be supplied because two factor authentication is enabled")
    user_manager = current_app.user_manager
    if not user_manager.get_password(user):
        raise Exception("Password not set")
    if not user_manager.verify_password(password, user):
        raise Exception("Incorrect password")
    return pad_to_16(MD5Hash(data=password).hexdigest())


def parse_api_sessions_query(query):
    if query is None or query.strip() == '':
        return None
    if illegal_sessions_query(query):
        raise Exception("Illegal query")
    return eval(query, {'DA': docassemble.base.DA})


@app.route('/api/users/interviews', methods=['GET', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'HEAD'], automatic_options=True)
def api_users_interviews():
    if not api_verify(request, roles=['admin', 'advocate'], permissions=['access_sessions']):
        return jsonify_with_status("Access denied.", 403)
    user_id = request.args.get('user_id', None)
    filename = request.args.get('i', None)
    session_id = request.args.get('session', None)
    query = request.args.get('query', None)
    try:
        query = parse_api_sessions_query(query)
    except:
        return jsonify_with_status("Invalid query parameter", 400)
    secret = request.args.get('secret', None)
    tag = request.args.get('tag', None)
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
        except:
            start_id = None
    else:
        start_id = None
    if secret is not None:
        secret = str(secret)
    if request.method == 'GET':
        include_dict = true_or_false(request.args.get('include_dictionary', False))
        try:
            (the_list, start_id) = user_interviews(user_id=user_id, secret=secret, exclude_invalid=False, tag=tag,
                                                   filename=filename, session=session_id, query=query,
                                                   include_dict=include_dict, start_id=start_id)
        except Exception as err:
            return jsonify_with_status("Error getting interview list.  " + str(err), 400)
        if start_id is None:
            next_id = None
        else:
            next_id = safeid(str(start_id))
        return jsonify(dict(next_id=next_id, items=docassemble.base.functions.safe_json(the_list)))
    if request.method == 'DELETE':
        start_id = None
        while True:
            try:
                (the_list, start_id) = user_interviews(user_id=user_id, exclude_invalid=False, tag=tag,
                                                       filename=filename, session=session_id, query=query,
                                                       include_dict=False, start_id=start_id)
            except:
                return jsonify_with_status("Error reading interview list.", 400)
            for info in the_list:
                user_interviews(user_id=info['user_id'], action='delete', filename=info['filename'],
                                session=info['session'])
            if start_id is None:
                break
        return ('', 204)
    return ('', 204)


@app.route('/api/user/<int:user_id>/interviews', methods=['GET', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'HEAD'], automatic_options=True)
def api_user_user_id_interviews(user_id):
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if not (current_user.id == user_id or current_user.has_role_or_permission('admin', 'advocate',
                                                                              permissions=['access_sessions'])):
        return jsonify_with_status("Access denied.", 403)
    filename = request.args.get('i', None)
    session_id = request.args.get('session', None)
    query = request.args.get('query', None)
    try:
        query = parse_api_sessions_query(query)
    except:
        return jsonify_with_status("Invalid query parameter", 400)
    secret = request.args.get('secret', None)
    tag = request.args.get('tag', None)
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
        except:
            start_id = None
    else:
        start_id = None
    if secret is not None:
        secret = str(secret)
    include_dict = true_or_false(request.args.get('include_dictionary', False))
    if request.method == 'GET':
        try:
            (the_list, start_id) = user_interviews(user_id=user_id, secret=secret, exclude_invalid=False, tag=tag,
                                                   filename=filename, session=session_id, query=query,
                                                   include_dict=include_dict, start_id=start_id)
        except:
            return jsonify_with_status("Error reading interview list.", 400)
        if start_id is None:
            next_id = None
        else:
            next_id = safeid(str(start_id))
        return jsonify(dict(next_id=next_id, items=docassemble.base.functions.safe_json(the_list)))
    if request.method == 'DELETE':
        start_id = None
        while True:
            try:
                (the_list, start_id) = user_interviews(user_id=user_id, exclude_invalid=False, tag=tag,
                                                       filename=filename, session=session_id, query=query,
                                                       include_dict=False, start_id=start_id)
            except:
                return jsonify_with_status("Error reading interview list.", 400)
            for info in the_list:
                user_interviews(user_id=info['user_id'], action='delete', filename=info['filename'],
                                session=info['session'])
            if start_id is None:
                break
        return ('', 204)
    return ('', 204)


@app.route('/api/session/back', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_session_back():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    yaml_filename = post_data.get('i', None)
    session_id = post_data.get('session', None)
    secret = str(post_data.get('secret', None))
    reply_with_question = true_or_false(post_data.get('question', True))
    if yaml_filename is None or session_id is None:
        return jsonify_with_status("Parameters i and session are required.", 400)
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        data = go_back_in_session(yaml_filename, session_id, secret=secret, return_question=reply_with_question)
    except Exception as the_err:
        return jsonify_with_status(str(the_err), 400)
    if data is None:
        return ('', 204)
    if data.get('questionType', None) is 'response':
        return data['response']
    return jsonify(**data)


@app.route('/api/session', methods=['GET', 'POST', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'HEAD'], automatic_options=True)
def api_session():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if request.method == 'GET':
        yaml_filename = request.args.get('i', None)
        session_id = request.args.get('session', None)
        secret = request.args.get('secret', None)
        if secret is not None:
            secret = str(secret)
        if yaml_filename is None or session_id is None:
            return jsonify_with_status("Parameters i and session are required.", 400)
        docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
        try:
            variables = get_session_variables(yaml_filename, session_id, secret=secret)
        except Exception as the_err:
            return jsonify_with_status(str(the_err), 400)
        return jsonify(variables)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        yaml_filename = post_data.get('i', None)
        session_id = post_data.get('session', None)
        secret = str(post_data.get('secret', None))
        question_name = post_data.get('question_name', None)
        treat_as_raw = true_or_false(post_data.get('raw', False))
        advance_progress_meter = true_or_false(post_data.get('advance_progress_meter', False))
        post_setting = not true_or_false(post_data.get('overwrite', False))
        reply_with_question = true_or_false(post_data.get('question', True))
        if yaml_filename is None or session_id is None:
            return jsonify_with_status("Parameters i and session are required.", 400)
        docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
        if 'variables' in post_data and isinstance(post_data['variables'], dict):
            variables = post_data['variables']
        else:
            try:
                variables = json.loads(post_data.get('variables', '{}'))
            except:
                return jsonify_with_status("Malformed variables.", 400)
        if not treat_as_raw:
            variables = transform_json_variables(variables)
        if 'file_variables' in post_data and isinstance(post_data['file_variables'], dict):
            file_variables = post_data['file_variables']
        else:
            try:
                file_variables = json.loads(post_data.get('file_variables', '{}'))
            except:
                return jsonify_with_status("Malformed list of file variables.", 400)
        if 'delete_variables' in post_data and isinstance(post_data['delete_variables'], list):
            del_variables = post_data['delete_variables']
        else:
            try:
                del_variables = json.loads(post_data.get('delete_variables', '[]'))
            except:
                return jsonify_with_status("Malformed list of delete variables.", 400)
        if 'event_list' in post_data and isinstance(post_data['event_list'], list):
            event_list = post_data['event_list']
        else:
            try:
                event_list = json.loads(post_data.get('event_list', '[]'))
                assert isinstance(event_list, list)
            except:
                return jsonify_with_status("Malformed event list.", 400)
        if not isinstance(variables, dict):
            return jsonify_with_status("Variables data is not a dict.", 400)
        if not isinstance(file_variables, dict):
            return jsonify_with_status("File variables data is not a dict.", 400)
        if not isinstance(del_variables, list):
            return jsonify_with_status("Delete variables data is not a list.", 400)
        if not isinstance(event_list, list):
            return jsonify_with_status("Event list data is not a list.", 400)
        files = []
        literal_variables = {}
        for filekey in request.files:
            if filekey not in file_variables:
                file_variables[filekey] = filekey
            the_files = request.files.getlist(filekey)
            files_to_process = []
            if the_files:
                for the_file in the_files:
                    filename = secure_filename(the_file.filename)
                    file_number = get_new_file_number(session_id, filename, yaml_file_name=yaml_filename)
                    extension, mimetype = get_ext_and_mimetype(filename)
                    saved_file = SavedFile(file_number, extension=extension, fix=True, should_not_exist=True)
                    temp_file = tempfile.NamedTemporaryFile(prefix="datemp", suffix='.' + extension, delete=False)
                    the_file.save(temp_file.name)
                    process_file(saved_file, temp_file.name, mimetype, extension)
                    files_to_process.append((filename, file_number, mimetype, extension))
            file_field = file_variables[filekey]
            if illegal_variable_name(file_field):
                return jsonify_with_status("Malformed file variable.", 400)
            if len(files_to_process) > 0:
                elements = []
                indexno = 0
                for (filename, file_number, mimetype, extension) in files_to_process:
                    elements.append("docassemble.base.util.DAFile(" + repr(
                        file_field + '[' + str(indexno) + ']') + ", filename=" + repr(filename) + ", number=" + str(
                        file_number) + ", make_pngs=True, mimetype=" + repr(mimetype) + ", extension=" + repr(
                        extension) + ")")
                    indexno += 1
                literal_variables[file_field] = "docassemble.base.util.DAFileList(" + repr(
                    file_field) + ", elements=[" + ", ".join(elements) + "])"
            else:
                literal_variables[file_field] = "None"
        try:
            data = set_session_variables(yaml_filename, session_id, variables, secret=secret,
                                         return_question=reply_with_question, literal_variables=literal_variables,
                                         del_variables=del_variables, question_name=question_name,
                                         event_list=event_list, advance_progress_meter=advance_progress_meter,
                                         post_setting=post_setting)
        except Exception as the_err:
            return jsonify_with_status(str(the_err), 400)
        if data is None:
            return ('', 204)
        if data.get('questionType', None) is 'response':
            return data['response']
        return jsonify(**data)
    if request.method == 'DELETE':
        yaml_filename = request.args.get('i', None)
        session_id = request.args.get('session', None)
        if yaml_filename is None or session_id is None:
            return jsonify_with_status("Parameters i and session are required.", 400)
        user_interviews(action='delete', filename=yaml_filename, session=session_id)
        return ('', 204)
    return ('', 204)


@app.route('/api/file/<int:file_number>', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_file(file_number):
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if request.method == 'GET':
        yaml_filename = request.args.get('i', None)
        session_id = request.args.get('session', None)
        number = re.sub(r'[^0-9]', '', str(file_number))
        privileged = bool(current_user.is_authenticated and current_user.has_role('admin', 'advocate'))
        try:
            file_info = get_info_from_file_number(number, privileged=privileged, uids=get_session_uids())
        except:
            return ('File not found', 404)
        if 'path' not in file_info:
            return ('File not found', 404)
        else:
            if 'extension' in request.args:
                extension = werkzeug.utils.secure_filename(request.args['extension'])
                if os.path.isfile(file_info['path'] + '.' + extension):
                    the_path = file_info['path'] + '.' + extension
                    extension, mimetype = get_ext_and_mimetype(file_info['path'] + '.' + extension)
                else:
                    return ('File not found', 404)
            elif 'filename' in request.args:
                the_filename = secure_filename_spaces_ok(request.args['filename'])
                if os.path.isfile(os.path.join(os.path.dirname(file_info['path']), the_filename)):
                    the_path = os.path.join(os.path.dirname(file_info['path']), the_filename)
                    extension, mimetype = get_ext_and_mimetype(the_filename)
                else:
                    return ('File not found', 404)
            else:
                the_path = file_info['path']
                mimetype = file_info['mimetype']
            if not os.path.isfile(the_path):
                return ('File not found', 404)
            response = send_file(the_path, mimetype=mimetype)
            response.headers[
                'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            return response
        return ('File not found', 404)


def get_session_variables(yaml_filename, session_id, secret=None, simplify=True, use_lock=False):
    if use_lock:
        obtain_lock(session_id, yaml_filename)
    # sys.stderr.write("get_session_variables: fetch_user_dict\n")
    if secret is None:
        secret = docassemble.base.functions.this_thread.current_info.get('secret', None)
    tbackup = docassemble.base.functions.backup_thread_variables()
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=str(secret))
    except Exception as the_err:
        if use_lock:
            release_lock(session_id, yaml_filename)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to decrypt interview dictionary: " + str(the_err))
    if use_lock:
        release_lock(session_id, yaml_filename)
    docassemble.base.functions.restore_thread_variables(tbackup)
    if user_dict is None:
        raise Exception("Unable to obtain interview dictionary.")
    if simplify:
        variables = docassemble.base.functions.serializable_dict(user_dict, include_internal=True)
        # variables['_internal'] = docassemble.base.functions.serializable_dict(user_dict['_internal'])
        return variables
    return user_dict


@app.route('/api/session/new', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_session_new():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        return jsonify_with_status("Parameter i is required.", 400)
    secret = request.args.get('secret', None)
    if secret is None:
        new_secret = True
        secret = random_string(16)
    else:
        new_secret = False
    secret = str(secret)
    url_args = {}
    for argname in request.args:
        if argname in ('i', 'secret', 'key'):
            continue
        if re.match('[A-Za-z_][A-Za-z0-9_]*', argname):
            url_args[argname] = request.args[argname]
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        (encrypted, session_id) = create_new_interview(yaml_filename, secret, url_args=url_args, req=request)
    except Exception as err:
        return jsonify_with_status(err.__class__.__name__ + ': ' + str(err), 400)
    if encrypted and new_secret:
        return jsonify(dict(session=session_id, i=yaml_filename, secret=secret, encrypted=encrypted))
    else:
        return jsonify(dict(session=session_id, i=yaml_filename, encrypted=encrypted))


@app.route('/api/session/question', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_session_question():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    yaml_filename = request.args.get('i', None)
    session_id = request.args.get('session', None)
    secret = request.args.get('secret', None)
    if secret is not None:
        secret = str(secret)
    if yaml_filename is None or session_id is None:
        return jsonify_with_status("Parameters i and session are required.", 400)
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        data = get_question_data(yaml_filename, session_id, secret)
    except Exception as err:
        return jsonify_with_status(str(err), 400)
    if data.get('questionType', None) == 'response':
        return data['response']
    return jsonify(**data)


@app.route('/api/session/action', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_session_action():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    result = run_action_in_session(**post_data)
    if not isinstance(result, dict):
        return result
    if result['status'] == 'success':
        return ('', 204)
    return jsonify_with_status(result['message'], 400)


def run_action_in_session(**kwargs):
    yaml_filename = kwargs.get('i', None)
    session_id = kwargs.get('session', None)
    secret = kwargs.get('secret', None)
    action = kwargs.get('action', None)
    persistent = true_or_false(kwargs.get('persistent', False))
    overwrite = true_or_false(kwargs.get('overwrite', False))
    if yaml_filename is None or session_id is None or action is None:
        return {"status": "error", "message": "Parameters i, session, and action are required."}
    secret = str(secret)
    if 'arguments' in kwargs and kwargs['arguments'] is not None:
        if isinstance(kwargs['arguments'], dict):
            arguments = kwargs['arguments']
        else:
            try:
                arguments = json.loads(kwargs['arguments'])
            except:
                return {"status": "error", "message": "Malformed arguments."}
            if not isinstance(arguments, dict):
                return {"status": "error", "message": "Arguments data is not a dict."}
    else:
        arguments = {}
    device_id = docassemble.base.functions.this_thread.current_info['user']['device_id']
    session_uid = docassemble.base.functions.this_thread.current_info['user']['session_uid']
    ci = current_info(yaml=yaml_filename, req=request, action=dict(action=action, arguments=arguments), secret=secret,
                      device_id=device_id, session_uid=session_uid)
    ci['session'] = session_id
    ci['secret'] = secret
    interview = docassemble.base.interview_cache.get_interview(yaml_filename)
    if current_user.is_anonymous:
        if not interview.allowed_to_access(is_anonymous=True):
            raise Exception('Insufficient permissions to run this interview.')
    else:
        if not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
            raise Exception('Insufficient permissions to run this interview.')
    tbackup = docassemble.base.functions.backup_thread_variables()
    sbackup = backup_session()
    docassemble.base.functions.this_thread.current_info = ci
    obtain_lock(session_id, yaml_filename)
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
    except:
        release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return {"status": "error", "message": "Unable to obtain interview dictionary."}
    ci['encrypted'] = is_encrypted
    interview_status = docassemble.base.parse.InterviewStatus(current_info=ci)
    if not persistent:
        interview_status.checkin = True
    changed = True
    try:
        interview.assemble(user_dict, interview_status)
    except DAErrorMissingVariable as err:
        if overwrite:
            save_status = 'overwrite'
            changed = False
        else:
            save_status = docassemble.base.functions.this_thread.misc.get('save_status', 'new')
        if save_status == 'new':
            steps += 1
            user_dict['_internal']['steps'] = steps
        if save_status != 'ignore':
            save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, changed=changed,
                           steps=steps)
            if user_dict.get('multi_user', False) is True and is_encrypted is True:
                is_encrypted = False
                decrypt_session(secret, user_code=session_id, filename=yaml_filename)
            if user_dict.get('multi_user', False) is False and is_encrypted is False:
                encrypt_session(secret, user_code=session_id, filename=yaml_filename)
                is_encrypted = True
        release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return {"status": "success"}
    except Exception as e:
        release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return {"status": "error",
                "message": "api_session_action: failure to assemble interview: " + e.__class__.__name__ + ": " + str(e)}
    if overwrite:
        save_status = 'overwrite'
        changed = False
    else:
        save_status = docassemble.base.functions.this_thread.misc.get('save_status', 'new')
    if save_status == 'new':
        steps += 1
        user_dict['_internal']['steps'] = steps
    if save_status != 'ignore':
        save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, changed=changed,
                       steps=steps)
        if user_dict.get('multi_user', False) is True and is_encrypted is True:
            is_encrypted = False
            decrypt_session(secret, user_code=session_id, filename=yaml_filename)
        if user_dict.get('multi_user', False) is False and is_encrypted is False:
            encrypt_session(secret, user_code=session_id, filename=yaml_filename)
            is_encrypted = True
    release_lock(session_id, yaml_filename)
    if interview_status.question.question_type == "response":
        if hasattr(interview_status.question, 'all_variables'):
            if hasattr(interview_status.question, 'include_internal'):
                include_internal = interview_status.question.include_internal
            else:
                include_internal = False
            response_to_send = make_response(
                docassemble.base.functions.dict_as_json(user_dict, include_internal=include_internal).encode('utf-8'),
                '200 OK')
        elif hasattr(interview_status.question, 'binaryresponse'):
            response_to_send = make_response(interview_status.question.binaryresponse, '200 OK')
        else:
            response_to_send = make_response(interview_status.questionText.encode('utf-8'), '200 OK')
        response_to_send.headers['Content-Type'] = interview_status.extras['content_type']
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return response_to_send
    if interview_status.question.question_type == "sendfile":
        if interview_status.question.response_file is not None:
            the_path = interview_status.question.response_file.path()
        else:
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            return jsonify_with_status("Could not send file because the response was None", 404)
        if not os.path.isfile(the_path):
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            return jsonify_with_status("Could not send file because " + str(the_path) + " not found", 404)
        response_to_send = send_file(the_path, mimetype=interview_status.extras['content_type'])
        response_to_send.headers[
            'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return response_to_send
    restore_session(sbackup)
    docassemble.base.functions.restore_thread_variables(tbackup)
    return {'status': 'success'}


@app.route('/api/login_url', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_login_url():
    if not api_verify(request, roles=['admin'], permissions=['log_user_in']):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    result = get_login_url(**post_data)
    if result['status'] == 'error':
        return jsonify_with_status(result['message'], 400)
    if result['status'] == 'auth_error':
        return jsonify_with_status(result['message'], 403)
    if result['status'] == 'success':
        return jsonify(result['url'])
    return jsonify_with_status("Error", 400)


def get_login_url(**kwargs):
    username = kwargs.get('username', None)
    password = kwargs.get('password', None)
    if username is None or password is None:
        return {"status": "error", "message": "A username and password must be supplied"}
    username = str(username)
    password = str(password)
    try:
        secret = get_secret(username, password)
    except Exception as err:
        return {"status": "auth_error", "message": str(err)}
    try:
        expire = int(kwargs.get('expire', 15))
        assert expire > 0
    except:
        return {"status": "error", "message": "Invalid number of seconds."}
    if 'url_args' in kwargs:
        if isinstance(kwargs['url_args'], dict):
            url_args = kwargs['url_args']
        else:
            try:
                url_args = json.loads(kwargs['url_args'])
                assert isinstance(url_args, dict)
            except:
                return {"status": "error", "message": "Malformed URL arguments"}
    else:
        url_args = {}
    username = re.sub(r'\%', '', username)
    user = db.session.execute(select(UserModel).where(UserModel.email.ilike(username))).scalar()
    if user is None:
        return {"status": "auth_error", "message": "Username not known"}
    info = dict(user_id=user.id, secret=secret)
    del user
    if 'next' in kwargs:
        try:
            path = get_url_from_file_reference(kwargs['next'])
            assert isinstance(path, str)
            assert not path.startswith('javascript')
        except:
            return {"status": "error", "message": "Unknown path for next"}
    for key in ['i', 'next', 'session']:
        if key in kwargs:
            info[key] = kwargs[key]
    if len(url_args) > 0:
        info['url_args'] = url_args
    if 'i' in info:
        old_yaml_filename = docassemble.base.functions.this_thread.current_info.get('yaml_filename', None)
        docassemble.base.functions.this_thread.current_info['yaml_filename'] = info['i']
        if 'session' in info:
            try:
                steps, user_dict, is_encrypted = fetch_user_dict(info['session'], info['i'], secret=secret)
                info['encrypted'] = is_encrypted
            except:
                if old_yaml_filename:
                    docassemble.base.functions.this_thread.current_info['yaml_filename'] = old_yaml_filename
                return {"status": "error", "message": "Could not decrypt dictionary"}
        elif true_or_false(kwargs.get('resume_existing', False)) or daconfig.get('auto login resume existing', False):
            interviews = \
                user_interviews(user_id=info['user_id'], secret=secret, exclude_invalid=True, filename=info['i'],
                                include_dict=True)[0]
            if len(interviews) > 0:
                info['session'] = interviews[0]['session']
                info['encrypted'] = interviews[0]['encrypted']
            del interviews
        if old_yaml_filename:
            docassemble.base.functions.this_thread.current_info['yaml_filename'] = old_yaml_filename
    encryption_key = random_string(16)
    encrypted_text = encrypt_dictionary(info, encryption_key)
    while True:
        code = random_string(24)
        the_key = 'da:auto_login:' + code
        if r.get(the_key) is None:
            break
    pipe = r.pipeline()
    pipe.set(the_key, encrypted_text)
    pipe.expire(the_key, expire)
    pipe.execute()
    return {"status": "success", "url": url_for('auth.auto_login', key=encryption_key + code, _external=True)}


@app.route('/api/user/interviews', methods=['GET', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'HEAD'], automatic_options=True)
def api_user_interviews():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    filename = request.args.get('i', None)
    session_id = request.args.get('session', None)
    query = request.args.get('query', None)
    try:
        query = parse_api_sessions_query(query)
    except:
        return jsonify_with_status("Invalid query parameter", 400)
    tag = request.args.get('tag', None)
    secret = request.args.get('secret', None)
    if secret is not None:
        secret = str(secret)
    include_dict = true_or_false(request.args.get('include_dictionary', False))
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
        except:
            start_id = None
    else:
        start_id = None
    if request.method == 'GET':
        try:
            (the_list, start_id) = user_interviews(user_id=current_user.id, secret=secret, filename=filename,
                                                   session=session_id, query=query, exclude_invalid=False, tag=tag,
                                                   include_dict=include_dict, start_id=start_id)
        except:
            return jsonify_with_status("Error reading interview list.", 400)
        if start_id is None:
            next_id = None
        else:
            next_id = safeid(str(start_id))
        return jsonify(dict(next_id=next_id, items=docassemble.base.functions.safe_json(the_list)))
    if request.method == 'DELETE':
        start_id = None
        while True:
            try:
                (the_list, start_id) = user_interviews(user_id=current_user.id, filename=filename, session=session_id,
                                                       query=query, exclude_invalid=False, tag=tag, include_dict=False,
                                                       start_id=start_id)
            except:
                return jsonify_with_status("Error reading interview list.", 400)
            for info in the_list:
                user_interviews(user_id=info['user_id'], action='delete', filename=info['filename'],
                                session=info['session'])
            if start_id is None:
                break
        return ('', 204)
    return ('', 204)


@app.route('/api/interviews', methods=['GET', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'HEAD'], automatic_options=True)
def api_interviews():
    if not api_verify(request, roles=['admin', 'advocate'], permissions=['access_sessions']):
        return jsonify_with_status("Access denied.", 403)
    filename = request.args.get('i', None)
    session_id = request.args.get('session', None)
    query = request.args.get('query', None)
    try:
        query = parse_api_sessions_query(query)
    except:
        return jsonify_with_status("Invalid query parameter", 400)
    tag = request.args.get('tag', None)
    secret = request.args.get('secret', None)
    if secret is not None:
        secret = str(secret)
    include_dict = true_or_false(request.args.get('include_dictionary', False))
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
        except:
            start_id = None
    else:
        start_id = None
    if request.method == 'GET':
        try:
            (the_list, start_id) = user_interviews(secret=secret, filename=filename, session=session_id, query=query,
                                                   exclude_invalid=False, tag=tag, include_dict=include_dict,
                                                   start_id=start_id)
        except Exception as err:
            return jsonify_with_status("Error reading interview list: " + str(err), 400)
        if start_id is None:
            next_id = None
        else:
            next_id = safeid(str(start_id))
        return jsonify(dict(next_id=next_id, items=docassemble.base.functions.safe_json(the_list)))
    if request.method == 'DELETE':
        if not current_user.has_role_or_permission('admin', 'advocate', permissions=['edit_sessions']):
            return jsonify_with_status("Access denied.", 403)
        start_id = None
        while True:
            try:
                (the_list, start_id) = user_interviews(filename=filename, session=session_id, query=query,
                                                       exclude_invalid=False, tag=tag, include_dict=False,
                                                       start_id=start_id)
            except:
                return jsonify_with_status("Error reading interview list.", 400)
            for info in the_list:
                if info['user_id'] is not None:
                    user_interviews(user_id=info['user_id'], action='delete', filename=info['filename'],
                                    session=info['session'])
                else:
                    user_interviews(temp_user_id=info['temp_user_id'], action='delete', filename=info['filename'],
                                    session=info['session'])
            if start_id is None:
                break
        return ('', 204)
    return ('', 204)


def jsonify_task(result):
    while True:
        code = random_string(24)
        the_key = 'da:install_status:' + code
        if r.get(the_key) is None:
            break
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps({'id': result.id, 'server_start_time': START_TIME}))
    pipe.expire(the_key, 3600)
    pipe.execute()
    return jsonify({'task_id': code})


@app.route('/api/package', methods=['GET', 'POST', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'HEAD'], automatic_options=True)
def api_package():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['manage_packages']):
        return jsonify_with_status("Access denied.", 403)
    if request.method == 'GET':
        package_list, package_auth = get_package_info(exclude_core=True)
        packages = []
        for package in package_list:
            if not package.package.active:
                continue
            item = {'name': package.package.name, 'type': package.package.type, 'can_update': package.can_update,
                    'can_uninstall': package.can_uninstall}
            if package.package.packageversion:
                item['version'] = package.package.packageversion
            if package.package.giturl:
                item['git_url'] = package.package.giturl
            if package.package.gitbranch:
                item['branch'] = package.package.gitbranch
            if package.package.upload:
                item['zip_file_number'] = package.package.upload
            packages.append(item)
        return jsonify(packages)
    if request.method == 'DELETE':
        target = request.args.get('package', None)
        do_restart = true_or_false(request.args.get('restart', True))
        if target is None:
            return jsonify_with_status("Missing package name.", 400)
        package_list, package_auth = get_package_info()
        the_package = None
        for package in package_list:
            if package.package.name == target:
                the_package = package
                break
        if the_package is None:
            return jsonify_with_status("Package not found.", 400)
        if not the_package.can_uninstall:
            return jsonify_with_status("You are not allowed to uninstall that package.", 400)
        uninstall_package(target)
        if do_restart:
            logmessage("Starting process of updating packages followed by restarting server")
            result = docassemble.webapp.worker.update_packages.apply_async(
                link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(target)))
        else:
            result = docassemble.webapp.worker.update_packages.delay(restart=False)
        return jsonify_task(result)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        do_restart = true_or_false(post_data.get('restart', True))
        num_commands = 0
        if 'update' in post_data:
            num_commands += 1
        if 'github_url' in post_data:
            num_commands += 1
        if 'pip' in post_data:
            num_commands += 1
        if 'zip' in request.files:
            num_commands += 1
        if num_commands == 0:
            return jsonify_with_status("No instructions provided.", 400)
        if num_commands > 1:
            return jsonify_with_status("Only one package can be installed or updated at a time.", 400)
        if 'update' in post_data:
            target = post_data['update']
            package_list, package_auth = get_package_info()
            the_package = None
            for package in package_list:
                if package.package.name == target:
                    the_package = package
                    break
            if the_package is None:
                return jsonify_with_status("Package not found.", 400)
            if not the_package.can_update:
                return jsonify_with_status("You are not allowed to update that package.", 400)
            existing_package = db.session.execute(
                select(Package).filter_by(name=target, active=True).order_by(Package.id.desc())).scalar()
            if existing_package is not None:
                if existing_package.type == 'git' and existing_package.giturl is not None:
                    if existing_package.gitbranch:
                        install_git_package(target, existing_package.giturl, existing_package.gitbranch)
                    else:
                        install_git_package(target, existing_package.giturl, get_master_branch(existing_package.giturl))
                elif existing_package.type == 'pip':
                    if existing_package.name == 'docassemble.webapp' and existing_package.limitation:
                        existing_package.limitation = None
                    install_pip_package(existing_package.name, existing_package.limitation)
            db.session.commit()
            if do_restart:
                logmessage("Starting process of updating packages followed by restarting server")
                result = docassemble.webapp.worker.update_packages.apply_async(
                    link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(target)))
            else:
                result = docassemble.webapp.worker.update_packages.delay(restart=False)
            return jsonify_task(result)
        if 'github_url' in post_data:
            github_url = post_data['github_url'].rstrip('/')
            branch = post_data.get('branch', None)
            if branch is None:
                branch = get_master_branch(github_url)
            packagename = re.sub(r'/*$', '', github_url)
            packagename = re.sub(r'^git+', '', packagename)
            packagename = re.sub(r'#.*', '', packagename)
            packagename = re.sub(r'\.git$', '', packagename)
            packagename = re.sub(r'.*/', '', packagename)
            packagename = re.sub(r'^docassemble-', 'docassemble.', packagename)
            if user_can_edit_package(giturl=github_url) and user_can_edit_package(pkgname=packagename):
                install_git_package(packagename, github_url, branch)
                if do_restart:
                    logmessage("Starting process of updating packages followed by restarting server")
                    result = docassemble.webapp.worker.update_packages.apply_async(
                        link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(packagename)))
                else:
                    result = docassemble.webapp.worker.update_packages.delay(restart=False)
                return jsonify_task(result)
            else:
                jsonify_with_status("You do not have permission to install that package.", 403)
        if 'pip' in post_data:
            m = re.match(r'([^>=<]+)([>=<]+.+)', post_data['pip'])
            if m:
                packagename = m.group(1)
                limitation = m.group(2)
            else:
                packagename = post_data['pip']
                limitation = None
            packagename = re.sub(r'[^A-Za-z0-9\_\-\.]', '', packagename)
            if user_can_edit_package(pkgname=packagename):
                install_pip_package(packagename, limitation)
                if do_restart:
                    logmessage("Starting process of updating packages followed by restarting server")
                    result = docassemble.webapp.worker.update_packages.apply_async(
                        link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(packagename)))
                else:
                    result = docassemble.webapp.worker.update_packages.delay(restart=False)
                return jsonify_task(result)
            else:
                return jsonify_with_status("You do not have permission to install that package.", 403)
        if 'zip' in request.files and request.files['zip'].filename:
            try:
                the_file = request.files['zip']
                filename = secure_filename(the_file.filename)
                file_number = get_new_file_number(docassemble.base.functions.get_uid(), filename)
                saved_file = SavedFile(file_number, extension='zip', fix=True, should_not_exist=True)
                file_set_attributes(file_number, private=False, persistent=True)
                zippath = saved_file.path
                the_file.save(zippath)
                saved_file.save()
                saved_file.finalize()
                pkgname = get_package_name_from_zip(zippath)
                if user_can_edit_package(pkgname=pkgname):
                    install_zip_package(pkgname, file_number)
                    if do_restart:
                        logmessage("Starting process of updating packages followed by restarting server")
                        result = docassemble.webapp.worker.update_packages.apply_async(
                            link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(pkgname)))
                    else:
                        result = docassemble.webapp.worker.update_packages.delay(restart=False)
                    return jsonify_task(result)
                return jsonify_with_status("You do not have permission to install that package.", 403)
            except:
                return jsonify_with_status("There was an error when installing that package.", 400)


@app.route('/api/package_update_status', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_package_update_status():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['manage_packages']):
        return jsonify_with_status("Access denied.", 403)
    code = request.args.get('task_id', None)
    if code is None:
        return jsonify_with_status("Missing task_id", 400)
    the_key = 'da:install_status:' + str(code)
    task_data = r.get(the_key)
    if task_data is None:
        return jsonify({'status': 'unknown'})
    task_info = json.loads(task_data.decode())
    result = docassemble.webapp.worker.workerapp.AsyncResult(id=task_info['id'])
    if result.ready():
        the_result = result.get()
        if isinstance(the_result, ReturnValue):
            if the_result.ok:
                if the_result.restart and START_TIME <= task_info['server_start_time']:
                    return jsonify(status='working')
                r.delete(the_key)
                return jsonify(status='completed', ok=True,
                               log=summarize_results(the_result.results, the_result.logmessages, html=False))
            if hasattr(the_result, 'error_message'):
                r.delete(the_key)
                return jsonify(status='completed', ok=False, error_message=str(the_result.error_message))
            if hasattr(the_result, 'results') and hasattr(the_result, 'logmessages'):
                r.delete(the_key)
                return jsonify(status='completed', ok=False,
                               error_message=summarize_results(the_result.results, the_result.logmessages, html=False))
            r.expire(the_key, 30)
            return jsonify(status='completed', ok=False,
                           error_message=str("No error message.  Result is " + str(the_result)))
        r.expire(the_key, 30)
        return jsonify(status='completed', ok=False, error_message=str(the_result))
    return jsonify(status='working')


@app.route('/api/temp_url', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_temporary_redirect():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    url = request.args.get('url', None)
    if url is None:
        return jsonify_with_status("No url supplied.", 400)
    try:
        one_time = true_or_false(request.args.get('one_time', 0))
    except:
        one_time = False
    try:
        expire = int(request.args.get('expire', 3600))
        assert expire > 0
    except:
        return jsonify_with_status("Invalid number of seconds.", 400)
    return jsonify(docassemble.base.functions.temp_redirect(url, expire, False, one_time))


@app.route('/api/resume_url', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_resume_url():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    filename = post_data.get('i', None)
    if filename is None:
        return jsonify_with_status("No filename supplied.", 400)
    session_id = post_data.get('session_id', None)
    if 'url_args' in post_data:
        if isinstance(post_data['url_args'], dict):
            url_args = post_data['url_args']
        else:
            try:
                url_args = json.loads(post_data['url_args'])
                assert isinstance(url_args, dict)
            except:
                return jsonify_with_status("Malformed URL arguments", 400)
    else:
        url_args = {}
    try:
        one_time = bool(int(post_data.get('one_time', 0)))
    except:
        one_time = False
    try:
        expire = int(post_data.get('expire', 3600))
        assert expire > 0
    except:
        return jsonify_with_status("Invalid number of seconds.", 400)
    info = dict(i=filename)
    if session_id:
        info['session'] = session_id
    if one_time:
        info['once'] = True
    while True:
        code = random_string(32)
        the_key = 'da:resume_interview:' + code
        if r.get(the_key) is None:
            break
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps(info))
    pipe.expire(the_key, expire)
    pipe.execute()
    return jsonify(url_for('interview.launch', c=code, _external=True))


@app.route('/api/clear_cache', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_clear_cache():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    for key in r.keys('da:interviewsource:*'):
        r.incr(key.decode())
    return ('', 204)


@app.route('/api/config', methods=['GET', 'POST', 'PATCH'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'PATCH', 'HEAD'], automatic_options=True)
def api_config():
    if not api_verify(request, roles=['admin'], permissions=['manage_config']):
        return jsonify_with_status("Access denied.", 403)
    if request.method == 'GET':
        try:
            with open(daconfig['config file'], 'r', encoding='utf-8') as fp:
                content = fp.read()
            data = yaml.load(content, Loader=yaml.FullLoader)
        except:
            return jsonify_with_status("Could not parse Configuration.", 400)
        return jsonify(data)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        if 'config' not in post_data:
            return jsonify_with_status("Configuration not supplied.", 400)
        if isinstance(post_data['config'], dict):
            data = post_data['config']
        else:
            try:
                data = json.loads(post_data['config'])
            except:
                return jsonify_with_status("Configuration was not valid JSON.", 400)
        yaml_data = ruamel.yaml.safe_dump(data, default_flow_style=False, default_style='"', allow_unicode=True,
                                          width=10000)
        if cloud is not None:
            key = cloud.get_key('config.yml')
            key.set_contents_from_string(yaml_data)
        with open(daconfig['config file'], 'w', encoding='utf-8') as fp:
            fp.write(yaml_data)
        return_val = jsonify_restart_task()
        restart_all()
        return return_val
    if request.method == 'PATCH':
        try:
            with open(daconfig['config file'], 'r', encoding='utf-8') as fp:
                content = fp.read()
            data = yaml.load(content, Loader=yaml.FullLoader)
        except:
            return jsonify_with_status("Could not parse Configuration.", 400)
        patch_data = request.get_json(silent=True)
        if patch_data is None:
            using_json = False
            patch_data = request.form.copy()
        else:
            using_json = True
        if 'config_changes' not in patch_data:
            return jsonify_with_status("Configuration changes not supplied.", 400)
        if isinstance(patch_data['config_changes'], dict):
            new_data = patch_data['config_changes']
        else:
            try:
                new_data = json.loads(patch_data['config_changes'])
            except:
                return jsonify_with_status("Configuration changes were not valid JSON.", 400)
        data.update(new_data)
        yaml_data = ruamel.yaml.safe_dump(data, default_flow_style=False, default_style='"', allow_unicode=True,
                                          width=10000)
        if cloud is not None:
            key = cloud.get_key('config.yml')
            key.set_contents_from_string(yaml_data)
        with open(daconfig['config file'], 'w', encoding='utf-8') as fp:
            fp.write(yaml_data)
        return_val = jsonify_restart_task()
        restart_all()
        return return_val


@app.route('/api/restart', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_restart():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    return_val = jsonify_restart_task()
    restart_all()
    return return_val


@app.route('/api/restart_status', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_restart_status():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    code = request.args.get('task_id', None)
    if code is None:
        return jsonify_with_status("Missing task_id", 400)
    the_key = 'da:restart_status:' + str(code)
    task_data = r.get(the_key)
    if task_data is None:
        return jsonify(status='unknown')
    task_info = json.loads(task_data.decode())
    if START_TIME <= task_info['server_start_time']:
        return jsonify(status='working')
    r.expire(the_key, 30)
    return jsonify(status='completed')


@app.route('/api/convert_file', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_convert_file():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.form.copy()
    to_format = post_data.get('format', 'md')
    if to_format not in 'md':
        return jsonify_with_status("Invalid output file format.", 400)
    for filekey in request.files:
        the_files = request.files.getlist(filekey)
        if the_files:
            for the_file in the_files:
                filename = werkzeug.utils.secure_filename(the_file.filename)
                extension, mimetype = get_ext_and_mimetype(filename)
                if mimetype and mimetype in convertible_mimetypes:
                    the_format = convertible_mimetypes[mimetype]
                elif extension and extension in convertible_extensions:
                    the_format = convertible_extensions[extension]
                else:
                    return jsonify_with_status("Invalid input file format.", 400)
                with tempfile.NamedTemporaryFile() as temp_file:
                    the_file.save(temp_file.name)
                    result = word_to_markdown(temp_file.name, the_format)
                    if result is None:
                        return jsonify_with_status("Unable to convert file.", 400)
                    with open(result.name, 'r', encoding='utf-8') as fp:
                        contents = fp.read()
                response = make_response(contents, 200)
                response.headers['Content-Type'] = 'text/plain'
                return response


@app.route('/api/interview_data', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_interview_data():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['interview_data']):
        return jsonify_with_status("Access denied.", 403)
    filename = request.args.get('i', None)
    if filename is None:
        return jsonify_with_status("No filename supplied.", 400)
    try:
        interview_source = docassemble.base.parse.interview_source_from_string(filename, testing=True)
    except Exception as err:
        return jsonify_with_status("Error finding interview: " + str(err), 400)
    try:
        interview = interview_source.get_interview()
    except Exception as err:
        return jsonify_with_status("Error finding interview: " + str(err), 400)
    device_id = docassemble.base.functions.this_thread.current_info['user']['device_id']
    interview_status = docassemble.base.parse.InterviewStatus(
        current_info=current_info(yaml=filename, req=request, action=None, device_id=device_id))
    m = re.search('docassemble.playground([0-9]+)([^:]*):', filename)
    if m:
        use_playground = bool(current_user.id == int(m.group(1)))
        if m.group(2) != '':
            current_project = m.group(2)
        else:
            current_project = 'default'
    else:
        use_playground = False
        current_project = 'default'
    variables_json, vocab_list = get_vars_in_use(interview, interview_status, debug_mode=False, return_json=True,
                                                 use_playground=use_playground, current_project=current_project)
    return jsonify({'names': variables_json, 'vocabulary': list(vocab_list)})


@app.route('/api/stash_data', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_stash_data():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
        if 'data' not in post_data:
            return jsonify_with_status("Data must be provided.", 400)
        try:
            data = json.loads(post_data['data'])
        except Exception as err:
            return jsonify_with_status("Malformed data.", 400)
    else:
        data = post_data['data']
    if not true_or_false(post_data.get('raw', False)):
        data = transform_json_variables(data)
    expire = post_data.get('expire', None)
    if expire is None:
        expire = 60 * 60 * 24 * 90
    try:
        expire = int(expire)
        assert expire > 0
    except:
        expire = 60 * 60 * 24 * 90
    (key, secret) = stash_data(data, expire)
    return jsonify({'stash_key': key, 'secret': secret})


@app.route('/api/retrieve_stashed_data', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_retrieve_stashed_data():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    do_delete = true_or_false(request.args.get('delete', False))
    refresh = request.args.get('refresh', None)
    if refresh:
        try:
            refresh = int(refresh)
            assert refresh > 0
        except:
            refresh = False
    stash_key = request.args.get('stash_key', None)
    secret = request.args.get('secret', None)
    if stash_key is None or secret is None:
        return jsonify_with_status("The stash key and secret parameters are required.", 400)
    try:
        data = retrieve_stashed_data(stash_key, secret, delete=do_delete, refresh=refresh)
        assert data is not None
    except Exception as err:
        return jsonify_with_status(
            "The stashed data could not be retrieved: " + err.__class__.__name__ + " " + str(err) + ".", 400)
    return jsonify(docassemble.base.functions.safe_json(data))


@app.route('/me', methods=['GET'])
def whoami():
    if current_user.is_authenticated:
        return jsonify(logged_in=True, user_id=current_user.id, email=current_user.email,
                       roles=[role.name for role in current_user.roles], firstname=current_user.first_name,
                       lastname=current_user.last_name, country=current_user.country,
                       subdivisionfirst=current_user.subdivisionfirst, subdivisionsecond=current_user.subdivisionsecond,
                       subdivisionthird=current_user.subdivisionthird, organization=current_user.organization,
                       timezone=current_user.timezone)
    else:
        return jsonify(logged_in=False)


def retrieve_email(email_id):
    if not isinstance(email_id, int):
        raise DAError("email_id not provided")
    email = db.session.execute(select(Email).filter_by(id=email_id)).scalar()
    if email is None:
        raise DAError("E-mail did not exist")
    short_record = db.session.execute(select(Shortener).filter_by(short=email.short)).scalar()
    if short_record is not None and short_record.user_id is not None:
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(id=short_record.user_id,
                                                                                active=True)).scalar()
    else:
        user = None
    if short_record is None:
        raise DAError("Short code did not exist")
    return get_email_obj(email, short_record, user)


class AddressEmail:
    def __str__(self):
        return str(self.address)


def retrieve_emails(**pargs):
    key = pargs.get('key', None)
    index = pargs.get('index', None)
    if key is None and index is not None:
        raise DAError("retrieve_emails: if you provide an index you must provide a key")
    if 'i' in pargs:
        yaml_filename = pargs['i']
    else:
        yaml_filename = docassemble.base.functions.this_thread.current_info.get('yaml_filename', None)
    if 'uid' in pargs:
        uid = pargs['uid']
    else:
        uid = docassemble.base.functions.get_uid()
    if 'user_id' in pargs:
        user_id = pargs['user_id']
        temp_user_id = None
    elif 'temp_user_id' in pargs:
        user_id = None
        temp_user_id = pargs['temp_user_id']
    elif current_user.is_anonymous:
        user_id = None
        temp_user_id = session.get('tempuser', None)
    else:
        user_id = current_user.id
        temp_user_id = None
    user_cache = {}
    results = []
    if key is None:
        the_query = db.session.execute(select(Shortener).filter_by(filename=yaml_filename, uid=uid, user_id=user_id,
                                                                   temp_user_id=temp_user_id).order_by(
            Shortener.modtime)).scalars()
    else:
        if index is None:
            the_query = db.session.execute(
                select(Shortener).filter_by(filename=yaml_filename, uid=uid, user_id=user_id, temp_user_id=temp_user_id,
                                            key=key).order_by(Shortener.modtime)).scalars()
        else:
            the_query = db.session.execute(
                select(Shortener).filter_by(filename=yaml_filename, uid=uid, user_id=user_id, temp_user_id=temp_user_id,
                                            key=key, index=index).order_by(Shortener.modtime)).scalars()
    for record in the_query:
        result_for_short = AddressEmail()
        result_for_short.address = record.short
        result_for_short.key = record.key
        result_for_short.index = record.index
        result_for_short.emails = []
        if record.user_id is not None:
            if record.user_id in user_cache:
                user = user_cache[record.user_id]
            else:
                user = get_user_object(record.user_id)
                user_cache[record.user_id] = user
            result_for_short.owner = user.email
        else:
            user = None
            result_for_short.owner = None
        for email in db.session.execute(
                select(Email).filter_by(short=record.short).order_by(Email.datetime_received)).scalars():
            result_for_short.emails.append(get_email_obj(email, record, user))
        results.append(result_for_short)
    return results


def get_email_obj(email, short_record, user):
    email_obj = DAEmail(short=email.short)
    email_obj.key = short_record.key
    email_obj.index = short_record.index
    email_obj.initializeAttribute('to_address', DAEmailRecipientList, json.loads(email.to_addr), gathered=True)
    email_obj.initializeAttribute('cc_address', DAEmailRecipientList, json.loads(email.cc_addr), gathered=True)
    email_obj.initializeAttribute('from_address', DAEmailRecipient, **json.loads(email.from_addr))
    email_obj.initializeAttribute('reply_to', DAEmailRecipient, **json.loads(email.reply_to_addr))
    email_obj.initializeAttribute('return_path', DAEmailRecipient, **json.loads(email.return_path_addr))
    email_obj.subject = email.subject
    email_obj.datetime_message = email.datetime_message
    email_obj.datetime_received = email.datetime_received
    email_obj.initializeAttribute('attachment', DAFileList, gathered=True)
    if user is None:
        email_obj.address_owner = None
    else:
        email_obj.address_owner = user.email
    for attachment_record in db.session.execute(
            select(EmailAttachment).filter_by(email_id=email.id).order_by(EmailAttachment.index)).scalars():
        # sys.stderr.write("Attachment record is " + str(attachment_record.id) + "\n")
        upload = db.session.execute(select(Uploads).filter_by(indexno=attachment_record.upload)).scalar()
        if upload is None:
            continue
        # sys.stderr.write("Filename is " + upload.filename + "\n")
        saved_file_att = SavedFile(attachment_record.upload, extension=attachment_record.extension, fix=True)
        process_file(saved_file_att, saved_file_att.path, attachment_record.content_type, attachment_record.extension,
                     initial=False)
        extension, mimetype = get_ext_and_mimetype(upload.filename)
        if upload.filename == 'headers.json':
            # sys.stderr.write("Processing headers\n")
            email_obj.initializeAttribute('headers', DAFile, mimetype=mimetype, extension=extension,
                                          number=attachment_record.upload)
        elif upload.filename == 'attachment.txt' and attachment_record.index < 3:
            # sys.stderr.write("Processing body text\n")
            email_obj.initializeAttribute('body_text', DAFile, mimetype=mimetype, extension=extension,
                                          number=attachment_record.upload)
        elif upload.filename == 'attachment.html' and attachment_record.index < 3:
            email_obj.initializeAttribute('body_html', DAFile, mimetype=mimetype, extension=extension,
                                          number=attachment_record.upload)
        else:
            email_obj.attachment.appendObject(DAFile, mimetype=mimetype, extension=extension,
                                              number=attachment_record.upload)
    if not hasattr(email_obj, 'headers'):
        email_obj.headers = None
    if not hasattr(email_obj, 'body_text'):
        email_obj.body_text = None
    if not hasattr(email_obj, 'body_html'):
        email_obj.body_html = None
    return email_obj


def da_send_fax(fax_number, the_file, config, country=None):
    if clicksend_config is not None and fax_provider == 'clicksend':
        if config not in clicksend_config['name']:
            raise Exception("There is no ClickSend configuration called " + str(config))
        info = docassemble.webapp.clicksend.send_fax(fax_number, the_file, clicksend_config['name'][config], country)
        the_key = 'da:faxcallback:sid:' + info['message_id']
        pipe = r.pipeline()
        pipe.set(the_key, json.dumps(info))
        pipe.expire(the_key, 86400)
        pipe.execute()
        return info['message_id']
    if telnyx_config is not None and fax_provider == 'telnyx':
        if config not in telnyx_config['name']:
            raise Exception("There is no Telnyx configuration called " + str(config))
        info = docassemble.webapp.telnyx.send_fax(fax_number, the_file, telnyx_config['name'][config], country)
        the_key = 'da:faxcallback:sid:' + info['id']
        pipe = r.pipeline()
        pipe.set(the_key, json.dumps(info))
        pipe.expire(the_key, 86400)
        pipe.execute()
        return info['id']
    if twilio_config is None:
        logmessage("da_send_fax: ignoring call to da_send_fax because Twilio not enabled")
        return None
    if config not in twilio_config['name'] or 'fax' not in twilio_config['name'][config] or \
            twilio_config['name'][config]['fax'] in (False, None):
        logmessage("da_send_fax: ignoring call to da_send_fax because fax feature not enabled")
        return None
    account_sid = twilio_config['name'][config].get('account sid', None)
    auth_token = twilio_config['name'][config].get('auth token', None)
    from_number = twilio_config['name'][config].get('number', None)
    if account_sid is None or auth_token is None or from_number is None:
        logmessage("da_send_fax: ignoring call to da_send_fax because account sid, auth token, and/or number missing")
        return None
    client = TwilioRestClient(account_sid, auth_token)
    fax = client.fax.v1.faxes.create(
        from_=from_number,
        to=fax_number,
        media_url=the_file.url_for(temporary=True, seconds=600),
        status_callback=url_for('fax_callback', _external=True)
    )
    return fax.sid


def write_pypirc():
    pypirc_file = daconfig.get('pypirc path', '/var/www/.pypirc')
    pypi_url = daconfig.get('pypi url', 'https://upload.pypi.org/legacy/')
    # if pypi_username is None or pypi_password is None:
    #     return
    if os.path.isfile(pypirc_file):
        with open(pypirc_file, 'r', encoding='utf-8') as fp:
            existing_content = fp.read()
    else:
        existing_content = None
    content = """\
[distutils]
index-servers =
  pypi

[pypi]
repository: """ + pypi_url + "\n"
    #     """
    # username: """ + pypi_username + """
    # password: """ + pypi_password + "\n"
    if existing_content != content:
        with open(pypirc_file, 'w', encoding='utf-8') as fp:
            fp.write(content)
        os.chmod(pypirc_file, stat.S_IRUSR | stat.S_IWUSR)


def path_from_reference(file_reference):
    if isinstance(file_reference, DAFileCollection):
        file_reference = file_reference._first_file()
    if isinstance(file_reference, DAFileList):
        file_reference = file_reference[0]
    if isinstance(file_reference, DAFile):
        file_info = get_info_from_file_number_with_uids(file_reference.number)
        if 'fullpath' not in file_info:
            raise Exception("File not found")
        path = file_info['fullpath']
        friendly_path = os.path.join(tempfile.mkdtemp(prefix='SavedFile'), file_reference.filename)
        try:
            os.symlink(file_info['fullpath'], friendly_path)
        except:
            shutil.copyfile(file_info['fullpath'], friendly_path)
        return friendly_path
    if isinstance(file_reference, DAStaticFile):
        return file_reference.path()
    if file_reference is None:
        return None
    file_info = get_info_from_file_reference(file_reference)
    if 'fullpath' not in file_info:
        raise Exception("File not found")
    return file_info['fullpath']


def get_short_code(**pargs):
    key = pargs.get('key', None)
    index = pargs.get('index', None)
    if key is None and index is not None:
        raise DAError("get_short_code: if you provide an index you must provide a key")
    if 'i' in pargs:
        yaml_filename = pargs['i']
    else:
        yaml_filename = docassemble.base.functions.this_thread.current_info.get('yaml_filename', None)
    if 'uid' in pargs:
        uid = pargs['uid']
    else:
        uid = docassemble.base.functions.get_uid()
    if 'user_id' in pargs:
        user_id = pargs['user_id']
        temp_user_id = None
    elif 'temp_user_id' in pargs:
        user_id = None
        temp_user_id = pargs['temp_user_id']
    elif current_user.is_anonymous:
        user_id = None
        temp_user_id = session.get('tempuser', None)
    else:
        user_id = current_user.id
        temp_user_id = None
    short_code = None
    for record in db.session.execute(select(Shortener.short).filter_by(filename=yaml_filename, uid=uid, user_id=user_id,
                                                                       temp_user_id=temp_user_id, key=key,
                                                                       index=index)):
        short_code = record.short
    if short_code is not None:
        return short_code
    counter = 0
    new_record = None
    while counter < 20:
        existing_id = None
        new_short = random_lower_string(6)
        for record in db.session.execute(select(Shortener.id).filter_by(short=new_short)):
            existing_id = record.id
        if existing_id is None:
            new_record = Shortener(filename=yaml_filename, uid=uid, user_id=user_id, temp_user_id=temp_user_id,
                                   short=new_short, key=key, index=index)
            db.session.add(new_record)
            db.session.commit()
            break
        counter += 1
    if new_record is None:
        raise SystemError("Failed to generate unique short code")
    return new_short


def illegal_sessions_query(expr):
    if re.search(r'[\n\r]', expr):
        return True
    try:
        t = ast.parse(expr)
    except:
        return True
    detector = docassemble.base.astparser.detectIllegalQuery()
    detector.visit(t)
    return detector.illegal


emoji_match = re.compile(r':([A-Za-z][A-Za-z0-9\_\-]+):')
html_match = re.compile(
    r'(</?[A-Za-z\!][^>]*>|https*://[A-Za-z0-9\-\_:\%\/\@\.\#\&\=\~\?]+|mailto*://[A-Za-z0-9\-\_:\%\/\@\.\#\&\=\~]+\?)')


def mako_parts(expression):
    in_percent = False
    in_var = False
    in_square = False
    var_depth = 0
    in_colon = 0
    in_html = 0
    in_pre_bracket = False
    in_post_bracket = False
    output = []
    current = ''
    i = 0
    expression = emoji_match.sub(r'^^\1^^', expression)
    expression = html_match.sub(r'!@\1!@', expression)
    n = len(expression)
    while i < n:
        if in_html:
            if i + 1 < n and expression[i:i + 2] == '!@':
                in_html = False
                if current != '':
                    output.append([current, 2])
                current = ''
                i += 2
            else:
                current += expression[i]
                i += 1
            continue
        if in_percent:
            if expression[i] in ["\n", "\r"]:
                in_percent = False
                current += expression[i]
                output.append([current, 1])
                current = ''
                i += 1
                continue
        elif in_var:
            if expression[i] == '{' and expression[i - 1] != "\\":
                var_depth += 1
            elif expression[i] == '}' and expression[i - 1] != "\\":
                var_depth -= 1
                if var_depth == 0:
                    current += expression[i]
                    if current != '':
                        output.append([current, 2])
                    current = ''
                    in_var = False
                    i += 1
                    continue
        elif in_pre_bracket:
            if i + 2 < n:
                if expression[i:i + 3] == '</%':
                    in_pre_bracket = False
                    in_post_bracket = True
                    current += expression[i:i + 3]
                    i += 3
                    continue
            if i + 1 < n and expression[i:i + 2] == '%>':
                in_pre_bracket = False
                current += expression[i:i + 2]
                if current != '':
                    output.append([current, 1])
                current = ''
                i += 2
                continue
        elif in_post_bracket:
            if expression[i] == '>' and expression[i - 1] != "\\":
                current += expression[i]
                if current != '':
                    output.append([current, 1])
                current = ''
                in_post_bracket = False
                i += 1
                continue
        elif in_square:
            if expression[i] == ']' and (i == 0 or expression[i - 1] != "\\"):
                mode = 0
                current += expression[i]
                for pattern in ['[FILE', '[TARGET ', '[EMOJI ', '[QR ', '[YOUTUBE', '[VIMEO]', '[PAGENUM]',
                                '[BEGIN_TWOCOL]', '[BREAK]', '[END_TWOCOL', '[BEGIN_CAPTION]', '[VERTICAL_LINE]',
                                '[END_CAPTION]', '[TIGHTSPACING]', '[SINGLESPACING]', '[DOUBLESPACING]',
                                '[ONEANDAHALFSPACING]', '[TRIPLESPACING]', '[START_INDENTATION]', '[STOP_INDENTATION]',
                                '[NBSP]', '[REDACTION', '[ENDASH]', '[EMDASH]', '[HYPHEN]', '[CHECKBOX]', '[BLANK]',
                                '[BLANKFILL]', '[PAGEBREAK]', '[PAGENUM]', '[SECTIONNUM]', '[SKIPLINE]', '[NEWLINE]',
                                '[NEWPAR]', '[BR]', '[TAB]', '[END]', '[BORDER]', '[NOINDENT]', '[FLUSHLEFT]',
                                '[FLUSHRIGHT]', '[CENTER]', '[BOLDCENTER]', '[INDENTBY', '[${']:
                    if current.startswith(pattern):
                        mode = 2
                        break
                if current != '':
                    output.append([current, mode])
                current = ''
                in_square = False
                i += 1
                continue
            if i + 1 < n and expression[i:i + 2] == '^^':
                if in_colon:
                    in_colon = False
                    current += ':'
                    output.append([current, 2])
                    current = ''
                else:
                    in_colon = True
                    if current.startswith('[${'):
                        output.append([current, 2])
                    else:
                        output.append([current, 0])
                    current = ':'
                i += 2
                continue
            if i + 1 < n and expression[i:i + 2] == '!@':
                in_html = True
                if current != '':
                    if current.startswith('[${'):
                        output.append([current, 2])
                    else:
                        output.append([current, 0])
                current = ''
                i += 2
                continue
        elif in_colon:
            if i + 1 < n and expression[i:i + 2] == '^^':
                current += ':'
                if current != '':
                    output.append([current, 2])
                current = ''
                in_colon = False
                i += 2
                continue
        elif i + 1 < n:
            if expression[i:i + 2] == '${':
                in_var = True
                var_depth += 1
                if current != '':
                    output.append([current, 0])
                current = expression[i:i + 2]
                i += 2
                continue
            if expression[i:i + 2] == '^^':
                in_colon = True
                if current != '':
                    output.append([current, 0])
                current = ':'
                i += 2
                continue
            if expression[i:i + 2] == '!@':
                in_html = True
                if current != '':
                    output.append([current, 0])
                current = ''
                i += 2
                continue
            if expression[i:i + 2] == '<%':
                in_pre_bracket = True
                if current != '':
                    output.append([current, 0])
                current = expression[i:i + 2]
                i += 2
                continue
            if expression[i:i + 2] == '% ' and start_of_line(expression, i):
                in_percent = True
                if current != '':
                    output.append([current, 0])
                current = expression[i:i + 2]
                i += 2
                continue
            if expression[i] == '[' and (i == 0 or expression[i - 1] != "\\"):
                in_square = True
                if current != '':
                    output.append([current, 0])
                current = expression[i]
                i += 1
                continue
        current += expression[i]
        i += 1
    if current != '':
        if in_pre_bracket or in_post_bracket or in_percent:
            output.append([current, 1])
        elif in_var:
            output.append([current, 2])
        else:
            output.append([current, 0])
    return output


def start_of_line(expression, i):
    if i == 0:
        return True
    i -= 1
    while i >= 0:
        if expression[i] in ("\n", "\r"):
            return True
        if expression[i] in (" ", "\t"):
            i -= 1
            continue
        return False
    return True


def applock(action, application):
    key = 'da:applock:' + application + ':' + hostname
    if action == 'obtain':
        found = False
        count = 4
        while count > 0:
            record = r.get(key)
            if record:
                sys.stderr.write("obtain_applock: waiting for " + key + "\n")
                time.sleep(1.0)
            else:
                found = False
                break
            found = True
            count -= 1
        if found:
            sys.stderr.write("Request for applock " + key + " deadlocked\n")
            r.delete(key)
        pipe = r.pipeline()
        pipe.set(key, 1)
        pipe.expire(key, 4)
        pipe.execute()
    elif action == 'release':
        r.delete(key)


@app.errorhandler(CSRFError)
def handle_csrf_error(the_error):
    if request.method == 'POST':
        setup_translation()
        if 'ajax' in request.form and int(request.form['ajax']):
            flash(word("Input not processed because the page expired."), "success")
            return jsonify(dict(action='reload', reason='csrf_error'))
        try:
            referer = str(request.referrer)
        except:
            referer = None
        if referer:
            flash(word("Input not processed because the page expired."), "success")
            return redirect(referer)
    return server_error(the_error)


def error_notification(err, message=None, history=None, trace=None, referer=None, the_request=None, the_vars=None):
    recipient_email = daconfig.get('error notification email', None)
    if not recipient_email:
        return
    if err.__class__.__name__ in ['CSRFError', 'ClientDisconnected', 'MethodNotAllowed',
                                  'DANotFoundError'] + ERROR_TYPES_NO_EMAIL:
        return
    email_recipients = []
    if isinstance(recipient_email, list):
        email_recipients.extend(recipient_email)
    else:
        email_recipients.append(recipient_email)
    if message is None:
        errmess = str(err)
    else:
        errmess = message
    try:
        email_address = current_user.email
    except:
        email_address = None
    if the_request:
        try:
            referer = str(the_request.referrer)
        except:
            referer = None
        ipaddress = get_requester_ip(the_request)
    else:
        referer = None
        ipaddress = None
    if daconfig.get('error notification variables', DEBUG):
        if the_vars is None:
            try:
                the_vars = docassemble.base.functions.all_variables(include_internal=True)
            except:
                pass
    else:
        the_vars = None
    json_filename = None
    if the_vars is not None and len(the_vars):
        try:
            with tempfile.NamedTemporaryFile(mode='w', prefix="datemp", suffix='.json', delete=False,
                                             encoding='utf-8') as fp:
                fp.write(json.dumps(the_vars, sort_keys=True, indent=2))
                json_filename = fp.name
        except Exception as the_err:
            pass
    interview_path = docassemble.base.functions.interview_path()
    try:
        the_key = 'da:errornotification:' + str(ipaddress)
        existing = r.get(the_key)
        pipe = r.pipeline()
        pipe.set(the_key, 1)
        pipe.expire(the_key, 60)
        pipe.execute()
        if existing:
            return
    except:
        pass
    try:
        try:
            body = "There was an error in the " + app.config[
                'APP_NAME'] + " application.\n\nThe error message was:\n\n" + err.__class__.__name__ + ": " + str(
                errmess)
            if trace is not None:
                body += "\n\n" + str(trace)
            if history is not None:
                body += "\n\n" + BeautifulSoup(history, "html.parser").get_text('\n')
            if referer is not None and referer != 'None':
                body += "\n\nThe referer URL was " + str(referer)
            elif interview_path is not None:
                body += "\n\nThe interview was " + str(interview_path)
            if email_address is not None:
                body += "\n\nThe user was " + str(email_address)
            html = "<html>\n  <body>\n    <p>There was an error in the " + app.config[
                'APP_NAME'] + " application.</p>\n    <p>The error message was:</p>\n<pre>" + err.__class__.__name__ + ": " + str(
                errmess)
            if trace is not None:
                html += "\n\n" + str(trace)
            html += "</pre>\n"
            if history is not None:
                html += str(history)
            if referer is not None and referer != 'None':
                html += "<p>The referer URL was " + str(referer) + "</p>"
            elif interview_path is not None:
                body += "<p>The interview was " + str(interview_path) + "</p>"
            if email_address is not None:
                body += "<p>The user was " + str(email_address) + "</p>"
            if 'external hostname' in daconfig and daconfig['external hostname'] is not None:
                body += "<p>The external hostname was " + str(daconfig['external hostname']) + "</p>"
            html += "\n  </body>\n</html>"
            msg = Message(app.config['APP_NAME'] + " error: " + err.__class__.__name__, recipients=email_recipients,
                          body=body, html=html)
            if json_filename:
                with open(json_filename, 'r', encoding='utf-8') as fp:
                    msg.attach('variables.json', 'application/json', fp.read())
            da_send_mail(msg)
        except Exception as zerr:
            logmessage(str(zerr))
            body = "There was an error in the " + app.config['APP_NAME'] + " application."
            html = "<html>\n  <body>\n    <p>There was an error in the " + app.config[
                'APP_NAME'] + " application.</p>\n  </body>\n</html>"
            msg = Message(app.config['APP_NAME'] + " error: " + err.__class__.__name__, recipients=email_recipients,
                          body=body, html=html)
            if json_filename:
                with open(json_filename, 'r', encoding='utf-8') as fp:
                    msg.attach('variables.json', 'application/json', fp.read())
            da_send_mail(msg)
    except:
        pass


def stash_data(data, expire):
    while True:
        key = random_alphanumeric(16)
        if r.get(key) is None:
            break
    secret = random_string(16)
    packed_data = encrypt_dictionary(data, secret)
    pipe = r.pipeline()
    pipe.set('da:stash:' + key, packed_data)
    pipe.expire('da:stash:' + key, expire)
    pipe.execute()
    return (key, secret)


def retrieve_stashed_data(key, secret, delete=False, refresh=False):
    packed_data = r.get('da:stash:' + key)
    if packed_data is None:
        return None
    try:
        data = decrypt_dictionary(packed_data.decode(), secret)
    except:
        return None
    if delete:
        r.delete('da:stash:' + key)
    elif refresh and isinstance(refresh, int) and refresh > 0:
        r.expire('da:stash:' + key, refresh)
    return data


def make_necessary_dirs():
    for path in (FULL_PACKAGE_DIRECTORY, UPLOAD_DIRECTORY, LOG_DIRECTORY):  # PACKAGE_CACHE
        if not os.path.isdir(path):
            try:
                os.makedirs(path, exist_ok=True)
            except:
                sys.exit("Could not create path: " + path)
        if not os.access(path, os.W_OK):
            sys.exit("Unable to create files in directory: " + path)
    if not os.access(WEBAPP_PATH, os.W_OK):
        sys.exit("Unable to modify the timestamp of the WSGI file: " + WEBAPP_PATH)


make_necessary_dirs()

docassemble.base.functions.update_server(url_finder=get_url_from_file_reference,
                                         navigation_bar=navigation_bar,
                                         chat_partners_available=chat_partners_available,
                                         get_chat_log=get_current_chat_log,
                                         sms_body=sms_body,
                                         send_fax=da_send_fax,
                                         get_sms_session=get_sms_session,
                                         initiate_sms_session=initiate_sms_session,
                                         terminate_sms_session=terminate_sms_session,
                                         applock=applock,
                                         twilio_config=twilio_config,
                                         server_redis=r,
                                         server_redis_user=r_user,
                                         user_id_dict=user_id_dict,
                                         get_user_object=get_user_object,
                                         retrieve_emails=retrieve_emails,
                                         get_short_code=get_short_code,
                                         make_png_for_pdf=make_png_for_pdf,
                                         ocr_google_in_background=ocr_google_in_background,
                                         task_ready=task_ready,
                                         wait_for_task=wait_for_task,
                                         user_interviews=user_interviews,
                                         interview_menu=interview_menu,
                                         get_user_list=get_user_list,
                                         get_user_info=get_user_info,
                                         set_user_info=set_user_info,
                                         make_user_inactive=make_user_inactive,
                                         get_secret=get_secret,
                                         get_session_variables=get_session_variables,
                                         go_back_in_session=go_back_in_session,
                                         create_session=create_new_interview,
                                         set_session_variables=set_session_variables,
                                         get_privileges_list=get_privileges_list,
                                         add_privilege=add_privilege,
                                         remove_privilege=remove_privilege,
                                         add_user_privilege=add_user_privilege,
                                         remove_user_privilege=remove_user_privilege,
                                         get_permissions_of_privilege=get_permissions_of_privilege,
                                         create_user=create_user,
                                         file_set_attributes=file_set_attributes,
                                         file_user_access=file_user_access,
                                         file_privilege_access=file_privilege_access,
                                         fg_make_png_for_pdf=fg_make_png_for_pdf,
                                         fg_make_png_for_pdf_path=fg_make_png_for_pdf_path,
                                         fg_make_pdf_for_word_path=fg_make_pdf_for_word_path,
                                         get_question_data=get_question_data,
                                         fix_pickle_obj=fix_pickle_obj,
                                         main_page_parts=main_page_parts,
                                         SavedFile=SavedFile,
                                         path_from_reference=path_from_reference,
                                         button_class_prefix=app.config['BUTTON_STYLE'],
                                         write_answer_json=write_answer_json,
                                         read_answer_json=read_answer_json,
                                         delete_answer_json=delete_answer_json,
                                         variables_snapshot_connection=variables_snapshot_connection,
                                         get_referer=get_referer,
                                         stash_data=stash_data,
                                         retrieve_stashed_data=retrieve_stashed_data,
                                         secure_filename_spaces_ok=secure_filename_spaces_ok,
                                         secure_filename=secure_filename,
                                         transform_json_variables=transform_json_variables,
                                         get_login_url=get_login_url,
                                         run_action_in_session=run_action_in_session)

password_secret_key = daconfig.get('password secretkey', app.secret_key)

sys_logger = logging.getLogger('docassemble')
sys_logger.setLevel(logging.DEBUG)

LOGFORMAT = daconfig.get('log format',
                         'docassemble: ip=%(clientip)s i=%(yamlfile)s uid=%(session)s user=%(user)s %(message)s')


def add_log_handler():
    tries = 0
    while tries < 5:
        try:
            docassemble_log_handler = logging.FileHandler(filename=os.path.join(LOG_DIRECTORY, 'docassemble.log'))
        except PermissionError:
            time.sleep(1)
            next
        sys_logger.addHandler(docassemble_log_handler)
        break


add_log_handler()

if not in_celery:
    if LOGSERVER is None:
        docassemble.base.logger.set_logmessage(syslog_message_with_timestamp)
    else:
        docassemble.base.logger.set_logmessage(syslog_message)


def null_func(*pargs, **kwargs):
    logmessage("Null function called")
    return None


if in_celery:
    def illegal_worker_convert(*pargs, **kwargs):
        raise Exception("You cannot access the status of a background task from inside of a background task.")


    docassemble.base.functions.update_server(bg_action=null_func,
                                             # async_ocr=null_func,
                                             chord=null_func,
                                             ocr_page=null_func,
                                             ocr_finalize=null_func,
                                             worker_convert=illegal_worker_convert)
else:
    docassemble.base.functions.update_server(bg_action=docassemble.webapp.worker.background_action,
                                             # async_ocr=docassemble.webapp.worker.async_ocr,
                                             chord=chord,
                                             ocr_page=docassemble.webapp.worker.ocr_page,
                                             ocr_dummy=docassemble.webapp.worker.ocr_dummy,
                                             ocr_finalize=docassemble.webapp.worker.ocr_finalize,
                                             worker_convert=docassemble.webapp.worker.convert)


def my_default_url(error, endpoint, values):
    return url_for('index.index')


app.handle_url_build_error = my_default_url

initialize()

if __name__ == "__main__":
    app.run()
