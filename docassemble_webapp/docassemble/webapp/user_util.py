import copy
import copy
import json
import os
import re
import traceback

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
from docassemble.base.config import daconfig
from docassemble.base.error import DAErrorMissingVariable
from docassemble.base.functions import word
from docassemble.base.generate_key import random_alphanumeric, random_string
from docassemble.base.logger import logmessage
from docassemble.webapp.api_key import encrypt_api_key, get_api_key
from docassemble.webapp.app_object import app
from docassemble.webapp.authentication import backup_session, current_info, decrypt_session, encrypt_session, \
    reset_session, restore_session, save_user_dict, save_user_dict_key, update_last_login
from docassemble.webapp.backend import advance_progress, fetch_previous_user_dict, fetch_user_dict, url_for
from docassemble.webapp.config_server import ALLOW_REGISTRATION, DEFAULT_LANGUAGE, NoneType, SHOW_LOGIN, \
    contains_volatile, default_short_title, default_title, main_page_parts
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.page_values import exit_href
from docassemble.webapp.users.models import UserModel
from docassemble.webapp.util import add_referer, get_part, get_requester_ip, illegal_variable_name, jsonify_with_status, \
    process_set_variable, title_converter, \
    transform_json_variables
from flask import current_app, make_response, request, send_file
from flask_login import current_user, login_user
from sqlalchemy import select


def get_question_data(yaml_filename, session_id, secret, use_lock=True, user_dict=None, steps=None, is_encrypted=None,
                      old_user_dict=None, save=True, post_setting=False, advance_progress_meter=False, action=None,
                      encode=False):
    if use_lock:
        obtain_lock(session_id, yaml_filename)
    tbackup = docassemble.base.functions.backup_thread_variables()
    sbackup = backup_session()
    interview = docassemble.base.interview_cache.get_interview(yaml_filename)
    if current_user.is_anonymous:
        if not interview.allowed_to_access(is_anonymous=True):
            raise Exception('Insufficient permissions to run this interview.')
    else:
        if not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
            raise Exception('Insufficient permissions to run this interview.')
    device_id = docassemble.base.functions.this_thread.current_info['user']['device_id']
    session_uid = docassemble.base.functions.this_thread.current_info['user']['session_uid']
    ci = current_info(yaml=yaml_filename, req=request, secret=secret, device_id=device_id, action=action,
                      session_uid=session_uid)
    ci['session'] = session_id
    ci['secret'] = secret
    docassemble.base.functions.this_thread.current_info = ci
    if user_dict is None:
        try:
            steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
        except Exception as err:
            if use_lock:
                release_lock(session_id, yaml_filename)
            raise Exception("Unable to obtain interview dictionary: " + str(err))
    ci['encrypted'] = is_encrypted
    interview_status = docassemble.base.parse.InterviewStatus(current_info=ci)
    # interview_status.checkin = True
    try:
        interview.assemble(user_dict, interview_status=interview_status, old_user_dict=old_user_dict)
    except DAErrorMissingVariable as err:
        if use_lock:
            # save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, changed=False, steps=steps)
            release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        return dict(questionType='undefined_variable', variable=err.variable,
                    message_log=docassemble.base.functions.get_message_log())
    except Exception as e:
        if use_lock:
            release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("get_question_data: failure to assemble interview: " + e.__class__.__name__ + ": " + str(e))
    save_status = docassemble.base.functions.this_thread.misc.get('save_status', 'new')
    restore_session(sbackup)
    docassemble.base.functions.restore_thread_variables(tbackup)
    try:
        the_section = user_dict['nav'].get_section()
        the_section_display = user_dict['nav'].get_section(display=True)
        the_sections = user_dict['nav'].get_sections()
    except:
        the_section = None
        the_section_display = None
        the_sections = []
    if advance_progress_meter:
        if interview.use_progress_bar and interview_status.question.progress is None and save_status == 'new':
            advance_progress(user_dict, interview)
        if interview.use_progress_bar and interview_status.question.progress is not None and (
                user_dict['_internal']['progress'] is None or interview.options.get('strict progress',
                                                                                    False) or interview_status.question.progress >
                user_dict['_internal']['progress']):
            user_dict['_internal']['progress'] = interview_status.question.progress
    if save:
        save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, changed=post_setting,
                       steps=steps)
        if user_dict.get('multi_user', False) is True and is_encrypted is True:
            decrypt_session(secret, user_code=session_id, filename=yaml_filename)
            is_encrypted = False
        if user_dict.get('multi_user', False) is False and is_encrypted is False:
            encrypt_session(secret, user_code=session_id, filename=yaml_filename)
            is_encrypted = True
    if use_lock:
        release_lock(session_id, yaml_filename)
    if interview_status.question.question_type == "response":
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
        return dict(questionType='response', response=response_to_send)
    if interview_status.question.question_type == "sendfile":
        if interview_status.question.response_file is not None:
            the_path = interview_status.question.response_file.path()
        else:
            return jsonify_with_status("Could not send file because the response was None", 404)
        if not os.path.isfile(the_path):
            return jsonify_with_status("Could not send file because " + str(the_path) + " not found", 404)
        response_to_send = send_file(the_path, mimetype=interview_status.extras['content_type'])
        response_to_send.headers[
            'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return dict(questionType='response', response=response_to_send)
    if interview_status.question.language != '*':
        interview_language = interview_status.question.language
    else:
        interview_language = DEFAULT_LANGUAGE
    title_info = interview.get_title(user_dict, status=interview_status,
                                     converter=lambda content, part: title_converter(content, part, interview_status))
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
        'main page corner back button label'] or interview_status.question.cornerback())
    bootstrap_theme = interview.get_bootstrap_theme()
    if steps is None:
        steps = user_dict['_internal']['steps']
    allow_going_back = bool(interview_status.question.can_go_back and (
            steps is None or (steps - user_dict['_internal']['steps_offset']) > 1))
    data = dict(browser_title=interview_status.tabtitle, exit_link=interview_status.exit_link,
                exit_url=interview_status.exit_url, exit_label=interview_status.exit_label,
                title=interview_status.title, display_title=interview_status.display_title,
                short_title=interview_status.short_title, lang=interview_language, steps=steps,
                allow_going_back=allow_going_back, message_log=docassemble.base.functions.get_message_log(),
                section=the_section, display_section=the_section_display, sections=the_sections)
    if allow_going_back:
        data['cornerBackButton'] = interview_status.cornerback
    data.update(interview_status.as_data(user_dict, encode=encode))
    if 'source' in data:
        data['source']['varsLink'] = url_for('get_variables', i=yaml_filename)
        data['source']['varsLabel'] = word('Show variables and values')
    # if interview_status.question.question_type == "review" and len(interview_status.question.fields_used):
    #    next_action_review = dict(action=list(interview_status.question.fields_used)[0], arguments={})
    # else:
    #    next_action_review = None
    if 'reload_after' in interview_status.extras:
        reload_after = 1000 * int(interview_status.extras['reload_after'])
    else:
        reload_after = 0
    # if next_action_review:
    #    data['next_action'] = next_action_review
    data['interview_options'] = interview.options
    if reload_after and reload_after > 0:
        data['reload_after'] = reload_after
    for key in list(data.keys()):
        if key == "_question_name":
            data['questionName'] = data[key]
            del data[key]
        elif key.startswith('_'):
            del data[key]
    data['menu'] = {'items': []}
    menu_items = data['menu']['items']
    if 'menu_items' in interview_status.extras:
        if not isinstance(interview_status.extras['menu_items'], list):
            menu_items.append({'anchor': word("Error: menu_items is not a Python list")})
        elif len(interview_status.extras['menu_items']) > 0:
            for menu_item in interview_status.extras['menu_items']:
                if not (isinstance(menu_item, dict) and 'url' in menu_item and 'label' in menu_item):
                    menu_items.append(
                        {'anchor': word("Error: menu item is not a Python dict with keys of url and label")})
                else:
                    match_action = re.search(r'^\?action=([^\&]+)', menu_item['url'])
                    if match_action:
                        menu_items.append(
                            {'href': menu_item['url'], 'action': match_action.group(1), 'anchor': menu_item['label']})
                    else:
                        menu_items.append({'href': menu_item['url'], 'anchor': menu_item['label']})
    if ALLOW_REGISTRATION:
        sign_in_text = word('Sign in or sign up to save answers')
    else:
        sign_in_text = word('Sign in to save answers')
    if daconfig.get('resume interview after login', False):
        login_url = url_for('user.login', next=url_for('index', i=yaml_filename))
    else:
        login_url = url_for('user.login')
    if interview.consolidated_metadata.get('show login', SHOW_LOGIN):
        if current_user.is_anonymous:
            if len(menu_items) > 0:
                data['menu']['top'] = {'anchor': word("Menu")}
                menu_items.append({'href': login_url, 'anchor': sign_in_text})
            else:
                data['menu']['top'] = {'href': login_url, 'anchor': sign_in_text}
        else:
            if len(menu_items) == 0 and interview.options.get('hide standard menu', False):
                data['menu']['top'] = {'anchor': (
                    current_user.email if current_user.email else re.sub(r'.*\$', '', current_user.social_id))}
            else:
                data['menu']['top'] = {
                    'anchor': current_user.email if current_user.email else re.sub(r'.*\$', '', current_user.social_id)}
                if not interview.options.get('hide standard menu', False):
                    if current_user.has_role('admin', 'developer') and interview.debug:
                        menu_items.append({'href': '#source', 'title': word("How this question came to be asked"),
                                           'anchor': word('Source')})
                    if current_user.has_role('admin', 'advocate') and app.config['ENABLE_MONITOR']:
                        menu_items.append({'href': url_for('monitor'), 'anchor': word('Monitor')})
                    if current_user.has_role('admin', 'developer', 'trainer'):
                        menu_items.append({'href': url_for('train'), 'anchor': word('Train')})
                    if current_user.has_role('admin', 'developer'):
                        if app.config['ALLOW_UPDATES']:
                            menu_items.append({'href': url_for('update_package'), 'anchor': word('Package Management')})
                        menu_items.append({'href': url_for('logs'), 'anchor': word('Logs')})
                        if app.config['ENABLE_PLAYGROUND']:
                            menu_items.append({'href': url_for('playground_page'), 'anchor': word('Playground')})
                        menu_items.append({'href': url_for('utilities'), 'anchor': word('Utilities')})
                        if current_user.has_role('admin', 'advocate') or current_user.can_do('access_user_info'):
                            menu_items.append({'href': url_for('user_list'), 'anchor': word('User List')})
                        if current_user.has_role('admin'):
                            menu_items.append({'href': url_for('config_page'), 'anchor': word('Configuration')})
                    if app.config['SHOW_DISPATCH']:
                        menu_items.append({'href': url_for('interview_start'), 'anchor': word('Available Interviews')})
                    for item in app.config['ADMIN_INTERVIEWS']:
                        if item.can_use() and docassemble.base.functions.this_thread.current_info.get('yaml_filename',
                                                                                                      '') != item.interview:
                            menu_items.append({'href': url_for('index'),
                                               'anchor': item.get_title(docassemble.base.functions.get_language())})
                    if app.config['SHOW_MY_INTERVIEWS'] or current_user.has_role('admin'):
                        menu_items.append({'href': url_for('interview_list'), 'anchor': word('My Interviews')})
                    if current_user.has_role('admin', 'developer'):
                        menu_items.append({'href': url_for('user_profile_page'), 'anchor': word('Profile')})
                    else:
                        if app.config['SHOW_PROFILE'] or current_user.has_role('admin'):
                            menu_items.append({'href': url_for('user_profile_page'), 'anchor': word('Profile')})
                        else:
                            menu_items.append(
                                {'href': url_for('user.change_password'), 'anchor': word('Change Password')})
                    menu_items.append({'href': url_for('user.logout'), 'anchor': word('Sign Out')})
    else:
        if len(menu_items) > 0:
            data['menu']['top'] = {'anchor': word("Menu")}
            if not interview.options.get('hide standard menu', False):
                menu_items.append({'href': exit_href(interview_status), 'anchor': interview_status.exit_label})
        else:
            data['menu']['top'] = {'href': exit_href(interview_status), 'anchor': interview_status.exit_label}
    return data


def create_new_interview(yaml_filename, secret, url_args=None, referer=None, req=None):
    interview = docassemble.base.interview_cache.get_interview(yaml_filename)
    if current_user.is_anonymous:
        if not interview.allowed_to_initiate(is_anonymous=True):
            raise Exception('Insufficient permissions to run this interview.')
        if not interview.allowed_to_access(is_anonymous=True):
            raise Exception('Insufficient permissions to run this interview.')
    else:
        if (not current_user.has_role('admin')) and (
                not interview.allowed_to_initiate(has_roles=[role.name for role in current_user.roles])):
            raise Exception('Insufficient permissions to run this interview.')
        if not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
            raise Exception('Insufficient permissions to run this interview.')
    if req is None:
        req = request
    if secret is None:
        secret = random_string(16)
    tbackup = docassemble.base.functions.backup_thread_variables()
    sbackup = backup_session()
    session_id, user_dict = reset_session(yaml_filename, secret)
    add_referer(user_dict, referer=referer)
    if url_args and (isinstance(url_args, dict) or (
            hasattr(url_args, 'instanceName') and hasattr(url_args, 'elements') and isinstance(url_args.elements,
                                                                                               dict))):
        for key, val in url_args.items():
            if isinstance(val, str):
                val = val.encode('unicode_escape').decode()
            exec("url_args['" + key + "'] = " + repr(val), user_dict)
    device_id = docassemble.base.functions.this_thread.current_info['user']['device_id']
    session_uid = docassemble.base.functions.this_thread.current_info['user']['session_uid']
    ci = current_info(yaml=yaml_filename, req=req, secret=secret, device_id=device_id, session_uid=session_uid)
    ci['session'] = session_id
    ci['encrypted'] = True
    ci['secret'] = secret
    interview_status = docassemble.base.parse.InterviewStatus(current_info=ci)
    interview_status.checkin = True
    try:
        interview.assemble(user_dict, interview_status)
    except DAErrorMissingVariable as err:
        pass
    except Exception as e:
        release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        if hasattr(e, 'traceback'):
            the_trace = e.traceback
        else:
            the_trace = traceback.format_exc()
        raise Exception(
            "create_new_interview: failure to assemble interview: " + e.__class__.__name__ + ": " + str(e) + "\n" + str(
                the_trace))
    restore_session(sbackup)
    docassemble.base.functions.restore_thread_variables(tbackup)
    encrypted = not bool(user_dict.get('multi_user', False) is True)
    save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=encrypted, changed=False, steps=1)
    save_user_dict_key(session_id, yaml_filename)
    release_lock(session_id, yaml_filename)
    return (encrypted, session_id)


def set_session_variables(yaml_filename, session_id, variables, secret=None, return_question=False,
                          literal_variables=None, del_variables=None, question_name=None, event_list=None,
                          advance_progress_meter=False, post_setting=True, use_lock=False, encode=False,
                          process_objects=False):
    if use_lock:
        obtain_lock(session_id, yaml_filename)
    tbackup = docassemble.base.functions.backup_thread_variables()
    sbackup = backup_session()
    device_id = docassemble.base.functions.this_thread.current_info['user']['device_id']
    session_uid = docassemble.base.functions.this_thread.current_info['user']['session_uid']
    if secret is None:
        secret = docassemble.base.functions.this_thread.current_info.get('secret', None)
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
    except:
        if use_lock:
            release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to decrypt interview dictionary.")
    vars_set = set()
    old_values = {}
    if user_dict is None:
        if use_lock:
            release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to obtain interview dictionary.")
    if process_objects:
        variables = transform_json_variables(variables)
    pre_assembly_necessary = False
    for key, val in variables.items():
        if contains_volatile.search(key):
            pre_assembly_necessary = True
            break
    if pre_assembly_necessary is False and literal_variables is not None:
        for key, val in literal_variables.items():
            if contains_volatile.search(key):
                pre_assembly_necessary = True
                break
    if pre_assembly_necessary is False and del_variables is not None:
        for key in del_variables:
            if contains_volatile.search(key):
                pre_assembly_necessary = True
                break
    if pre_assembly_necessary:
        interview = docassemble.base.interview_cache.get_interview(yaml_filename)
        if current_user.is_anonymous:
            if not interview.allowed_to_access(is_anonymous=True):
                if use_lock:
                    release_lock(session_id, yaml_filename)
                restore_session(sbackup)
                docassemble.base.functions.restore_thread_variables(tbackup)
                raise Exception('Insufficient permissions to run this interview.')
        else:
            if not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                if use_lock:
                    release_lock(session_id, yaml_filename)
                restore_session(sbackup)
                docassemble.base.functions.restore_thread_variables(tbackup)
                raise Exception('Insufficient permissions to run this interview.')
        ci = current_info(yaml=yaml_filename, req=request, secret=secret, device_id=device_id, session_uid=session_uid)
        ci['session'] = session_id
        ci['encrypted'] = is_encrypted
        ci['secret'] = secret
        interview_status = docassemble.base.parse.InterviewStatus(current_info=ci)
        try:
            interview.assemble(user_dict, interview_status)
        except Exception as err:
            if use_lock:
                release_lock(session_id, yaml_filename)
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            raise Exception("Error processing session: " + err.__class__.__name__ + ": " + str(err))
    try:
        for key, val in variables.items():
            if illegal_variable_name(key):
                raise Exception("Illegal value as variable name.")
            if isinstance(val, (str, bool, int, float, NoneType)):
                exec(str(key) + ' = ' + repr(val), user_dict)
            else:
                if key == '_xxxtempvarxxx':
                    continue
                user_dict['_xxxtempvarxxx'] = copy.deepcopy(val)
                exec(str(key) + ' = _xxxtempvarxxx', user_dict)
                del user_dict['_xxxtempvarxxx']
            process_set_variable(str(key), user_dict, vars_set, old_values)
    except Exception as the_err:
        if '_xxxtempvarxxx' in user_dict:
            del user_dict['_xxxtempvarxxx']
        if use_lock:
            release_lock(session_id, yaml_filename)
        restore_session(sbackup)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Problem setting variables:" + str(the_err))
    if literal_variables is not None:
        exec('import docassemble.base.util', user_dict)
        for key, val in literal_variables.items():
            if illegal_variable_name(key):
                if use_lock:
                    release_lock(session_id, yaml_filename)
                restore_session(sbackup)
                docassemble.base.functions.restore_thread_variables(tbackup)
                raise Exception("Illegal value as variable name.")
            exec(str(key) + ' = ' + val, user_dict)
            process_set_variable(str(key), user_dict, vars_set, old_values)
    if question_name is not None:
        interview = docassemble.base.interview_cache.get_interview(yaml_filename)
        if current_user.is_anonymous:
            if not interview.allowed_to_access(is_anonymous=True):
                if use_lock:
                    release_lock(session_id, yaml_filename)
                restore_session(sbackup)
                docassemble.base.functions.restore_thread_variables(tbackup)
                raise Exception('Insufficient permissions to run this interview.')
        else:
            if not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                if use_lock:
                    release_lock(session_id, yaml_filename)
                restore_session(sbackup)
                docassemble.base.functions.restore_thread_variables(tbackup)
                raise Exception('Insufficient permissions to run this interview.')
        if question_name in interview.questions_by_name:
            interview.questions_by_name[question_name].mark_as_answered(user_dict)
        else:
            if use_lock:
                release_lock(session_id, yaml_filename)
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            raise Exception("Problem marking question as completed")
    if del_variables is not None:
        try:
            for key in del_variables:
                if illegal_variable_name(key):
                    raise Exception("Illegal value as variable name.")
                exec('del ' + str(key), user_dict)
        except Exception as the_err:
            if use_lock:
                release_lock(session_id, yaml_filename)
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            raise Exception("Problem deleting variables: " + str(the_err))
    session_uid = docassemble.base.functions.this_thread.current_info['user']['session_uid']
    # if 'event_stack' in user_dict['_internal']:
    #    logmessage("Event stack starting as: " + repr(user_dict['_internal']['event_stack']))
    # else:
    #    logmessage("No event stack.")
    if event_list is not None and len(event_list) and 'event_stack' in user_dict['_internal'] and session_uid in \
            user_dict['_internal']['event_stack'] and len(user_dict['_internal']['event_stack'][session_uid]):
        for event_name in event_list:
            if user_dict['_internal']['event_stack'][session_uid][0]['action'] == event_name:
                user_dict['_internal']['event_stack'][session_uid].pop(0)
                # logmessage("Popped " + str(event_name))
            if len(user_dict['_internal']['event_stack'][session_uid]) == 0:
                break
    if len(vars_set) > 0 and 'event_stack' in user_dict['_internal'] and session_uid in user_dict['_internal'][
        'event_stack'] and len(user_dict['_internal']['event_stack'][session_uid]):
        for var_name in vars_set:
            if user_dict['_internal']['event_stack'][session_uid][0]['action'] == var_name:
                user_dict['_internal']['event_stack'][session_uid].pop(0)
                # logmessage("Popped " + str(var_name))
            if len(user_dict['_internal']['event_stack'][session_uid]) == 0:
                break
    if question_name is not None:
        for var_name in vars_set:
            if var_name in interview.invalidation_todo or var_name in interview.onchange_todo:
                interview.invalidate_dependencies(var_name, user_dict, old_values)
            try:
                del user_dict['_internal']['dirty'][var_name]
            except:
                pass
    # if 'event_stack' in user_dict['_internal']:
    #    logmessage("Event stack now: " + repr(user_dict['_internal']['event_stack']))
    if post_setting:
        steps += 1
    if return_question:
        try:
            data = get_question_data(yaml_filename, session_id, secret, use_lock=False, user_dict=user_dict,
                                     steps=steps, is_encrypted=is_encrypted, post_setting=post_setting,
                                     advance_progress_meter=advance_progress_meter, encode=encode)
        except Exception as the_err:
            if use_lock:
                release_lock(session_id, yaml_filename)
            restore_session(sbackup)
            docassemble.base.functions.restore_thread_variables(tbackup)
            raise Exception("Problem getting current question:" + str(the_err))
    else:
        data = None
    if not return_question:
        save_user_dict(session_id, user_dict, yaml_filename, secret=secret, encrypt=is_encrypted, changed=post_setting,
                       steps=steps)
        if 'multi_user' in vars_set:
            if user_dict.get('multi_user', False) is True and is_encrypted is True:
                decrypt_session(secret, user_code=session_id, filename=yaml_filename)
                is_encrypted = False
            if user_dict.get('multi_user', False) is False and is_encrypted is False:
                encrypt_session(secret, user_code=session_id, filename=yaml_filename)
                is_encrypted = True
    if use_lock:
        release_lock(session_id, yaml_filename)
    restore_session(sbackup)
    docassemble.base.functions.restore_thread_variables(tbackup)
    return data


def go_back_in_session(yaml_filename, session_id, secret=None, return_question=False, use_lock=False, encode=False):
    if use_lock:
        obtain_lock(session_id, yaml_filename)
    tbackup = docassemble.base.functions.backup_thread_variables()
    docassemble.base.functions.this_thread.current_info['yaml_filename'] = yaml_filename
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
    except:
        if use_lock:
            release_lock(session_id, yaml_filename)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to decrypt interview dictionary.")
    if user_dict is None:
        if use_lock:
            release_lock(session_id, yaml_filename)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to obtain interview dictionary.")
    if steps == 1:
        if use_lock:
            release_lock(session_id, yaml_filename)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Cannot go back.")
    old_user_dict = user_dict
    steps, user_dict, is_encrypted = fetch_previous_user_dict(session_id, yaml_filename, secret)
    if user_dict is None:
        if use_lock:
            release_lock(session_id, yaml_filename)
        docassemble.base.functions.restore_thread_variables(tbackup)
        raise Exception("Unable to obtain interview dictionary.")
    if return_question:
        try:
            data = get_question_data(yaml_filename, session_id, secret, use_lock=False, user_dict=user_dict,
                                     steps=steps, is_encrypted=is_encrypted, old_user_dict=old_user_dict, encode=encode)
        except Exception as the_err:
            if use_lock:
                release_lock(session_id, yaml_filename)
            docassemble.base.functions.restore_thread_variables(tbackup)
            raise Exception("Problem getting current question:" + str(the_err))
    else:
        data = None
    if use_lock:
        release_lock(session_id, yaml_filename)
    docassemble.base.functions.restore_thread_variables(tbackup)
    return data


def api_verify(req, roles=None, permissions=None):
    api_key = get_api_key()
    if api_key is None:
        logmessage("api_verify: no API key provided")
        return False
    api_key = encrypt_api_key(api_key, current_app.secret_key)
    rkeys = r.keys('da:apikey:userid:*:key:' + api_key + ':info')
    if len(rkeys) == 0:
        logmessage("api_verify: API key not found")
        return False
    try:
        info = json.loads(r.get(rkeys[0].decode()).decode())
    except:
        logmessage("api_verify: API information could not be unpacked")
        return False
    m = re.match(r'da:apikey:userid:([0-9]+):key:' + re.escape(api_key) + ':info', rkeys[0].decode())
    if not m:
        logmessage("api_verify: user id could not be extracted")
        return False
    user_id = m.group(1)
    if not isinstance(info, dict):
        logmessage("api_verify: API information was in the wrong format")
        return False
    if len(info['constraints']) > 0:
        clientip = get_requester_ip(request)
        if info['method'] == 'ip' and clientip not in info['constraints']:
            logmessage("api_verify: IP address " + str(clientip) + " did not match")
            return False
        if info['method'] == 'referer':
            if not request.referrer:
                the_referer = request.headers.get('Origin', None)
                if not the_referer:
                    logmessage("api_verify: could not authorize based on referer because no referer provided")
                    return False
            else:
                the_referer = request.referrer
            matched = False
            for constraint in info['constraints']:
                constraint = re.sub(r'^[\*]+|[\*]+$', '', constraint)
                constraint = re.escape(constraint)
                constraint = re.sub(r'\\\*+', '.*', constraint)
                the_referer = re.sub(r'\?.*', '', the_referer)
                the_referer = re.sub(r'^https?://([^/]*)/', r'\1', the_referer)
                if re.search(constraint, the_referer):
                    matched = True
                    break
            if not matched:
                logmessage("api_verify: authorization failure referer " + str(the_referer) + " could not be matched")
                return False
    user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    if user is None or user.social_id.startswith('disabled$'):
        logmessage("api_verify: user does not exist")
        return False
    if not user.active:
        logmessage("api_verify: user is no longer active")
        return False
    login_user(user, remember=False)
    update_last_login(user)
    if current_user.has_role('admin') and 'permissions' in info and len(info['permissions']) > 0:
        current_user.limited_api = True
        current_user.limits = info['permissions']
    ok_permission = False
    if permissions:
        for permission in permissions:
            if current_user.can_do(permission):
                ok_permission = True
                break
        if current_user.limited_api and not ok_permission:
            logmessage("api_verify: user did not have correct privileges for resource")
            return False
    if roles and not ok_permission:
        ok_role = False
        for role in roles:
            if current_user.has_role(role):
                ok_role = True
                break
        if not ok_role:
            logmessage("api_verify: user did not have correct privileges for resource")
            return False
    docassemble.base.functions.this_thread.current_info = current_info(req=request, interface='api',
                                                                       device_id=request.cookies.get('ds', None),
                                                                       session_uid=current_user.email)
    return True

