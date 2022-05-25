import ast
import codecs
import copy
import datetime
import importlib
import inspect
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import types
import unicodedata
from urllib.parse import quote as urllibquote, unquote as urllibunquote

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
import oauth2client.client
import werkzeug.exceptions
import werkzeug.utils
from Crypto.Hash import MD5
from docassemble.base.config import daconfig, hostname
from docassemble.base.error import DAError, DAErrorCompileError, DAErrorMissingVariable, DAErrorNoEndpoint
from docassemble.base.functions import word
from docassemble.base.generate_key import random_alphanumeric, random_string
from docassemble.base.logger import logmessage
from docassemble.base.util import DADict, DAList, DAObject
from docassemble.webapp.app_object import app
from docassemble.webapp.backend import cloud, directory_for, \
    generate_csrf, initial_dict, url_for
from docassemble.webapp.config_server import DEFAULT_LANGUAGE, \
    DOCUMENTATION_BASE, HTTP_TO_HTTPS, START_TIME, SUPERVISORCTL, TypeType, USING_SUPERVISOR, \
    WEBAPP_PATH, amp_match, base_name_info, documentation_dict, \
    equals_byte, extraneous_var, gt_match, lt_match, noquote_match, page_parts, the_method_type, \
    title_documentation, valid_python_var
from docassemble.webapp.core.models import Supervisors
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.users.models import Role, UserAuthModel, UserModel
from flask import Markup, current_app, jsonify, redirect, request, session
from flask_login import current_user
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import YamlLexer
from sqlalchemy import delete, select
from user_agents import parse as ua_parse


def tidy_action(action):
    result = {}
    if not isinstance(action, dict):
        return result
    if 'action' in action:
        result['action'] = action['action']
    if 'arguments' in action:
        result['arguments'] = action['arguments']
    return result


def as_int(val):
    try:
        return int(val)
    except:
        return 0


def get_safe_next_param(param_name, default_endpoint):
    if param_name in request.args:
        safe_next = current_app.user_manager.make_safe_url_function(urllibunquote(request.args[param_name]))
    else:
        safe_next = endpoint_url(default_endpoint)
    return safe_next


def endpoint_url(endpoint, **kwargs):
    url = url_for('index.index')
    if endpoint:
        url = url_for(endpoint, **kwargs)
    return url


def get_base_url():
    return re.sub(r'^(https?://[^/]+).*', r'\1', url_for('rootindex', _external=True))


def pad_to_16(the_string):
    if len(the_string) >= 16:
        return the_string[:16]
    return str(the_string) + (16 - len(the_string)) * '0'


def fix_http(url):
    if HTTP_TO_HTTPS:
        return re.sub(r'^http:', 'https:', url)
    return url


def add_timestamps(the_dict, manual_user_id=None):
    nowtime = datetime.datetime.utcnow()
    the_dict['_internal']['starttime'] = nowtime
    the_dict['_internal']['modtime'] = nowtime
    if manual_user_id is not None or (current_user and current_user.is_authenticated and not current_user.is_anonymous):
        if manual_user_id is not None:
            the_user_id = manual_user_id
        else:
            the_user_id = current_user.id
        the_dict['_internal']['accesstime'][the_user_id] = nowtime
    else:
        the_dict['_internal']['accesstime'][-1] = nowtime


def fresh_dictionary():
    the_dict = copy.deepcopy(initial_dict)
    add_timestamps(the_dict)
    return the_dict


def indent_by(text, num):
    if not text:
        return ""
    return (" " * num) + re.sub(r'\n', "\n" + (" " * num), text).rstrip() + "\n"


def get_requester_ip(req):
    if not req:
        return '127.0.0.1'
    if HTTP_TO_HTTPS:
        if 'X-Real-Ip' in req.headers:
            return req.headers['X-Real-Ip']
        if 'X-Forwarded-For' in req.headers:
            return req.headers['X-Forwarded-For']
    return req.remote_addr


def MD5Hash(data=None):
    if data is None:
        data = ''
    h = MD5.new()
    h.update(bytearray(data, encoding='utf-8'))
    return h


def safe_quote_func(string, safe='', encoding=None, errors=None):
    return urllibquote(string, safe='', encoding=encoding, errors=errors)


class RedisCredStorage(oauth2client.client.Storage):
    def __init__(self, app='googledrive'):
        self.key = 'da:' + app + ':userid:' + str(current_user.id)
        self.lockkey = 'da:' + app + ':lock:userid:' + str(current_user.id)

    def acquire_lock(self):
        pipe = r.pipeline()
        pipe.set(self.lockkey, 1)
        pipe.expire(self.lockkey, 5)
        pipe.execute()

    def release_lock(self):
        r.delete(self.lockkey)

    def locked_get(self):
        json_creds = r.get(self.key)
        creds = None
        if json_creds is not None:
            json_creds = json_creds.decode()
            try:
                creds = oauth2client.client.Credentials.new_from_json(json_creds)
            except:
                logmessage("RedisCredStorage: could not read credentials from " + str(json_creds))
        return creds

    def locked_put(self, credentials):
        r.set(self.key, credentials.to_json())

    def locked_delete(self):
        r.delete(self.key)


def secure_filename(filename):
    filename = werkzeug.utils.secure_filename(filename)
    extension, mimetype = get_ext_and_mimetype(filename)
    filename = re.sub(r'\.[^\.]+$', '', filename) + '.' + extension
    return filename


def secure_filename_spaces_ok(filename):
    filename = unicodedata.normalize("NFKD", filename)
    filename = filename.encode("ascii", "ignore").decode("ascii")
    for sep in os.path.sep, os.path.altsep:
        if sep:
            filename = filename.replace(sep, "_")
    filename = str(re.sub(r'[^A-Za-z0-9\_\.\- ]', '', " ".join(filename.split(' ')))).strip("._ ")
    return filename


def should_run_create(package_name):
    if package_name in ('docassemble.base', 'docassemble.webapp', 'docassemble.demo', 'docassemble'):
        return True
    return False


def splitall(path):
    allparts = []
    while 1:
        parts = os.path.split(path)
        if parts[0] == path:
            allparts.insert(0, parts[0])
            break
        elif parts[1] == path:
            allparts.insert(0, parts[1])
            break
        else:
            path = parts[0]
            allparts.insert(0, parts[1])
    return allparts


def process_bracket_expression(match):
    if match.group(1) in ('B', 'R'):
        try:
            inner = codecs.decode(repad(bytearray(match.group(2), encoding='utf-8')), 'base64').decode('utf-8')
        except:
            inner = match.group(2)
    else:
        inner = match.group(2)
    return "[" + repr(inner) + "]"


def myb64unquote(the_string):
    return codecs.decode(repad(bytearray(the_string, encoding='utf-8')), 'base64').decode('utf-8')


def safeid(text):
    return re.sub(r'[\n=]', '', codecs.encode(text.encode('utf-8'), 'base64').decode())


def from_safeid(text):
    return codecs.decode(repad(bytearray(text, encoding='utf-8')), 'base64').decode('utf-8')


def repad(text):
    return text + (equals_byte * ((4 - len(text) % 4) % 4))


def test_for_valid_var(varname):
    if not valid_python_var.match(varname):
        raise DAError(
            varname + " is not a valid name.  A valid name consists only of letters, numbers, and underscores, and begins with a letter.")


def tidy_action(action):
    result = {}
    if not isinstance(action, dict):
        return result
    if 'action' in action:
        result['action'] = action['action']
    if 'arguments' in action:
        result['arguments'] = action['arguments']
    return result


def refresh_or_continue(interview, post_data):
    return_val = False
    try:
        if interview.questions_by_name[post_data['_question_name']].fields[0].choices[
            int(post_data['X211bHRpcGxlX2Nob2ljZQ'])]['key'].question_type in ('refresh', 'continue'):
            return_val = True
    except:
        pass
    return return_val


def is_mobile_or_tablet():
    ua_string = request.headers.get('User-Agent', None)
    if ua_string is not None:
        response = ua_parse(ua_string)
        if response.is_mobile or response.is_tablet:
            return True
    return False


def get_referer():
    return request.referrer or None


def add_referer(user_dict, referer=None):
    if referer:
        user_dict['_internal']['referer'] = referer
    elif request.referrer:
        user_dict['_internal']['referer'] = request.referrer
    else:
        user_dict['_internal']['referer'] = None


def update_current_info_with_session_info(the_current_info, session_info):
    if session_info is not None:
        user_code = session_info['uid']
        encrypted = session_info['encrypted']
    else:
        user_code = None
        encrypted = True
    the_current_info.update({'session': user_code, 'encrypted': encrypted})


def do_redirect(url, is_ajax, is_json, js_target):
    if is_ajax:
        return jsonify(action='redirect', url=url, csrf_token=generate_csrf())
    if is_json:
        if re.search(r'\?', url):
            url = url + '&json=1'
        else:
            url = url + '?json=1'
    if js_target and 'js_target=' not in url:
        if re.search(r'\?', url):
            url = url + '&js_target=' + js_target
        else:
            url = url + '?js_target=' + js_target
    return redirect(url)


def illegal_variable_name(var):
    if re.search(r'[\n\r]', var):
        return True
    try:
        t = ast.parse(var)
    except:
        return True
    detector = docassemble.base.astparser.detectIllegal()
    detector.visit(t)
    return detector.illegal


def sub_indices(the_var, the_user_dict):
    try:
        if the_var.startswith('x.') and 'x' in the_user_dict and isinstance(the_user_dict['x'], DAObject):
            the_var = re.sub(r'^x\.', the_user_dict['x'].instanceName + '.', the_var)
        if the_var.startswith('x[') and 'x' in the_user_dict and isinstance(the_user_dict['x'], DAObject):
            the_var = re.sub(r'^x\[', the_user_dict['x'].instanceName + '[', the_var)
        if re.search(r'\[[ijklmn]\]', the_var):
            the_var = re.sub(r'\[([ijklmn])\]', lambda m: '[' + repr(the_user_dict[m.group(1)]) + ']', the_var)
    except KeyError as the_err:
        missing_var = str(the_err)
        raise DAError("Reference to variable " + missing_var + " that was not defined")
    return the_var


def process_set_variable(field_name, user_dict, vars_set, old_values):
    vars_set.add(field_name)
    try:
        old_values[field_name] = eval(field_name, user_dict)
    except:
        pass


def process_file(saved_file, orig_file, mimetype, extension, initial=True):
    if extension == "gif" and daconfig.get('imagemagick', 'convert') is not None:
        unconverted = tempfile.NamedTemporaryFile(prefix="datemp", suffix=".gif", delete=False)
        converted = tempfile.NamedTemporaryFile(prefix="datemp", suffix=".png", delete=False)
        shutil.move(orig_file, unconverted.name)
        call_array = [daconfig.get('imagemagick', 'convert'), str(unconverted.name), 'png:' + converted.name]
        try:
            result = subprocess.run(call_array, timeout=60, check=False).returncode
        except subprocess.TimeoutExpired:
            logmessage("process_file: convert from gif took too long")
            result = 1
        if result == 0:
            saved_file.copy_from(converted.name, filename=re.sub(r'\.[^\.]+$', '', saved_file.filename) + '.png')
        else:
            logmessage("process_file: error converting from gif to png")
        shutil.move(unconverted.name, saved_file.path)
        saved_file.save()
    elif extension == "jpg" and daconfig.get('imagemagick', 'convert') is not None:
        unrotated = tempfile.NamedTemporaryFile(prefix="datemp", suffix=".jpg", delete=False)
        rotated = tempfile.NamedTemporaryFile(prefix="datemp", suffix=".jpg", delete=False)
        shutil.move(orig_file, unrotated.name)
        call_array = [daconfig.get('imagemagick', 'convert'), str(unrotated.name), '-auto-orient', '-density', '300',
                      'jpeg:' + rotated.name]
        try:
            result = subprocess.run(call_array, timeout=60, check=False).returncode
        except subprocess.TimeoutExpired:
            logmessage("process_file: convert from jpeg took too long")
            result = 1
        if result == 0:
            saved_file.copy_from(rotated.name)
        else:
            saved_file.copy_from(unrotated.name)
    elif initial:
        shutil.move(orig_file, saved_file.path)
        saved_file.save()
    if mimetype == 'audio/ogg' and daconfig.get('pacpl', 'pacpl') is not None:
        call_array = [daconfig.get('pacpl', 'pacpl'), '-t', 'mp3', saved_file.path + '.' + extension]
        try:
            result = subprocess.run(call_array, timeout=120, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 1
    if mimetype == 'audio/3gpp' and daconfig.get('ffmpeg', 'ffmpeg') is not None:
        call_array = [daconfig.get('ffmpeg', 'ffmpeg'), '-i', saved_file.path + '.' + extension,
                      saved_file.path + '.ogg']
        try:
            result = subprocess.run(call_array, timeout=120, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 1
        call_array = [daconfig.get('ffmpeg', 'ffmpeg'), '-i', saved_file.path + '.' + extension,
                      saved_file.path + '.mp3']
        try:
            result = subprocess.run(call_array, timeout=120, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 1
    if mimetype in ('audio/x-wav', 'audio/wav') and daconfig.get('pacpl', 'pacpl') is not None:
        call_array = [daconfig.get('pacpl', 'pacpl'), '-t', 'mp3', saved_file.path + '.' + extension]
        try:
            result = subprocess.run(call_array, timeout=120, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 1
        call_array = [daconfig.get('pacpl', 'pacpl'), '-t', 'ogg', saved_file.path + '.' + extension]
        try:
            result = subprocess.run(call_array, timeout=120, check=False).returncode
        except subprocess.TimeoutExpired:
            result = 1
    saved_file.finalize()


def get_history(interview, interview_status):
    output = ''
    has_question = bool(hasattr(interview_status, 'question'))
    index = 0
    seeking_len = len(interview_status.seeking)
    if seeking_len:
        starttime = interview_status.seeking[0]['time']
        seen_done = False
        for stage in interview_status.seeking:
            if seen_done:
                output = ''
                seen_done = False
            index += 1
            if index < seeking_len and 'reason' in interview_status.seeking[index] and interview_status.seeking[index][
                'reason'] in ('asking', 'running') and interview_status.seeking[index]['question'] is stage[
                'question'] and 'question' in stage and 'reason' in stage and stage['reason'] == 'considering':
                continue
            the_time = " at %.5fs" % (stage['time'] - starttime)
            if 'question' in stage and 'reason' in stage and (
                    has_question is False or index < (seeking_len - 1) or stage[
                'question'] is not interview_status.question):
                if stage['reason'] == 'initial':
                    output += "          <h5>Ran initial code" + the_time + "</h5>\n"
                elif stage['reason'] == 'mandatory question':
                    output += "          <h5>Tried to ask mandatory question" + the_time + "</h5>\n"
                elif stage['reason'] == 'mandatory code':
                    output += "          <h5>Tried to run mandatory code" + the_time + "</h5>\n"
                elif stage['reason'] == 'asking':
                    output += "          <h5>Tried to ask question" + the_time + "</h5>\n"
                elif stage['reason'] == 'running':
                    output += "          <h5>Tried to run block" + the_time + "</h5>\n"
                elif stage['reason'] == 'considering':
                    output += "          <h5>Considered using block" + the_time + "</h5>\n"
                elif stage['reason'] == 'objects from file':
                    output += "          <h5>Tried to load objects from file" + the_time + "</h5>\n"
                elif stage['reason'] == 'data':
                    output += "          <h5>Tried to load data" + the_time + "</h5>\n"
                elif stage['reason'] == 'objects':
                    output += "          <h5>Tried to load objects" + the_time + "</h5>\n"
                elif stage['reason'] == 'result of multiple choice':
                    output += "          <h5>Followed the result of multiple choice selection" + the_time + "</h5>\n"
                if stage['question'].from_source.path != interview.source.path and stage[
                    'question'].from_source.path is not None:
                    output += '          <p style="font-weight: bold;"><small>(' + word('from') + ' ' + stage[
                        'question'].from_source.path + ")</small></p>\n"
                if (not hasattr(stage['question'], 'source_code')) or stage['question'].source_code is None:
                    output += word('(embedded question, source code not available)')
                else:
                    output += highlight(stage['question'].source_code, YamlLexer(), HtmlFormatter())
            elif 'variable' in stage:
                output += '          <h5>Needed definition of <code class="da-variable-needed">' + str(
                    stage['variable']) + "</code>" + the_time + "</h5>\n"
            elif 'done' in stage:
                output += "          <h5>Completed processing" + the_time + "</h5>\n"
                seen_done = True
    return output


def title_converter(content, part, status):
    if part in ('exit link', 'exit url', 'title url', 'title url opens in other window'):
        return content
    if part in (
            'title', 'subtitle', 'short title', 'tab title', 'exit label', 'back button label',
            'corner back button label',
            'logo', 'short logo', 'navigation bar html'):
        return docassemble.base.util.markdown_to_html(content, status=status, trim=True, do_terms=False)
    return docassemble.base.util.markdown_to_html(content, status=status)


def get_part(part, default=None):
    if default is None:
        default = str()
    if part not in page_parts:
        return default
    if 'language' in session:
        lang = session['language']
    else:
        lang = DEFAULT_LANGUAGE
    if lang in page_parts[part]:
        return page_parts[part][lang]
    if lang != DEFAULT_LANGUAGE and DEFAULT_LANGUAGE in page_parts[part]:
        return page_parts[part][DEFAULT_LANGUAGE]
    if '*' in page_parts[part]:
        return page_parts[part]['*']
    return default


def noquote(string):
    if string is None:
        return string
    string = amp_match.sub('&amp;', string)
    string = noquote_match.sub('&quot;', string)
    string = lt_match.sub('&lt;', string)
    string = gt_match.sub('&gt;', string)
    return string


def restart_on(host):
    logmessage("restart_on: " + str(host.hostname))
    if host.hostname == hostname:
        the_url = 'http://localhost:9001'
    else:
        the_url = host.url
    args = [SUPERVISORCTL, '-s', the_url, 'start', 'reset']
    result = subprocess.run(args, check=False).returncode
    if result == 0:
        logmessage("restart_on: sent reset to " + str(host.hostname))
    else:
        logmessage("restart_on: call to supervisorctl with reset on " + str(host.hostname) + " was not successful")
        return False
    return True


def restart_this():
    logmessage("restart_this: hostname is " + str(hostname))
    if USING_SUPERVISOR:
        to_delete = set()
        for host in db.session.execute(select(Supervisors)).scalars():
            if host.url:
                logmessage("restart_this: considering " + str(host.hostname) + " against " + str(hostname))
                if host.hostname == hostname:
                    result = restart_on(host)
                    if not result:
                        to_delete.add(host.id)
        for id_to_delete in to_delete:
            db.session.execute(delete(Supervisors).filter_by(id=id_to_delete))
            db.session.commit()
    else:
        logmessage("restart_this: touching wsgi file")
        wsgi_file = WEBAPP_PATH
        if os.path.isfile(wsgi_file):
            with open(wsgi_file, 'a', encoding='utf-8'):
                os.utime(wsgi_file, None)


def restart_others():
    logmessage("restart_others: starting")
    if USING_SUPERVISOR:
        cron_key = 'da:cron_restart'
        cron_url = None
        to_delete = set()
        for host in db.session.execute(select(Supervisors)).scalars():
            if host.url and host.hostname != hostname and ':cron:' in str(host.role):
                pipe = r.pipeline()
                pipe.set(cron_key, 1)
                pipe.expire(cron_key, 10)
                pipe.execute()
                result = restart_on(host)
                if not result:
                    to_delete.add(host.id)
                while r.get(cron_key) is not None:
                    time.sleep(1)
                cron_url = host.url
        for host in db.session.execute(select(Supervisors)).scalars():
            if host.url and host.url != cron_url and host.hostname != hostname and host.id not in to_delete:
                result = restart_on(host)
                if not result:
                    to_delete.add(host.id)
        for id_to_delete in to_delete:
            db.session.execute(delete(Supervisors).filter_by(id=id_to_delete))
            db.session.commit()


def restart_all():
    logmessage("restarting all")
    for interview_path in [x.decode() for x in r.keys('da:interviewsource:*')]:
        r.delete(interview_path)
    restart_others()
    restart_this()


def get_current_project():
    current_project = request.args.get('project', None)
    if current_project is not None:
        current_project = werkzeug.utils.secure_filename(current_project)
    key = 'da:playground:project:' + str(current_user.id)
    if current_project is None:
        current_project = r.get(key)
        if current_project is not None:
            current_project = current_project.decode()
    else:
        pipe = r.pipeline()
        pipe.set(key, current_project)
        pipe.expire(key, 2592000)
        pipe.execute()
    if current_project is None:
        return 'default'
    return current_project


def name_of_user(user, include_email=False):
    output = ''
    if user.first_name:
        output += user.first_name
        if user.last_name:
            output += ' '
    if user.last_name:
        output += user.last_name
    if include_email and user.email:
        if output:
            output += ', '
        output += user.email
    return output


def true_or_false(text):
    if text in (False, None) or text == 0 or str(text).lower().strip() in ('0', 'false', 'f'):
        return False
    return True


def jsonify_restart_task():
    while True:
        code = random_string(24)
        the_key = 'da:restart_status:' + code
        if r.get(the_key) is None:
            break
    pipe = r.pipeline()
    pipe.set(the_key, json.dumps({'server_start_time': START_TIME}))
    pipe.expire(the_key, 3600)
    pipe.execute()
    return jsonify({'task_id': code})


def jsonify_with_status(data, code):
    resp = jsonify(data)
    resp.status_code = code
    return resp


def variables_js(form=None, office_mode=False):
    output = """
function activatePopovers(){
  var daPopoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
  var daPopoverList = daPopoverTriggerList.map(function (daPopoverTriggerEl) {
    return new bootstrap.Popover(daPopoverTriggerEl, {trigger: "focus", html: true});
  });
}

function activateVariables(){
  $(".daparenthetical").on("click", function(event){
    var reference = $(this).data("ref");
    //console.log("reference is " + reference);
    var target = $('[data-name="' + reference + '"]').first();
    if (target.length > 0){
      //console.log("target is " + target);
      //console.log("scrolltop is now " + $('#daplaygroundcard').scrollTop());
      //console.log("Scrolling to " + target.parent().parent().position().top);
      $('#daplaygroundcard').animate({
          scrollTop: target.parent().parent().position().top
      }, 1000);
    }
    event.preventDefault();
  });

  $(".dashowmethods").on("click", function(event){
    var target_id = $(this).data("showhide");
    $("#" + target_id).slideToggle();
  });

  $(".dashowattributes").each(function(){
    var basename = $(this).data('name');
    if (attrs_showing.hasOwnProperty(basename)){
      if (attrs_showing[basename]){
        $('tr[data-parent="' + basename + '"]').show();
      }
    }
    else{
      attrs_showing[basename] = false;
    }
  });

  $(".dashowattributes").on("click", function(event){
    var basename = $(this).data('name');
    attrs_showing[basename] = !attrs_showing[basename];
    $('tr[data-parent="' + basename + '"]').each(function(){
      $(this).toggle();
    });
  });"""
    if office_mode:
        return output + "\n}"
    if form is None:
        form = 'form'
    output += """
  $(".playground-variable").on("click", function(event){
    daCodeMirror.replaceSelection($(this).data("insert"), "around");
    daCodeMirror.focus();
  });

  $(".dasearchicon").on("click", function(event){
    var query = $(this).data('name');
    if (query == null || query.length == 0){
      clear_matches();
      daCodeMirror.setCursor(daCodeMirror.getCursor('from'));
      return;
    }
    origPosition = daCodeMirror.getCursor('to');
    $("#""" + form + """ input[name='search_term']").val(query);
    var sc = daCodeMirror.getSearchCursor(query, origPosition);
    show_matches(query);
    var found = sc.findNext();
    if (found){
      daCodeMirror.setSelection(sc.from(), sc.to());
      scroll_to_selection();
      $("#form input[name='search_term']").removeClass('da-search-error');
    }
    else{
      origPosition = { line: 0, ch: 0, xRel: 1 }
      sc = daCodeMirror.getSearchCursor(query, origPosition);
      show_matches(query);
      var found = sc.findNext();
      if (found){
        daCodeMirror.setSelection(sc.from(), sc.to());
        scroll_to_selection();
        $("#""" + form + """ input[name='search_term']").removeClass('da-search-error');
      }
      else{
        $("#""" + form + """ input[name='search_term']").addClass('da-search-error');
      }
    }
    event.preventDefault();
    return false;
  });
}

var interviewBaseUrl = '""" + url_for('index.index', reset='1', cache='0',
                                      i='docassemble.playground' + str(current_user.id) + ':.yml') + """';
var shareBaseUrl = '""" + url_for('index.index', i='docassemble.playground' + str(current_user.id) + ':.yml') + """';

function updateRunLink(){
  if (currentProject == 'default'){
    $("#daRunButton").attr("href", interviewBaseUrl.replace('%3A.yml', ':' + $("#daVariables").val()));
    $("a.da-example-share").attr("href", shareBaseUrl.replace('%3A.yml', ':' + $("#daVariables").val()));
  }
  else{
    $("#daRunButton").attr("href", interviewBaseUrl.replace('%3A.yml', currentProject + ':' + $("#daVariables").val()));
    $("a.da-example-share").attr("href", shareBaseUrl.replace('%3A.yml', currentProject + ':' + $("#daVariables").val()));
  }
}

function fetchVars(changed){
  daCodeMirror.save();
  updateRunLink();
  $.ajax({
    type: "POST",
    url: """ + '"' + url_for('playground.playground_variables') + '"' + """ + '?project=' + currentProject,
    data: 'csrf_token=' + $("#""" + form + """ input[name='csrf_token']").val() + '&variablefile=' + $("#daVariables").val() + '&ajax=1&changed=' + (changed ? 1 : 0),
    success: function(data){
      if (data.action && data.action == 'reload'){
        location.reload(true);
      }
      if (data.vocab_list != null){
        vocab = data.vocab_list;
      }
      if (data.current_project != null){
        currentProject = data.current_project;
      }
      if (data.variables_html != null){
        $("#daplaygroundtable").html(data.variables_html);
        var daPopoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        var daPopoverList = daPopoverTriggerList.map(function (daPopoverTriggerEl) {
          return new bootstrap.Popover(daPopoverTriggerEl, {trigger: "focus", html: true});
        });
        activateVariables();
      }
    },
    dataType: 'json'
  });
  $("#daVariables").blur();
}

function variablesReady(){
  $("#daVariables").change(function(event){
    fetchVars(true);
  });
}

$( document ).ready(function() {
  $(document).on('keydown', function(e){
    if (e.which == 13){
      var tag = $( document.activeElement ).prop("tagName");
      if (tag == "INPUT"){
        e.preventDefault();
        e.stopPropagation();
        $(".CodeMirror textarea").focus();
        return false;
      }
    }
  });
});
"""
    return output


def ensure_ml_file_exists(interview, yaml_file, current_project):
    if len(interview.mlfields) > 0:
        if hasattr(interview, 'ml_store'):
            parts = interview.ml_store.split(':')
            if parts[0] != 'docassemble.playground' + str(current_user.id) + current_project:
                return
            source_filename = re.sub(r'.*/', '', parts[1])
        else:
            source_filename = 'ml-' + re.sub(r'\.ya?ml$', '', yaml_file) + '.json'
        # logmessage("Source filename is " + source_filename)
        source_dir = SavedFile(current_user.id, fix=False, section='playgroundsources')
        source_directory = directory_for(source_dir, current_project)
        if current_project != 'default':
            source_filename = os.path.join(current_project, source_filename)
        if source_filename not in source_dir.list_of_files():
            # logmessage("Source filename does not exist yet")
            source_dir.fix()
            source_path = os.path.join(source_directory, source_filename)
            with open(source_path, 'a', encoding='utf-8'):
                os.utime(source_path, None)
            source_dir.finalize()


def find_needed_names(interview, needed_names, the_name=None, the_question=None):
    if the_name is not None:
        needed_names.add(the_name)
        if the_name in interview.questions:
            for lang in interview.questions[the_name]:
                for question in interview.questions[the_name][lang]:
                    find_needed_names(interview, needed_names, the_question=question)
    elif the_question is not None:
        for the_set in (the_question.mako_names, the_question.names_used):
            for name in the_set:
                if name in needed_names:
                    continue
                find_needed_names(interview, needed_names, the_name=name)
    else:
        for question in interview.questions_list:
            # if not (question.is_mandatory or question.is_initial):
            #    continue
            find_needed_names(interview, needed_names, the_question=question)


def noquotetrunc(string):
    string = noquote(string)
    if string is not None:
        try:
            str('') + string
        except:
            string = ''
        if len(string) > 163:
            string = string[:160] + '...'
    return string


def source_code_url(the_name, datatype=None):
    if datatype == 'module':
        try:
            if (not hasattr(the_name, '__path__')) or (not the_name.__path__):
                # logmessage("Nothing for module " + the_name)
                return None
            source_file = re.sub(r'\.pyc$', r'.py', the_name.__path__[0])
            line_number = 1
        except:
            return None
    elif datatype == 'class':
        try:
            source_file = inspect.getsourcefile(the_name)
            line_number = inspect.findsource(the_name)[1]
        except:
            return None
    elif hasattr(the_name, '__code__'):
        source_file = the_name.__code__.co_filename
        line_number = the_name.__code__.co_firstlineno
    else:
        return None
    source_file = re.sub(r'.*/site-packages/', '', source_file)
    m = re.search(r'^docassemble/(base|webapp|demo)/', source_file)
    if m:
        output = 'https://github.com/jhpyle/docassemble/blob/master/docassemble_' + m.group(1) + '/' + source_file
        if line_number == 1:
            return output
        return output + '#L' + str(line_number)
    return None


def public_method(method, the_class):
    if isinstance(method, the_method_type) and method.__name__ != 'init' and not method.__name__.startswith(
            '_') and method.__name__ in the_class.__dict__:
        return True
    return False


def get_ml_info(varname, default_package, default_file):
    parts = varname.split(':')
    if len(parts) == 3 and parts[0].startswith('docassemble.') and re.match(r'data/sources/.*\.json', parts[1]):
        the_package = parts[0]
        the_file = parts[1]
        the_varname = parts[2]
    elif len(parts) == 2 and parts[0] == 'global':
        the_package = '_global'
        the_file = '_global'
        the_varname = parts[1]
    elif len(parts) == 2 and (re.match(r'data/sources/.*\.json', parts[0]) or re.match(r'[^/]+\.json', parts[0])):
        the_package = default_package
        the_file = re.sub(r'^data/sources/', '', parts[0])
        the_varname = parts[1]
    elif len(parts) != 1:
        the_package = '_global'
        the_file = '_global'
        the_varname = varname
    else:
        the_package = default_package
        the_file = default_file
        the_varname = varname
    return (the_package, the_file, the_varname)


def infobutton(title):
    docstring = ''
    if 'doc' in title_documentation[title]:
        docstring += noquote(title_documentation[title]['doc'])
    if 'url' in title_documentation[title]:
        docstring += "<br><a target='_blank' href='" + title_documentation[title]['url'] + "'>" + word(
            "View documentation") + "</a>"
    return '&nbsp;<a tabindex="0" role="button" class="daquestionsign" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + docstring + '" title="' + noquote(
        title_documentation[title].get('title', title)) + '"><i class="fas fa-question-circle"></i></a>'


def search_button(var, field_origins, name_origins, interview_source, all_sources):
    in_this_file = False
    usage = {}
    if var in field_origins:
        for x in sorted(field_origins[var]):
            if x is interview_source:
                in_this_file = True
            else:
                if x.path not in usage:
                    usage[x.path] = set()
                usage[x.path].add('defined')
                all_sources.add(x)
    if var in name_origins:
        for x in sorted(name_origins[var]):
            if x is interview_source:
                in_this_file = True
            else:
                if x.path not in usage:
                    usage[x.path] = set()
                usage[x.path].add('used')
                all_sources.add(x)
    usage_type = [set(), set(), set()]
    for path, the_set in usage.items():
        if 'defined' in the_set and 'used' in the_set:
            usage_type[2].add(path)
        elif 'used' in the_set:
            usage_type[1].add(path)
        elif 'defined' in the_set:
            usage_type[0].add(path)
        else:
            continue
    messages = []
    if len(usage_type[2]) > 0:
        messages.append(word("Defined and used in " + docassemble.base.functions.comma_and_list(sorted(usage_type[2]))))
    elif len(usage_type[0]) > 0:
        messages.append(word("Defined in") + ' ' + docassemble.base.functions.comma_and_list(sorted(usage_type[0])))
    elif len(usage_type[2]) > 0:
        messages.append(word("Used in") + ' ' + docassemble.base.functions.comma_and_list(sorted(usage_type[0])))
    if len(messages) > 0:
        title = 'title="' + '; '.join(messages) + '" '
    else:
        title = ''
    if in_this_file:
        classname = 'dasearchthis'
    else:
        classname = 'dasearchother'
    return '<a tabindex="0" class="dasearchicon ' + classname + '" ' + title + 'data-name="' + noquote(
        var) + '"><i class="fas fa-search"></i></a>'


pg_code_cache = {}
search_key = """
                  <tr><td><h4>""" + word("Note") + """</h4></td></tr>
                  <tr><td><a tabindex="0" class="dasearchicon dasearchthis"><i class="fas fa-search"></i></a> """ + word(
    "means the name is located in this file") + """</td></tr>
                  <tr><td><a tabindex="0" class="dasearchicon dasearchother"><i class="fas fa-search"></i></a> """ + word(
    "means the name may be located in a file included by reference, such as:") + """</td></tr>"""


def get_vars_in_use(interview, interview_status, debug_mode=False, return_json=False, show_messages=True,
                    show_jinja_help=False, current_project='default', use_playground=True):
    user_dict = fresh_dictionary()
    if debug_mode:
        has_error = True
        error_message = "Not checking variables because in debug mode."
        error_type = Exception
    else:
        if not interview.success:
            has_error = True
            error_type = DAErrorCompileError
        else:
            old_language = docassemble.base.functions.get_language()
            try:
                interview.assemble(user_dict, interview_status)
                has_error = False
            except Exception as errmess:
                has_error = True
                error_message = str(errmess)
                error_type = type(errmess)
                logmessage("get_vars_in_use: failed assembly with error type " + str(
                    error_type) + " and message: " + error_message)
            docassemble.base.functions.set_language(old_language)
    fields_used = set()
    names_used = set()
    field_origins = {}
    name_origins = {}
    all_sources = set()
    names_used.update(interview.names_used)
    for question in interview.questions_list:
        for the_set in (question.mako_names, question.names_used, question.fields_used):
            names_used.update(the_set)
            for key in the_set:
                if key not in name_origins:
                    name_origins[key] = set()
                name_origins[key].add(question.from_source)
        fields_used.update(question.fields_used)
        for key in question.fields_used:
            if key not in field_origins:
                field_origins[key] = set()
            field_origins[key].add(question.from_source)
    for val in interview.questions:
        names_used.add(val)
        if val not in name_origins:
            name_origins[val] = set()
        for lang in interview.questions[val]:
            for q in interview.questions[val][lang]:
                name_origins[val].add(q.from_source)
        fields_used.add(val)
        if val not in field_origins:
            field_origins[val] = set()
        for lang in interview.questions[val]:
            for q in interview.questions[val][lang]:
                field_origins[val].add(q.from_source)
    needed_names = set()
    find_needed_names(interview, needed_names)
    functions = set()
    modules = set()
    classes = set()
    name_info = copy.deepcopy(base_name_info)
    if use_playground:
        area = SavedFile(current_user.id, fix=True, section='playgroundtemplate')
        the_directory = directory_for(area, current_project)
        templates = sorted([f for f in os.listdir(the_directory) if
                            os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        area = SavedFile(current_user.id, fix=True, section='playgroundstatic')
        the_directory = directory_for(area, current_project)
        static = sorted([f for f in os.listdir(the_directory) if
                         os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        area = SavedFile(current_user.id, fix=True, section='playgroundsources')
        the_directory = directory_for(area, current_project)
        sources = sorted([f for f in os.listdir(the_directory) if
                          os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        area = SavedFile(current_user.id, fix=True, section='playgroundmodules')
        the_directory = directory_for(area, current_project)
        avail_modules = sorted([re.sub(r'.py$', '', f) for f in os.listdir(the_directory) if
                                os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    else:
        templates = []
        static = []
        sources = []
        avail_modules = []
    for val in user_dict:
        if isinstance(user_dict[val], types.FunctionType):
            if val not in pg_code_cache:
                try:
                    pg_code_cache[val] = {'doc': noquotetrunc(inspect.getdoc(user_dict[val])), 'name': str(val),
                                          'insert': str(val) + '()',
                                          'tag': str(val) + str(inspect.signature(user_dict[val])),
                                          'git': source_code_url(user_dict[val])}
                except:
                    pg_code_cache[val] = {'doc': '', 'name': str(val), 'insert': str(val) + '()',
                                          'tag': str(val) + '()', 'git': source_code_url(user_dict[val])}
            name_info[val] = copy.copy(pg_code_cache[val])
            if 'tag' in name_info[val]:
                functions.add(val)
        elif isinstance(user_dict[val], types.ModuleType):
            if val not in pg_code_cache:
                try:
                    pg_code_cache[val] = {'doc': noquotetrunc(inspect.getdoc(user_dict[val])), 'name': str(val),
                                          'insert': str(val), 'git': source_code_url(user_dict[val], datatype='module')}
                except:
                    pg_code_cache[val] = {'doc': '', 'name': str(val), 'insert': str(val),
                                          'git': source_code_url(user_dict[val], datatype='module')}
            name_info[val] = copy.copy(pg_code_cache[val])
            modules.add(val)
        elif isinstance(user_dict[val], TypeType):
            if val not in pg_code_cache:
                bases = []
                for x in list(user_dict[val].__bases__):
                    if x.__name__ != 'DAObject':
                        bases.append(x.__name__)
                try:
                    methods = inspect.getmembers(user_dict[val], predicate=lambda x: public_method(x, user_dict[val]))
                except:
                    methods = []
                method_list = []
                for name, value in methods:
                    try:
                        method_list.append({'insert': '.' + str(name) + '()', 'name': str(name),
                                            'doc': noquotetrunc(inspect.getdoc(value)),
                                            'tag': '.' + str(name) + str(inspect.signature(value)),
                                            'git': source_code_url(value)})
                    except:
                        method_list.append({'insert': '.' + str(name) + '()', 'name': str(name), 'doc': '',
                                            'tag': '.' + str(name) + '()', 'git': source_code_url(value)})
                try:
                    pg_code_cache[val] = {'doc': noquotetrunc(inspect.getdoc(user_dict[val])), 'name': str(val),
                                          'insert': str(val), 'bases': bases, 'methods': method_list,
                                          'git': source_code_url(user_dict[val], datatype='class')}
                except:
                    pg_code_cache[val] = {'doc': '', 'name': str(val), 'insert': str(val), 'bases': bases,
                                          'methods': method_list,
                                          'git': source_code_url(user_dict[val], datatype='class')}
            name_info[val] = copy.copy(pg_code_cache[val])
            if 'methods' in name_info[val]:
                classes.add(val)
    for val in docassemble.base.functions.pickleable_objects(user_dict):
        names_used.add(val)
        if val not in name_info:
            name_info[val] = {}
        name_info[val]['type'] = user_dict[val].__class__.__name__
        name_info[val]['iterable'] = bool(hasattr(user_dict[val], '__iter__') and not isinstance(user_dict[val], str))
    for var in base_name_info:
        if base_name_info[var]['show']:
            names_used.add(var)
    names_used = set(i for i in names_used if not extraneous_var.search(i))
    for var in ('_internal', '__object_type', '_DAOBJECTDEFAULTDA'):
        names_used.discard(var)
    for var in interview.mlfields:
        names_used.discard(var + '.text')
    if len(interview.mlfields) > 0:
        classes.add('DAModel')
        method_list = [{'insert': '.predict()', 'name': 'predict',
                        'doc': "Generates a prediction based on the 'text' attribute and sets the attributes 'entry_id,' 'predictions,' 'prediction,' and 'probability.'  Called automatically.",
                        'tag': '.predict(self)'}]
        name_info['DAModel'] = {'doc': 'Applies natural language processing to user input and returns a prediction.',
                                'name': 'DAModel', 'insert': 'DAModel', 'bases': [], 'methods': method_list}
    view_doc_text = word("View documentation")
    word_documentation = word("Documentation")
    attr_documentation = word("Show attributes")
    ml_parts = interview.get_ml_store().split(':')
    if len(ml_parts) == 2:
        ml_parts[1] = re.sub(r'^data/sources/ml-|\.json$', '', ml_parts[1])
    else:
        ml_parts = ['_global', '_global']
    for var in documentation_dict:
        if var not in name_info:
            name_info[var] = {}
        if 'doc' in name_info[var] and name_info[var]['doc'] is not None:
            name_info[var]['doc'] += '<br>'
        else:
            name_info[var]['doc'] = ''
        name_info[var]['doc'] += "<a target='_blank' href='" + DOCUMENTATION_BASE + documentation_dict[
            var] + "'>" + view_doc_text + "</a>"
    for var in name_info:
        if 'methods' in name_info[var]:
            for method in name_info[var]['methods']:
                if var + '.' + method['name'] in documentation_dict:
                    if method['doc'] is None:
                        method['doc'] = ''
                    else:
                        method['doc'] += '<br>'
                    if view_doc_text not in method['doc']:
                        method['doc'] += "<a target='_blank' href='" + DOCUMENTATION_BASE + documentation_dict[
                            var + '.' + method['name']] + "'>" + view_doc_text + "</a>"
    content = ''
    if has_error and show_messages:
        error_style = 'danger'
        if error_type is DAErrorNoEndpoint:
            error_style = 'warning'
            message_to_use = title_documentation['incomplete']['doc']
        elif error_type is DAErrorCompileError:
            message_to_use = title_documentation['compilefail']['doc']
        elif error_type is DAErrorMissingVariable:
            message_to_use = error_message
        else:
            message_to_use = title_documentation['generic error']['doc']
        content += '\n                  <tr><td class="playground-warning-box"><div class="alert alert-' + error_style + '">' + message_to_use + '</div></td></tr>'
    vocab_dict = {}
    vocab_set = (names_used | functions | classes | modules | fields_used | set(
        key for key in base_name_info if not re.search(r'\.', key)) | set(
        key for key in name_info if not re.search(r'\.', key)) | set(templates) | set(static) | set(sources) | set(
        avail_modules) | set(interview.images.keys()))
    vocab_set = set(i for i in vocab_set if not extraneous_var.search(i))
    names_used = names_used.difference(functions | classes | modules | set(avail_modules))
    undefined_names = names_used.difference(
        fields_used | set(base_name_info.keys()) | set(x for x in names_used if '.' in x))
    implicitly_defined = set()
    for var in fields_used:
        the_var = var
        while '.' in the_var:
            the_var = re.sub(r'(.*)\..*$', r'\1', the_var)
            implicitly_defined.add(the_var)
    for var in ('_internal', '__object_type', '_DAOBJECTDEFAULTDA'):
        undefined_names.discard(var)
        vocab_set.discard(var)
    for var in [x for x in undefined_names if x.endswith(']')]:
        undefined_names.discard(var)
    for var in (functions | classes | modules):
        undefined_names.discard(var)
    for var in user_dict:
        undefined_names.discard(var)
    names_used = names_used.difference(undefined_names)
    if return_json:
        if len(names_used) > 0:
            has_parent = {}
            has_children = set()
            for var in names_used:
                parent = re.sub(r'[\.\[].*', '', var)
                if parent != var:
                    has_parent[var] = parent
                    has_children.add(parent)
            var_list = []
            for var in sorted(names_used):
                var_trans = re.sub(r'\[[0-9]+\]', '[i]', var)
                # var_trans = re.sub(r'\[i\](.*)\[i\](.*)\[i\](.*)\[i\](.*)\[i\](.*)\[i\]', r'[i]\1[j]\2[k]\3[l]\4[m]\5[n]', var_trans)
                # var_trans = re.sub(r'\[i\](.*)\[i\](.*)\[i\](.*)\[i\](.*)\[i\]', r'[i]\1[j]\2[k]\3[l]\4[m]', var_trans)
                # var_trans = re.sub(r'\[i\](.*)\[i\](.*)\[i\](.*)\[i\]', r'[i]\1[j]\2[k]\3[l]', var_trans)
                var_trans = re.sub(r'\[i\](.*)\[i\](.*)\[i\]', r'[i]\1[j]\2[k]', var_trans)
                var_trans = re.sub(r'\[i\](.*)\[i\]', r'[i]\1[j]', var_trans)
                info = dict(var=var, to_insert=var)
                if var_trans != var:
                    info['var_base'] = var_trans
                info['hide'] = bool(var in has_parent)
                if var in base_name_info:
                    if not base_name_info[var]['show']:
                        continue
                if var in documentation_dict or var in base_name_info:
                    info['var_type'] = 'builtin'
                elif var not in fields_used and var not in implicitly_defined and var_trans not in fields_used and var_trans not in implicitly_defined:
                    info['var_type'] = 'not_used'
                elif var not in needed_names:
                    info['var_type'] = 'possibly_not_used'
                else:
                    info['var_type'] = 'default'
                if var in name_info and 'type' in name_info[var] and name_info[var]['type']:
                    info['class_name'] = name_info[var]['type']
                elif var in interview.mlfields:
                    info['class_name'] = 'DAModel'
                if var in name_info and 'iterable' in name_info[var]:
                    info['iterable'] = name_info[var]['iterable']
                if var in name_info and 'doc' in name_info[var] and name_info[var]['doc']:
                    info['doc_content'] = name_info[var]['doc']
                    info['doc_title'] = word_documentation
                if var in interview.mlfields:
                    if 'ml_group' in interview.mlfields[var] and not interview.mlfields[var]['ml_group'].uses_mako:
                        (ml_package, ml_file, ml_group_id) = get_ml_info(
                            interview.mlfields[var]['ml_group'].original_text, ml_parts[0], ml_parts[1])
                        info['train_link'] = url_for('train', package=ml_package, file=ml_file, group_id=ml_group_id)
                    else:
                        info['train_link'] = url_for('train', package=ml_parts[0], file=ml_parts[1], group_id=var)
                var_list.append(info)
        functions_list = []
        if len(functions) > 0:
            for var in sorted(functions):
                info = dict(var=var, to_insert=name_info[var]['insert'], name=name_info[var]['tag'])
                if 'doc' in name_info[var] and name_info[var]['doc']:
                    info['doc_content'] = name_info[var]['doc']
                    info['doc_title'] = word_documentation
                functions_list.append(info)
        classes_list = []
        if len(classes) > 0:
            for var in sorted(classes):
                info = dict(var=var, to_insert=name_info[var]['insert'], name=name_info[var]['name'])
                if name_info[var]['bases']:
                    info['bases'] = name_info[var]['bases']
                if 'doc' in name_info[var] and name_info[var]['doc']:
                    info['doc_content'] = name_info[var]['doc']
                    info['doc_title'] = word_documentation
                if 'methods' in name_info[var] and len(name_info[var]['methods']):
                    info['methods'] = []
                    for method_item in name_info[var]['methods']:
                        method_info = dict(name=method_item['name'], to_insert=method_item['insert'],
                                           tag=method_item['tag'])
                        if 'git' in method_item:
                            method_info['git'] = method_item['git']
                        if method_item['doc']:
                            method_info['doc_content'] = method_item['doc']
                            method_info['doc_title'] = word_documentation
                        info['methods'].append(method_info)
                classes_list.append(info)
        modules_list = []
        if len(modules) > 0:
            for var in sorted(modules):
                info = dict(var=var, to_insert=name_info[var]['insert'])
                if name_info[var]['doc']:
                    info['doc_content'] = name_info[var]['doc']
                    info['doc_title'] = word_documentation
                modules_list.append(info)
        if use_playground:
            modules_available_list = []
            if len(avail_modules) > 0:
                for var in sorted(avail_modules):
                    info = dict(var=var, to_insert="." + var)
                    modules_available_list.append(info)
            templates_list = []
            if len(templates) > 0:
                for var in sorted(templates):
                    info = dict(var=var, to_insert=var)
                    templates_list.append(info)
            sources_list = []
            if len(sources) > 0:
                for var in sorted(sources):
                    info = dict(var=var, to_insert=var)
                    sources_list.append(info)
            static_list = []
            if len(static) > 0:
                for var in sorted(static):
                    info = dict(var=var, to_insert=var)
                    static_list.append(info)
        images_list = []
        if len(interview.images) > 0:
            for var in sorted(interview.images):
                info = dict(var=var, to_insert=var)
                the_ref = get_url_from_file_reference(interview.images[var].get_reference())
                if the_ref:
                    info['url'] = the_ref
                images_list.append(info)
        if use_playground:
            return dict(undefined_names=list(sorted(undefined_names)), var_list=var_list, functions_list=functions_list,
                        classes_list=classes_list, modules_list=modules_list,
                        modules_available_list=modules_available_list, templates_list=templates_list,
                        sources_list=sources_list, images_list=images_list, static_list=static_list), sorted(vocab_set)
        return dict(undefined_names=list(sorted(undefined_names)), var_list=var_list, functions_list=functions_list,
                    classes_list=classes_list, modules_list=modules_list, images_list=images_list), sorted(vocab_set)
    if len(undefined_names) > 0:
        content += '\n                  <tr><td><h4>' + word('Undefined names') + infobutton(
            'undefined') + '</h4></td></tr>'
        for var in sorted(undefined_names):
            content += '\n                  <tr><td>' + search_button(var, field_origins, name_origins,
                                                                      interview.source,
                                                                      all_sources) + '<a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                var) + '" class="btn btn-danger btn-sm playground-variable">' + var + '</a></td></tr>'
            vocab_dict[var] = var
    if len(names_used) > 0:
        content += '\n                  <tr><td><h4>' + word('Variables') + infobutton('variables') + '</h4></td></tr>'
        has_parent = {}
        has_children = set()
        for var in names_used:
            parent = re.sub(r'[\.\[].*', '', var)
            if parent != var:
                has_parent[var] = parent
                has_children.add(parent)
        for var in sorted(names_used):
            var_trans = re.sub(r'\[[0-9]\]', '[i]', var)
            var_trans = re.sub(r'\[i\](.*)\[i\](.*)\[i\]', r'[i]\1[j]\2[k]', var_trans)
            var_trans = re.sub(r'\[i\](.*)\[i\]', r'[i]\1[j]', var_trans)
            if var in has_parent:
                hide_it = ' style="display: none" data-parent="' + noquote(has_parent[var]) + '"'
            else:
                hide_it = ''
            if var in base_name_info:
                if not base_name_info[var]['show']:
                    continue
            if var in documentation_dict or var in base_name_info:
                class_type = 'btn-info'
                title = 'title=' + json.dumps(word("Special variable")) + ' '
            elif var not in fields_used and var not in implicitly_defined and var_trans not in fields_used and var_trans not in implicitly_defined:
                class_type = 'btn-secondary'
                title = 'title=' + json.dumps(word("Possibly not defined")) + ' '
            elif var not in needed_names:
                class_type = 'btn-warning'
                title = 'title=' + json.dumps(word("Possibly not used")) + ' '
            else:
                class_type = 'btn-primary'
                title = ''
            content += '\n                  <tr' + hide_it + '><td>' + search_button(var, field_origins, name_origins,
                                                                                     interview.source,
                                                                                     all_sources) + '<a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                var) + '" ' + title + 'class="btn btn-sm ' + class_type + ' playground-variable">' + var + '</a>'
            vocab_dict[var] = var
            if var in has_children:
                content += '&nbsp;<a tabindex="0" class="dashowattributes" role="button" data-name="' + noquote(
                    var) + '" title=' + json.dumps(attr_documentation) + '><i class="fas fa-ellipsis-h"></i></a>'
            if var in name_info and 'type' in name_info[var] and name_info[var]['type']:
                content += '&nbsp;<span data-ref="' + noquote(name_info[var]['type']) + '" class="daparenthetical">(' + \
                           name_info[var]['type'] + ')</span>'
            elif var in interview.mlfields:
                content += '&nbsp;<span data-ref="DAModel" class="daparenthetical">(DAModel)</span>'
            if var in name_info and 'doc' in name_info[var] and name_info[var]['doc']:
                if 'git' in name_info[var] and name_info[var]['git']:
                    git_link = noquote("<a class='float-end' target='_blank' href='" + name_info[var][
                        'git'] + "'><i class='fas fa-code'></i></a>")
                else:
                    git_link = ''
                content += '&nbsp;<a tabindex="0" class="dainfosign" role="button" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + \
                           name_info[var][
                               'doc'] + '"  title="' + var + git_link + '"><i class="fas fa-info-circle"></i></a>'  # data-bs-selector="true" title=' + json.dumps(word_documentation) + '
            if var in interview.mlfields:
                if 'ml_group' in interview.mlfields[var] and not interview.mlfields[var]['ml_group'].uses_mako:
                    (ml_package, ml_file, ml_group_id) = get_ml_info(interview.mlfields[var]['ml_group'].original_text,
                                                                     ml_parts[0], ml_parts[1])
                    content += '&nbsp;<a class="datrain" target="_blank" href="' + url_for('train', package=ml_package,
                                                                                           file=ml_file,
                                                                                           group_id=ml_group_id) + '" title=' + json.dumps(
                        word("Train")) + '><i class="fas fa-graduation-cap"></i></a>'
                else:
                    content += '&nbsp;<a class="datrain" target="_blank" href="' + url_for('train', package=ml_parts[0],
                                                                                           file=ml_parts[1],
                                                                                           group_id=var) + '" title=' + json.dumps(
                        word("Train")) + '><i class="fas fa-graduation-cap"></i></a>'
            content += '</td></tr>'
        if len(all_sources) > 0 and show_messages:
            content += search_key
            content += '\n                <tr><td>'
            content += '\n                  <ul>'
            for path in sorted([x.path for x in all_sources]):
                content += '\n                    <li><a target="_blank" href="' + url_for('view_source', i=path,
                                                                                           project=current_project) + '">' + path + '<a></li>'
            content += '\n                  </ul>'
            content += '\n                </td></tr>'
    if len(functions) > 0:
        content += '\n                  <tr><td><h4>' + word('Functions') + infobutton('functions') + '</h4></td></tr>'
        for var in sorted(functions):
            if var in name_info:
                content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                    var) + '" data-insert="' + noquote(
                    name_info[var]['insert']) + '" class="btn btn-sm btn-warning playground-variable">' + \
                           name_info[var]['tag'] + '</a>'
            vocab_dict[var] = name_info[var]['insert']
            if var in name_info and 'doc' in name_info[var] and name_info[var]['doc']:
                if 'git' in name_info[var] and name_info[var]['git']:
                    git_link = noquote("<a class='float-end' target='_blank' href='" + name_info[var][
                        'git'] + "'><i class='fas fa-code'></i></a>")
                else:
                    git_link = ''
                content += '&nbsp;<a tabindex="0" class="dainfosign" role="button" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + \
                           name_info[var][
                               'doc'] + '" title="' + var + git_link + '"><i class="fas fa-info-circle"></i></a>'  # data-bs-selector="true" title=' + json.dumps(word_documentation) + '
            content += '</td></tr>'
    if len(classes) > 0:
        content += '\n                  <tr><td><h4>' + word('Classes') + infobutton('classes') + '</h4></td></tr>'
        for var in sorted(classes):
            content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                name_info[var]['insert']) + '" class="btn btn-sm btn-info playground-variable">' + name_info[var][
                           'name'] + '</a>'
            vocab_dict[var] = name_info[var]['insert']
            if name_info[var]['bases']:
                content += '&nbsp;<span data-ref="' + noquote(
                    name_info[var]['bases'][0]) + '" class="daparenthetical">(' + name_info[var]['bases'][
                               0] + ')</span>'
            if name_info[var]['doc']:
                if 'git' in name_info[var] and name_info[var]['git']:
                    git_link = noquote("<a class='float-end' target='_blank' href='" + name_info[var][
                        'git'] + "'><i class='fas fa-code'></i></a>")
                else:
                    git_link = ''
                content += '&nbsp;<a tabindex="0" class="dainfosign" role="button" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + \
                           name_info[var][
                               'doc'] + '" title="' + var + git_link + '"><i class="fas fa-info-circle"></i></a>'  # data-bs-selector="true" title=' + json.dumps(word_documentation) + '
            if len(name_info[var]['methods']) > 0:
                content += '&nbsp;<a tabindex="0" class="dashowmethods" role="button" data-showhide="XMETHODX' + var + '" title=' + json.dumps(
                    word('Methods')) + '><i class="fas fa-cog"></i></a>'
                content += '<div style="display: none;" id="XMETHODX' + var + '"><table><tbody>'
                for method_info in name_info[var]['methods']:
                    if 'git' in method_info and method_info['git']:
                        git_link = noquote("<a class='float-end' target='_blank' href='" + method_info[
                            'git'] + "'><i class='fas fa-code'></i></a>")
                    else:
                        git_link = ''
                    content += '<tr><td><a tabindex="0" role="button" data-name="' + noquote(
                        method_info['name']) + '" data-insert="' + noquote(
                        method_info['insert']) + '" class="btn btn-sm btn-warning playground-variable">' + method_info[
                                   'tag'] + '</a>'
                    # vocab_dict[method_info['name']] = method_info['insert']
                    if method_info['doc']:
                        content += '&nbsp;<a tabindex="0" class="dainfosign" role="button" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + \
                                   method_info['doc'] + '" data-bs-title="' + noquote(method_info[
                                                                                          'name']) + git_link + '"><i class="fas fa-info-circle"></i></a>'  # data-bs-selector="true" title=' + json.dumps(word_documentation) + '
                    content += '</td></tr>'
                content += '</tbody></table></div>'
            content += '</td></tr>'
    if len(modules) > 0:
        content += '\n                  <tr><td><h4>' + word('Modules defined') + infobutton(
            'modules') + '</h4></td></tr>'
        for var in sorted(modules):
            content += '\n                  <tr><td><a tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                name_info[var]['insert']) + '" role="button" class="btn btn-sm btn-success playground-variable">' + \
                       name_info[var]['name'] + '</a>'
            vocab_dict[var] = name_info[var]['insert']
            if name_info[var]['doc']:
                if 'git' in name_info[var] and name_info[var]['git']:
                    git_link = noquote("<a class='float-end' target='_blank' href='" + name_info[var][
                        'git'] + "'><i class='fas fa-code'></i></a>")
                else:
                    git_link = ''
                content += '&nbsp;<a tabindex="0" class="dainfosign" role="button" data-bs-container="body" data-bs-toggle="popover" data-bs-placement="auto" data-bs-content="' + \
                           name_info[var]['doc'] + '" data-bs-title="' + noquote(
                    var) + git_link + '"><i class="fas fa-info-circle"></i></a>'  # data-bs-selector="true" title=' + json.dumps(word_documentation) + '
            content += '</td></tr>'
    if len(avail_modules) > 0:
        content += '\n                  <tr><td><h4>' + word('Modules available in Playground') + infobutton(
            'playground_modules') + '</h4></td></tr>'
        for var in avail_modules:
            content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert=".' + noquote(
                var) + '" class="btn btn-sm btn-success playground-variable">.' + noquote(var) + '</a>'
            vocab_dict[var] = var
            content += '</td></tr>'
    if len(templates) > 0:
        content += '\n                  <tr><td><h4>' + word('Templates') + infobutton('templates') + '</h4></td></tr>'
        for var in templates:
            content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                var) + '" class="btn btn-sm btn-secondary playground-variable">' + noquote(var) + '</a>'
            vocab_dict[var] = var
            content += '</td></tr>'
    if len(static) > 0:
        content += '\n                  <tr><td><h4>' + word('Static files') + infobutton('static') + '</h4></td></tr>'
        for var in static:
            content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                var) + '" class="btn btn-sm btn-secondary playground-variable">' + noquote(var) + '</a>'
            vocab_dict[var] = var
            content += '</td></tr>'
    if len(sources) > 0:
        content += '\n                  <tr><td><h4>' + word('Source files') + infobutton('sources') + '</h4></td></tr>'
        for var in sources:
            content += '\n                  <tr><td><a role="button" tabindex="0" data-name="' + noquote(
                var) + '" data-insert="' + noquote(
                var) + '" class="btn btn-sm btn-secondary playground-variable">' + noquote(var) + '</a>'
            vocab_dict[var] = var
            content += '</td></tr>'
    if len(interview.images) > 0:
        content += '\n                  <tr><td><h4>' + word('Decorations') + infobutton(
            'decorations') + '</h4></td></tr>'
        show_images = not bool(cloud and len(interview.images) > 10)
        for var in sorted(interview.images):
            content += '\n                  <tr><td>'
            the_ref = get_url_from_file_reference(interview.images[var].get_reference())
            if the_ref is None:
                content += '<a role="button" tabindex="0" title=' + json.dumps(
                    word("This image file does not exist")) + ' data-name="' + noquote(
                    var) + '" data-insert="' + noquote(
                    var) + '" class="btn btn-sm btn-danger playground-variable">' + noquote(var) + '</a>'
            else:
                if show_images:
                    content += '<img class="daimageicon" src="' + the_ref + '">&nbsp;'
                content += '<a role="button" tabindex="0" data-name="' + noquote(var) + '" data-insert="' + noquote(
                    var) + '" class="btn btn-sm btn-primary playground-variable">' + noquote(var) + '</a>'
            vocab_dict[var] = var
            content += '</td></tr>'
    if show_messages:
        content += "\n                  <tr><td><br><em>" + word("Type Ctrl-space to autocomplete.") + "</em></td><tr>"
    if show_jinja_help:
        content += "\n                  <tr><td><h4 class=\"mt-2\">" + word("Using Jinja2") + infobutton(
            'jinja2') + "</h4>\n                  " + re.sub("table-striped", "table-bordered",
                                                             docassemble.base.util.markdown_to_html(
                                                                 word("Jinja2 help template"), trim=False,
                                                                 do_terms=False)) + "</td><tr>"
    for item in base_name_info:
        if item not in vocab_dict and not base_name_info.get('exclude', False):
            vocab_dict[item] = base_name_info.get('insert', item)
    return content, sorted(vocab_set), vocab_dict


def summarize_results(results, logmessages, html=True):
    if html:
        output = '<br>'.join([x + ':&nbsp;' + results[x] for x in sorted(results.keys())])
        if len(logmessages) > 0:
            if len(output) > 0:
                output += '<br><br><strong>' + word("pip log") + ':</strong><br>'
            else:
                output = ''
            output += re.sub(r'\n', r'<br>', logmessages)
        return Markup(output)
    output = '\n'.join([x + ': ' + results[x] for x in sorted(results.keys())])
    if len(logmessages) > 0:
        if len(output) > 0:
            output += "\n" + word("pip log") + ':\n'
        else:
            output = ''
        output += logmessages
    return output


def get_gd_flow():
    app_credentials = current_app.config['OAUTH_CREDENTIALS'].get('googledrive', {})
    client_id = app_credentials.get('id', None)
    client_secret = app_credentials.get('secret', None)
    if client_id is None or client_secret is None:
        raise DAError('Google Drive is not configured.')
    flow = oauth2client.client.OAuth2WebServerFlow(
        client_id=client_id,
        client_secret=client_secret,
        scope='https://www.googleapis.com/auth/drive',
        redirect_uri=url_for('util.google_drive_callback', _external=True),
        access_type='offline',
        prompt='consent')
    return flow


def add_br(text):
    return re.sub(r'[\n\r]+', "<br>", text)


def set_od_folder(folder):
    key = 'da:onedrive:mapping:userid:' + str(current_user.id)
    if folder is None:
        r.delete(key)
    else:
        set_gd_folder(None)
        r.set(key, folder)


def set_gd_folder(folder):
    key = 'da:googledrive:mapping:userid:' + str(current_user.id)
    if folder is None:
        r.delete(key)
    else:
        set_od_folder(None)
        r.set(key, folder)


def transform_json_variables(obj):
    if isinstance(obj, str):
        if re.search(r'^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]', obj):
            try:
                return docassemble.base.util.as_datetime(dateutil.parser.parse(obj))
            except:
                pass
        elif re.search(r'^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]', obj):
            try:
                return datetime.time.fromisoformat(obj)
            except:
                pass
        return obj
    if isinstance(obj, (bool, int, float)):
        return obj
    if isinstance(obj, dict):
        if '_class' in obj and obj['_class'] == 'type' and 'name' in obj and isinstance(obj['name'], str) and obj[
            'name'].startswith('docassemble.') and not illegal_variable_name(obj['name']):
            if '.' in obj['name']:
                the_module = re.sub(r'\.[^\.]+$', '', obj['name'])
            else:
                the_module = None
            try:
                if the_module:
                    importlib.import_module(the_module)
                new_obj = eval(obj['name'])
                if not isinstance(the_class, TypeType):
                    raise Exception("name is not a class")
                return new_obj
            except Exception as err:
                logmessage("transform_json_variables: " + err.__class__.__name__ + ": " + str(err))
                return None
        if '_class' in obj and isinstance(obj['_class'], str) and 'instanceName' in obj and obj['_class'].startswith(
                'docassemble.') and not illegal_variable_name(obj['_class']) and isinstance(obj['instanceName'], str):
            the_module = re.sub(r'\.[^\.]+$', '', obj['_class'])
            try:
                importlib.import_module(the_module)
                the_class = eval(obj['_class'])
                if not isinstance(the_class, TypeType):
                    raise Exception("_class was not a class")
                new_obj = the_class(obj['instanceName'])
                for key, val in obj.items():
                    if key == '_class':
                        continue
                    setattr(new_obj, key, transform_json_variables(val))
                return new_obj
            except Exception as err:
                logmessage("transform_json_variables: " + err.__class__.__name__ + ": " + str(err))
                return None
        new_dict = {}
        for key, val in obj.items():
            new_dict[transform_json_variables(key)] = transform_json_variables(val)
        return new_dict
    if isinstance(obj, list):
        return [transform_json_variables(val) for val in obj]
    if isinstance(obj, set):
        return set(transform_json_variables(val) for val in obj)
    return obj


def get_user_info(user_id=None, email=None, case_sensitive=False, admin=False):
    if user_id is not None:
        assert isinstance(user_id, int)
    if user_id is None and email is None:
        user_id = current_user.id
    if email is not None:
        assert isinstance(email, str)
        email = email.strip()
    user_info = dict(privileges=[])
    if user_id is not None:
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    else:
        if case_sensitive:
            user = db.session.execute(
                select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(email=email)).scalar()
        else:
            email = re.sub(r'\%', '', email)
            user = db.session.execute(
                select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.email.ilike(email))).scalar()
    if user is None or user.social_id.startswith('disabled$'):
        return None
    if not admin and not current_user.has_role_or_permission('admin', 'advocate', permissions=[
        'access_user_info']) and not current_user.same_as(user_id):
        raise Exception("You do not have sufficient privileges to access information about other users")
    for role in user.roles:
        user_info['privileges'].append(role.name)
    for attrib in (
            'id', 'email', 'first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond',
            'subdivisionthird',
            'organization', 'timezone', 'language', 'active'):
        user_info[attrib] = getattr(user, attrib)
    user_info['account_type'] = re.sub(r'\$.*', '', user.social_id)
    return user_info


def set_user_info(**kwargs):
    user_id = kwargs.get('user_id', None)
    email = kwargs.get('email', None)
    if user_id is None and email is None:
        user_id = int(current_user.id)
    if not current_user.has_role_or_permission('admin', permissions=['edit_user_info']):
        if (user_id is not None and current_user.id != user_id) or (email is not None and current_user.email != email):
            raise Exception("You do not have sufficient privileges to edit user information")
    if user_id is not None:
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(id=user_id)).scalar()
    else:
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(email=email)).scalar()
    if user is None or user.social_id.startswith('disabled$'):
        raise Exception("User not found")
    editing_self = current_user.same_as(user.id)
    if not current_user.has_role_or_permission('admin'):
        if not editing_self:
            if user.has_role('admin', 'developer', 'advocate', 'cron'):
                raise Exception("You do not have sufficient privileges to edit this user's information.")
            if 'password' in kwargs and not current_user.can_do('edit_user_password'):
                raise Exception("You do not have sufficient privileges to change this user's password.")
        if 'privileges' in kwargs:
            if user.has_role('admin', 'developer', 'advocate', 'cron') or not current_user.can_do(
                    'edit_user_privileges'):
                raise Exception("You do not have sufficient privileges to edit this user's privileges.")
    if 'active' in kwargs:
        if not isinstance(kwargs['active'], bool):
            raise Exception("The active parameter must be True or False")
        if editing_self:
            raise Exception("Cannot change active status of the current user.")
        else:
            if not current_user.has_role_or_permission('admin', permissions=['edit_user_active_status']):
                raise Exception("You do not have sufficient privileges to edit this user's active status.")
    for key, val in kwargs.items():
        if key in ('first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond', 'subdivisionthird',
                   'organization', 'timezone', 'language'):
            setattr(user, key, val)
    if 'password' in kwargs:
        if not editing_self and not current_user.has_role_or_permission('admin', permissions=['edit_user_password']):
            raise Exception("You do not have sufficient privileges to change a user's password.")
        user.user_auth.password = app.user_manager.hash_password(kwargs['password'])
    if 'active' in kwargs:
        user.active = kwargs['active']
    db.session.commit()
    if 'privileges' in kwargs and isinstance(kwargs['privileges'], (list, tuple, set)):
        if len(kwargs['privileges']) == 0:
            raise Exception("Cannot remove all of a user's privileges.")
        roles_to_add = []
        roles_to_delete = []
        role_names = [role.name for role in user.roles]
        for role in role_names:
            if role not in kwargs['privileges']:
                roles_to_delete.append(role)
        for role in kwargs['privileges']:
            if role not in role_names:
                roles_to_add.append(role)
        for role in roles_to_delete:
            remove_user_privilege(user.id, role)
        for role in roles_to_add:
            add_user_privilege(user.id, role)


def create_user(email, password, privileges=None, info=None):
    if not current_user.has_role_or_permission('admin', permissions=['create_user']):
        raise Exception("You do not have sufficient privileges to create a user")
    email = email.strip()
    password = str(password).strip()
    if len(password) < 4 or len(password) > 254:
        raise Exception("Password too short or too long")
    role_dict = {}
    if privileges is None:
        privileges = []
    if isinstance(privileges, DAList):
        info = info.elements
    if not isinstance(privileges, list):
        if not isinstance(privileges, str):
            raise Exception("The privileges parameter to create_user() must be a list or a string.")
        privileges = [privileges]
    if info is None:
        info = {}
    if isinstance(info, DADict):
        info = info.elements
    if not isinstance(info, dict):
        raise Exception("The info parameter to create_user() must be a dictionary.")
    user, user_email = app.user_manager.find_user_by_email(email)
    if user:
        raise Exception("That e-mail address is already being used.")
    user_auth = UserAuthModel(password=app.user_manager.hash_password(password))
    while True:
        new_social = 'local$' + random_alphanumeric(32)
        existing_user = db.session.execute(select(UserModel).filter_by(social_id=new_social)).first()
        if existing_user:
            continue
        break
    the_user = UserModel(
        active=True,
        nickname=re.sub(r'@.*', '', email),
        social_id=new_social,
        email=email,
        user_auth=user_auth,
        first_name=info.get('first_name', ''),
        last_name=info.get('last_name', ''),
        country=info.get('country', ''),
        subdivisionfirst=info.get('subdivisionfirst', ''),
        subdivisionsecond=info.get('subdivisionsecond', ''),
        subdivisionthird=info.get('subdivisionthird', ''),
        organization=info.get('organization', ''),
        timezone=info.get('timezone', ''),
        language=info.get('language', ''),
        confirmed_at=datetime.datetime.now()
    )
    num_roles = 0
    is_admin = current_user.has_role('admin')
    for role in db.session.execute(select(Role).where(Role.name != 'cron').order_by(Role.id)).scalars():
        if role.name in privileges and (is_admin or role.name not in ('admin', 'developer', 'advocate')):
            the_user.roles.append(role)
        num_roles += 1
    if num_roles == 0:
        user_role = db.session.execute(select(Role).filter_by(name='user')).scalar_one()
        the_user.roles.append(user_role)
    db.session.add(user_auth)
    db.session.add(the_user)
    db.session.commit()
    return the_user.id


def make_user_inactive(user_id=None, email=None):
    if not current_user.has_role_or_permission('admin', permissions=['edit_user_active_status']):
        raise Exception("You do not have sufficient privileges to make a user inactive")
    if user_id is None and email is None:
        raise Exception("You must supply a user ID or an e-mail address to make a user inactive")
    if user_id is not None:
        user = db.session.execute(select(UserModel).filter_by(id=user_id)).scalar()
    else:
        assert isinstance(email, str)
        email = email.strip()
        user = db.session.execute(select(UserModel).filter_by(email=email)).scalar()
    if user is None:
        raise Exception("User not found")
    user.active = False
    db.session.commit()


def remove_user_privilege(user_id, privilege):
    if not current_user.has_role_or_permission('admin', permissions=['edit_user_privileges']):
        raise Exception('You do not have sufficient privileges to take a privilege away from a user.')
    if current_user.id == user_id and privilege == 'admin':
        raise Exception('You cannot take away the admin privilege from the current user.')
    if privilege in ('admin', 'developer', 'advocate', 'cron') and not current_user.has_role('admin'):
        raise Exception('You do not have sufficient privileges to take away this privilege.')
    if privilege not in get_privileges_list(admin=True):
        raise Exception('The specified privilege does not exist.')
    user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    if user is None or user.social_id.startswith('disabled$'):
        raise Exception("The specified user did not exist")
    role_to_remove = None
    for role in user.roles:
        if role.name == privilege:
            role_to_remove = role
    if role_to_remove is None:
        raise Exception("The user did not already have that privilege.")
    user.roles.remove(role_to_remove)
    db.session.commit()


def add_user_privilege(user_id, privilege):
    if not current_user.has_role_or_permission('admin', permissions=['edit_user_privileges']):
        raise Exception('You do not have sufficient privileges to give another user a privilege.')
    if privilege in ('admin', 'developer', 'advocate', 'cron') and not current_user.has_role_or_permission('admin'):
        raise Exception('You do not have sufficient privileges to give the user this privilege.')
    if privilege not in get_privileges_list(admin=True):
        raise Exception('The specified privilege does not exist.')
    if privilege == 'cron':
        raise Exception('You cannot give a user the cron privilege.')
    user = db.session.execute(
        select(UserModel).options(db.joinedload(UserModel.roles)).where(UserModel.id == user_id)).scalar()
    if user is None or user.social_id.startswith('disabled$'):
        raise Exception("The specified user did not exist")
    for role in user.roles:
        if role.name == privilege:
            raise Exception("The user already had that privilege.")
    role_to_add = None
    for role in db.session.execute(select(Role).order_by(Role.id)).scalars():
        if role.name == privilege:
            role_to_add = role
    if role_to_add is None:
        raise Exception("The specified privilege did not exist.")
    user.roles.append(role_to_add)
    db.session.commit()


def get_privileges_list(admin=False):
    if admin is False and not current_user.has_role_or_permission('admin', 'developer',
                                                                  permissions=['access_privileges']):
        raise Exception('You do not have sufficient privileges to see the list of privileges.')
    role_names = []
    for role in db.session.execute(select(Role.name).order_by(Role.name)):
        role_names.append(role.name)
    return role_names
