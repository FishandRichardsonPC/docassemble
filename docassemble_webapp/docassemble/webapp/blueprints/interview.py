import copy
import copy
import datetime
import json
import re
import urllib
from urllib.parse import quote as urllibquote, urlparse

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
from docassemble.base.config import in_celery
from docassemble.webapp.app_object import app
from docassemble.webapp.authentication import get_existing_session, update_last_login
from docassemble.webapp.backend import reset_user_dict
from docassemble.webapp.config_server import PREVENT_DEMO, ga_configured, \
    google_config, reserved_argnames
from docassemble.webapp.db_object import db
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.package import get_url_from_file_reference
from docassemble.webapp.user_util import api_verify, create_new_interview, get_question_data, go_back_in_session, \
    set_session_variables
from docassemble.webapp.users.models import TempUser, UserModel
from docassemble.webapp.util import transform_json_variables

if not in_celery:
    import docassemble.webapp.worker

from flask_login import login_user
from sqlalchemy import select
import werkzeug.exceptions
import werkzeug.utils
import docassemble.base.interview_cache
import werkzeug.utils
from docassemble.base.config import daconfig, in_celery
from docassemble.base.error import DAError
from docassemble.base.functions import word
from docassemble.base.generate_key import random_string
from docassemble.base.logger import logmessage
from docassemble.webapp.app_object import csrf
from docassemble.webapp.authentication import current_info, needs_to_change_password, user_interviews
from docassemble.webapp.backend import generate_csrf, update_session, url_for
from docassemble.webapp.config_server import COOKIELESS_SESSIONS, final_default_yaml_filename, version_warning
from docassemble.webapp.daredis import r
from docassemble.webapp.fixpickle import fix_pickle_obj
from docassemble.webapp.blueprints.files import html_index
from docassemble.webapp.blueprints.index import index
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.users.forms import InterviewsListForm
from docassemble.webapp.util import as_int, from_safeid, jsonify_with_status, \
    myb64unquote, safeid, tidy_action, true_or_false
from docassemble_flask_user import login_required, roles_required
from flask import Blueprint, Markup, current_app, flash, make_response, render_template, render_template_string, session
from flask_cors import cross_origin
from flask_login import current_user

if not in_celery:
    pass

from flask import abort, request, redirect, \
    jsonify

interview = Blueprint('interview', __name__)


@interview.route("/launch", methods=['GET'])
def launch():
    if COOKIELESS_SESSIONS:
        return html_index()
    code = request.args.get('c', None)
    if code is None:
        abort(403)
    the_key = 'da:resume_interview:' + str(code)
    data = r.get(the_key)
    if data is None:
        raise DAError(word("The link has expired."), code=403)
    data = json.loads(data.decode())
    if data.get('once', False):
        r.delete(the_key)
    args = {}
    for key, val in request.args.items():
        if key != 'session':
            args[key] = val
    args['i'] = data['i']
    if 'session' in data:
        update_session(data['i'], uid=data['session'])
    else:
        args['new_session'] = '1'
    request.args = args
    return index(refer=['launch'])


@interview.route("/resume", methods=['POST'])
@csrf.exempt
def resume():
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    if 'session' not in post_data or 'i' not in post_data:
        abort(403)
    update_session(post_data['i'], uid=post_data['session'])
    del post_data['session']
    if 'ajax' in post_data:
        ajax_value = int(post_data['ajax'])
        del post_data['ajax']
        if ajax_value:
            return jsonify(action='redirect', url=url_for('index.index', **post_data), csrf_token=generate_csrf())
    return redirect(url_for('index.index', **post_data))


@interview.route('/start/<package>/<directory>/<filename>/', methods=['GET'])
def redirect_to_interview_in_package_directory(package, directory, filename):
    if COOKIELESS_SESSIONS:
        return html_index()
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    arguments['i'] = 'docassemble.' + package + ':data/questions/' + directory + '/' + filename + '.yml'
    if 'session' not in arguments:
        arguments['new_session'] = '1'
    request.args = arguments
    return index(refer=['start_directory', package, directory, filename])


@interview.route('/start/<package>/<filename>/', methods=['GET'])
def redirect_to_interview_in_package(package, filename):
    if COOKIELESS_SESSIONS:
        return html_index()
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    if re.search(r'playground[0-9]', package):
        arguments['i'] = 'docassemble.' + package + ':' + filename + '.yml'
    else:
        arguments['i'] = 'docassemble.' + package + ':data/questions/' + filename + '.yml'
    if 'session' not in arguments:
        arguments['new_session'] = '1'
    request.args = arguments
    return index(refer=['start', package, filename])


@interview.route('/start/<dispatch>/', methods=['GET'])
def redirect_to_interview(dispatch):
    # logmessage("redirect_to_interview: the dispatch is " + str(dispatch))
    if COOKIELESS_SESSIONS:
        return html_index()
    yaml_filename = daconfig['dispatch'].get(dispatch, None)
    if yaml_filename is None:
        return ('File not found', 404)
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    arguments['i'] = yaml_filename
    if 'session' not in arguments:
        arguments['new_session'] = '1'
    request.args = arguments
    return index(refer=['start_dispatch', dispatch])


@interview.route('/run/<package>/<directory>/<filename>/', methods=['GET'])
def run_interview_in_package_directory(package, directory, filename):
    if COOKIELESS_SESSIONS:
        return html_index()
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    arguments['i'] = 'docassemble.' + package + ':data/questions/' + directory + '/' + filename + '.yml'
    request.args = arguments
    return index(refer=['run_direcory', package, directory, filename])


@interview.route('/run/<package>/<filename>/', methods=['GET'])
def run_interview_in_package(package, filename):
    if COOKIELESS_SESSIONS:
        return html_index()
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    if re.search(r'playground[0-9]', package):
        arguments['i'] = 'docassemble.' + package + ':' + filename + '.yml'
    else:
        arguments['i'] = 'docassemble.' + package + ':data/questions/' + filename + '.yml'
    request.args = arguments
    return index(refer=['run', package, filename])


@interview.route('/run/<dispatch>/', methods=['GET'])
def run_interview(dispatch):
    if COOKIELESS_SESSIONS:
        return html_index()
    yaml_filename = daconfig['dispatch'].get(dispatch, None)
    if yaml_filename is None:
        return ('File not found', 404)
    arguments = {}
    for arg in request.args:
        arguments[arg] = request.args[arg]
    arguments['i'] = yaml_filename
    request.args = arguments
    return index(refer=['run_dispatch', dispatch])


def interview_menu(absolute_urls=False, start_new=False, tag=None):
    interview_info = []
    for key, yaml_filename in sorted(daconfig['dispatch'].items()):
        try:
            interview = docassemble.base.interview_cache.get_interview(yaml_filename)
            if interview.is_unlisted():
                continue
            if current_user.is_anonymous:
                if not interview.allowed_to_see_listed(is_anonymous=True):
                    continue
            else:
                if not interview.allowed_to_see_listed(has_roles=[role.name for role in current_user.roles]):
                    continue
            if interview.source is None:
                package = None
            else:
                package = interview.source.get_package()
            titles = interview.get_title(dict(_internal={}))
            tags = interview.get_tags(dict(_internal={}))
            metadata = copy.deepcopy(interview.consolidated_metadata)
            if 'tags' in metadata:
                del metadata['tags']
            interview_title = titles.get('full', titles.get('short', word('Untitled')))
            subtitle = titles.get('sub', None)
            status_class = None
            subtitle_class = None
        except:
            interview_title = yaml_filename
            tags = set()
            metadata = {}
            package = None
            subtitle = None
            status_class = 'dainterviewhaserror'
            subtitle_class = 'dainvisible'
            logmessage("interview_dispatch: unable to load interview file " + yaml_filename)
        if tag is not None and tag not in tags:
            continue
        if absolute_urls:
            if start_new:
                url = url_for('interview.run_interview', dispatch=key, _external=True, reset='1')
            else:
                url = url_for('interview.redirect_to_interview', dispatch=key, _external=True)
        else:
            if start_new:
                url = url_for('interview.run_interview', dispatch=key, reset='1')
            else:
                url = url_for('interview.redirect_to_interview', dispatch=key)
        interview_info.append(dict(link=url, title=interview_title, status_class=status_class, subtitle=subtitle,
                                   subtitle_class=subtitle_class, filename=yaml_filename, package=package,
                                   tags=sorted(tags), metadata=metadata))
    return interview_info


@interview.route('/list', methods=['GET'])
def interview_start():
    if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
        return redirect(url_for('user.login', next=url_for('interview.interview_start', **request.args)))
    setup_translation()
    if len(daconfig['dispatch']) == 0:
        return redirect(url_for('index.index', i=final_default_yaml_filename))
    is_json = bool(('json' in request.form and as_int(request.form['json'])) or (
            'json' in request.args and as_int(request.args['json'])))
    tag = request.args.get('tag', None)
    if daconfig.get('dispatch interview', None) is not None:
        if is_json:
            if tag:
                return redirect(
                    url_for('index.index', i=daconfig.get('dispatch interview'), from_list='1', json='1', tag=tag))
            else:
                return redirect(url_for('index.index', i=daconfig.get('dispatch interview'), from_list='1', json='1'))
        else:
            if tag:
                return redirect(url_for('index.index', i=daconfig.get('dispatch interview'), from_list='1', tag=tag))
            else:
                return redirect(url_for('index.index', i=daconfig.get('dispatch interview'), from_list='1'))
    if 'embedded' in request.args and int(request.args['embedded']):
        the_page = 'pages/start-embedded.html'
        embed = True
    else:
        embed = False
    interview_info = interview_menu(absolute_urls=embed, tag=tag)
    if is_json:
        return jsonify(action='menu', interviews=interview_info)
    argu = dict(version_warning=None,
                interview_info=interview_info)
    if embed:
        the_page = 'pages/start-embedded.html'
    else:
        if 'start page template' in daconfig and daconfig['start page template']:
            the_page = docassemble.base.functions.package_template_filename(daconfig['start page template'])
            if the_page is None:
                raise DAError("Could not find start page template " + daconfig['start page template'])
            with open(the_page, 'r', encoding='utf-8') as fp:
                template_string = fp.read()
                return render_template_string(template_string, **argu)
        else:
            the_page = 'pages/start.html'
    resp = make_response(render_template(the_page, **argu))
    if embed:
        resp.headers['Access-Control-Allow-Origin'] = '*'
    return resp


@interview.route('/api/list', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_list():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    return jsonify(interview_menu(absolute_urls=true_or_false(request.args.get('absolute_urls', True)),
                                  tag=request.args.get('tag', None)))


def page_after_login():
    if current_user.is_authenticated:
        for role, page in daconfig['page after login']:
            if role == '*' or current_user.has_role(role):
                return page
    return 'interview_list'


def valid_date_key(x):
    if x['dict']['_internal']['starttime'] is None:
        return datetime.datetime.now()
    return x['dict']['_internal']['starttime']

@interview.route('/interviews', methods=['GET', 'POST'])
@login_required
def interview_list():
    setup_translation()
    form = InterviewsListForm(request.form)
    is_json = bool(('json' in request.form and as_int(request.form['json'])) or (
            'json' in request.args and as_int(request.args['json'])))
    if 'lang' in request.form:
        session['language'] = request.form['lang']
        docassemble.base.functions.set_language(session['language'])
    tag = request.args.get('tag', None)
    if request.method == 'POST':
        tag = form.tags.data
    if tag is not None:
        tag = werkzeug.utils.secure_filename(tag)
    if 'newsecret' in session:
        the_args = {}
        if is_json:
            the_args['json'] = '1'
        if tag:
            the_args['tag'] = tag
        if 'from_login' in request.args:
            the_args['from_login'] = request.args['from_login']
        if 'post_restart' in request.args:
            the_args['post_restart'] = request.args['post_restart']
        if 'resume' in request.args:
            the_args['resume'] = request.args['resume']
        response = redirect(url_for('interview.interview_list', **the_args))
        response.set_cookie('secret', session['newsecret'], httponly=True,
                            secure=current_app.config['SESSION_COOKIE_SECURE'],
                            samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
        del session['newsecret']
        return response
    if request.method == 'GET' and needs_to_change_password():
        return redirect(url_for('user.change_password', next=url_for('interview.interview_list')))
    secret = request.cookies.get('secret', None)
    if secret is not None:
        secret = str(secret)
    if request.method == 'POST':
        if form.delete_all.data:
            num_deleted = user_interviews(user_id=current_user.id, secret=secret, action='delete_all', tag=tag)
            if num_deleted > 0:
                flash(word("Deleted interviews"), 'success')
            if is_json:
                return redirect(url_for('interview.interview_list', json='1'))
            return redirect(url_for('interview.interview_list'))
        elif form.delete.data:
            yaml_file = form.i.data
            session_id = form.session.data
            if yaml_file is not None and session_id is not None:
                user_interviews(user_id=current_user.id, secret=secret, action='delete', session=session_id,
                                filename=yaml_file)
                flash(word("Deleted interview"), 'success')
            if is_json:
                return redirect(url_for('interview.interview_list', json='1'))
            return redirect(url_for('interview.interview_list'))
    if request.args.get('from_login', False) or (
            re.search(r'user/(register|sign-in)', str(request.referrer)) and 'next=' not in str(request.referrer)):
        next_page = current_app.user_manager.make_safe_url_function(request.args.get('next', page_after_login()))
        if next_page is None:
            logmessage("Invalid page " + str(next_page))
            next_page = 'interview_list'
        if next_page not in ('interview_list', 'interviews'):
            return redirect(get_url_from_file_reference(next_page))
    if daconfig.get('session list interview', None) is not None:
        if is_json:
            return redirect(url_for('index.index', i=daconfig.get('session list interview'), from_list='1', json='1'))
        else:
            return redirect(url_for('index.index', i=daconfig.get('session list interview'), from_list='1'))
    exclude_invalid = not current_user.has_role('admin', 'developer')
    resume_interview = request.args.get('resume', None)
    if resume_interview is None and daconfig.get('auto resume interview', None) is not None and (
            request.args.get('from_login', False) or (
            re.search(r'user/(register|sign-in)', str(request.referrer)) and 'next=' not in str(request.referrer))):
        resume_interview = daconfig['auto resume interview']
    device_id = request.cookies.get('ds', None)
    if device_id is None:
        device_id = random_string(16)
    the_current_info = current_info(yaml=None, req=request, interface='web', session_info=None, secret=secret,
                                    device_id=device_id)
    docassemble.base.functions.this_thread.current_info = the_current_info
    if resume_interview is not None:
        (interviews, start_id) = user_interviews(user_id=current_user.id, secret=secret, exclude_invalid=True,
                                                 filename=resume_interview, include_dict=True)
        if len(interviews) > 0:
            return redirect(
                url_for('index.index', i=interviews[0]['filename'], session=interviews[0]['session'], from_list='1'))
        return redirect(url_for('index.index', i=resume_interview, from_list='1'))
    next_id_code = request.args.get('next_id', None)
    if next_id_code:
        try:
            start_id = int(from_safeid(next_id_code))
            assert start_id >= 0
            show_back = True
        except:
            start_id = None
            show_back = False
    else:
        start_id = None
        show_back = False
    result = user_interviews(user_id=current_user.id, secret=secret, exclude_invalid=exclude_invalid, tag=tag,
                             start_id=start_id)
    if result is None:
        raise Exception("interview_list: could not obtain list of interviews")
    (interviews, start_id) = result
    if start_id is None:
        next_id = None
    else:
        next_id = safeid(str(start_id))
    if is_json:
        for interview in interviews:
            if 'dict' in interview:
                del interview['dict']
            if 'tags' in interview:
                interview['tags'] = sorted(interview['tags'])
        return jsonify(action="interviews", interviews=interviews, next_id=next_id)
    script = """
    <script>
      $(".dadeletebutton").on('click', function(event){
        console.log("Doing click");
        var yamlFilename = $("<input>")
          .attr("type", "hidden")
          .attr("name", "i").val($(this).data('i'));
        $("#daform").append($(yamlFilename));
        var session = $("<input>")
          .attr("type", "hidden")
          .attr("name", "session").val($(this).data('session'));
        $("#daform").append($(session));
        return true;
      });
      $("#delete_all").on('click', function(event){
        if (confirm(""" + json.dumps(word("Are you sure you want to delete all saved interviews?")) + """)){
          return true;
        }
        event.preventDefault();
        return false;
      });
    </script>"""
    if re.search(r'user/register', str(request.referrer)) and len(interviews) == 1:
        return redirect(url_for('index.index', i=interviews[0]['filename'], session=interviews[0]['session'], from_list=1))
    tags_used = set()
    for interview in interviews:
        for the_tag in interview['tags']:
            if the_tag != tag:
                tags_used.add(the_tag)
    argu = dict(version_warning=version_warning, tags_used=sorted(tags_used) if len(tags_used) > 0 else None,
                numinterviews=len([y for y in interviews if not y['metadata'].get('hidden', False)]),
                interviews=sorted(interviews, key=valid_date_key), tag=tag, next_id=next_id, show_back=show_back,
                form=form, page_js=Markup(
            script))  # extra_css=Markup(global_css), extra_js=Markup(script), tab_title=interview_page_title, page_title=interview_page_title, title=title
    if 'interview page template' in daconfig and daconfig['interview page template']:
        the_page = docassemble.base.functions.package_template_filename(daconfig['interview page template'])
        if the_page is None:
            raise DAError("Could not find start page template " + daconfig['start page template'])
        with open(the_page, 'r', encoding='utf-8') as fp:
            template_string = fp.read()
            response = make_response(render_template_string(template_string, **argu), 200)
            response.headers[
                'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
            return response
    else:
        response = make_response(render_template('pages/interviews.html', **argu), 200)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response


@interview.route('/visit_interview', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'advocate'])
def visit_interview():
    setup_translation()
    i = request.args.get('i', None)
    uid = request.args.get('uid', None)
    userid = request.args.get('userid', None)
    key = 'da:session:uid:' + str(uid) + ':i:' + str(i) + ':userid:' + str(userid)
    try:
        obj = fix_pickle_obj(r.get(key))
    except:
        return ('Interview not found', 404)
    if 'secret' not in obj or 'encrypted' not in obj:
        return ('Interview not found', 404)
    session_info = update_session(i, uid=uid, encrypted=obj['encrypted'])
    if 'user_id' not in session:
        session['user_id'] = current_user.id
    if 'tempuser' in session:
        del session['tempuser']
    response = redirect(url_for('index.index', i=i))
    response.set_cookie('visitor_secret', obj['secret'], httponly=True, secure=current_app.config['SESSION_COOKIE_SECURE'],
                        samesite=current_app.config['SESSION_COOKIE_SAMESITE'])
    return response


@interview.route('/api/interview', methods=['GET', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'HEAD'], automatic_options=True)
def api_interview():
    abort(404)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            return jsonify_with_status('The request must be JSON', 400)
        yaml_filename = post_data.get('i', None)
        secret = post_data.get('secret', None)
        session_id = post_data.get('session', None)
        url_args = post_data.get('url_args', None)
        user_code = post_data.get('user_code', None)
        command = post_data.get('command', None)
        referer = post_data.get('referer', None)
    else:
        yaml_filename = request.args.get('i', None)
        secret = request.args.get('secret', None)
        session_id = request.args.get('session', None)
        url_args = {}
        user_code = request.args.get('user_code', None)
        command = request.args.get('command', None)
        referer = request.args.get('referer', None)
        for key, val in request.args.items():
            if key not in ('session', 'secret', 'i', 'user_code', 'command', 'referer', 'action'):
                url_args[key] = val
        if len(url_args) == 0:
            url_args = None
    output = {}
    action = None
    reset_fully = False
    is_new = False
    changed = False
    if user_code:
        key = 'da:apiinterview:usercode:' + user_code
        user_info = r.get(key)
        if user_info is None:
            user_code = None
        else:
            r.expire(key, 60 * 60 * 24 * 30)
            try:
                user_info = json.loads(user_info)
            except:
                user_code = None
        if user_code:
            if user_info['user_id']:
                user = db.session.execute(select(UserModel).filter_by(id=user_info['user_id'])).scalar()
                if user is None or user.social_id.startswith('disabled$') or not user.active:
                    user_code = None
                else:
                    login_user(user, remember=False)
                    update_last_login(user)
            else:
                session['tempuser'] = user_info['temp_user_id']
    if not user_code:
        user_code = current_app.session_interface.manual_save_session(app, session).decode()
        if current_user.is_anonymous:
            new_temp_user = TempUser()
            db.session.add(new_temp_user)
            db.session.commit()
            session['tempuser'] = new_temp_user.id
            user_info = {"user_id": None, "temp_user_id": new_temp_user.id, "sessions": {}}
        else:
            user_info = {"user_id": current_user.id, "temp_user_id": None, "sessions": {}}
        output['user_code'] = user_code
        changed = True
    need_to_reset = False
    new_session = False
    send_initial = False
    if yaml_filename.startswith('/'):
        parts = urlparse(yaml_filename)
        params = urllib.parse.parse_qs(parts.query)
        if params.get('action', '') != '':
            try:
                action = tidy_action(json.loads(myb64unquote(params['action'])))
            except:
                return jsonify_with_status(word("Invalid action."), 400)
        url_args = {}
        for key, val in dict(params).items():
            params[key] = val[0]
            if key not in reserved_argnames:
                url_args[key] = val[0]
        if parts.path == '/launch':
            code = params.get('c', None)
            if code is None:
                abort(403)
            the_key = 'da:resume_interview:' + str(code)
            data = r.get(the_key)
            if data is None:
                return jsonify_with_status(word("The link has expired."), 403)
            data = json.loads(data.decode())
            if data.get('once', False):
                r.delete(the_key)
            args = {}
            for key, val in params.items():
                if key != 'session':
                    args[key] = val
            yaml_filename = data['i']
            if 'session' in data:
                session_id = data['session']
                user_info['sessions'][yaml_filename] = session_id
            else:
                new_session = True
        if parts.path in ('/i', '/interview', '/'):
            ok = False
            if 'i' in params:
                yaml_filename = params['i']
                ok = True
            elif 'state' in params:
                try:
                    yaml_filename = re.sub(r'\^.*', '', from_safeid(params['state']))
                    ok = True
                except:
                    ok = False
            if not ok:
                if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
                    output['redirect'] = url_for('user.login')
                    return jsonify(output)
                if len(daconfig['dispatch']) > 0:
                    output['redirect'] = url_for('interview.interview_start')
                    return jsonify(output)
                else:
                    yaml_filename = final_default_yaml_filename
        refer = None
        if parts.path.startswith('/start/') or parts.path.startswith('/run/'):
            m = re.search(r'/(start|run)/([^/]+)/$', parts.path)
            if m:
                refer = [m.group(1) + '_dispatch', m.group(2)]
                dispatch = m.group(2)
            else:
                m = re.search(r'/(start|run)/([^/]+)/([^/]+)/(.*)/$', parts.path)
                if m:
                    refer = [m.group(1) + '_directory', m.group(2), m.group(3), m.group(4)]
                    yaml_filename = 'docassemble.' + m.group(2) + ':data/questions/' + m.group(3) + '/' + m.group(
                        4) + '.yml'
                else:
                    m = re.search(r'/(start|run)/([^/]+)/(.*)/$', parts.path)
                    if m:
                        refer = [m.group(1), m.group(2), m.group(3)]
                        if re.search(r'playground[0-9]', m.group(2)):
                            yaml_filename = 'docassemble.' + m.group(2) + ':' + m.group(3) + '.yml'
                        else:
                            yaml_filename = 'docassemble.' + m.group(2) + ':data/questions/' + m.group(3) + '.yml'
                    else:
                        yaml_filename = None
            if yaml_filename is None:
                return jsonify_with_status("File not found", 404)
            if m.group(1) == 'start':
                new_session = True
        if true_or_false(params.get('reset', False)):
            need_to_reset = True
            if str(params['reset']) == '2':
                reset_fully = True
        if true_or_false(params.get('new_session', False)):
            new_session = True
        index_params = dict(i=yaml_filename)
        output['i'] = yaml_filename
        output['page_sep'] = "#page"
        if refer is None:
            output['location_bar'] = url_for('index.index', **index_params)
        elif refer[0] in ('start', 'run'):
            output['location_bar'] = url_for('interview.run_interview_in_package', package=refer[1], filename=refer[2])
            output['page_sep'] = "#/"
        elif refer[0] in ('start_dispatch', 'run_dispatch'):
            output['location_bar'] = url_for('interview.run_interview', dispatch=refer[1])
            output['page_sep'] = "#/"
        elif refer[0] in ('start_directory', 'run_directory'):
            output['location_bar'] = url_for('interview.run_interview_in_package_directory', package=refer[1], directory=refer[2],
                                             filename=refer[3])
            output['page_sep'] = "#/"
        else:
            output['location_bar'] = None
            for k, v in daconfig['dispatch'].items():
                if v == yaml_filename:
                    output['location_bar'] = url_for('interview.run_interview', dispatch=k)
                    output['page_sep'] = "#/"
                    break
            if output['location_bar'] is None:
                output['location_bar'] = url_for('index.index', **index_params)
        send_initial = True
    if not yaml_filename:
        return jsonify_with_status("Parameter i is required.", 400)
    if not secret:
        secret = random_string(16)
        output['secret'] = secret
    secret = str(secret)
    docassemble.base.functions.this_thread.current_info = current_info(req=request, interface='api', secret=secret)
    if yaml_filename not in user_info['sessions'] or need_to_reset or new_session:
        was_new = True
        if PREVENT_DEMO and (
                yaml_filename.startswith('docassemble.base:') or yaml_filename.startswith('docassemble.demo:')) and (
                current_user.is_anonymous or not current_user.has_role_or_permission('admin', 'developer',
                                                                                     permissions=['demo_interviews'])):
            return jsonify_with_status(word("Not authorized"), 403)
        if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
            output['redirect'] = url_for('user.login', next=url_for('index.index', i=yaml_filename, **url_args))
            return jsonify(output)
        if yaml_filename.startswith('docassemble.playground'):
            if not current_app.config['ENABLE_PLAYGROUND']:
                return jsonify_with_status(word("Not authorized"), 403)
        else:
            yaml_filename = re.sub(r':([^\/]+)$', r':data/questions/\1', yaml_filename)
        interview = docassemble.base.interview_cache.get_interview(yaml_filename)
        if session_id is None:
            if need_to_reset and yaml_filename in user_info['sessions']:
                reset_user_dict(user_info['sessions'][yaml_filename], yaml_filename)
                del user_info['sessions'][yaml_filename]
            unique_sessions = interview.consolidated_metadata.get('sessions are unique', False)
            if unique_sessions is not False and not current_user.is_authenticated:
                if yaml_filename in user_info['sessions']:
                    del user_info['sessions'][yaml_filename]
                output['redirect'] = url_for('user.login', next=url_for('index.index', i=yaml_filename, **url_args))
                return jsonify(output)
            if interview.consolidated_metadata.get('temporary session', False):
                if yaml_filename in user_info['sessions']:
                    reset_user_dict(user_info['sessions'][yaml_filename], yaml_filename)
                    del user_info['sessions'][yaml_filename]
                if current_user.is_authenticated:
                    while True:
                        the_session_id, encrypted = get_existing_session(yaml_filename, secret)
                        if the_session_id:
                            reset_user_dict(the_session_id, yaml_filename)
                        else:
                            break
                    need_to_reset = True
            if current_user.is_anonymous:
                if (not interview.allowed_to_initiate(is_anonymous=True)) or (
                        not interview.allowed_to_access(is_anonymous=True)):
                    output['redirect'] = url_for('user.login', next=url_for('index.index', i=yaml_filename, **url_args))
                    return jsonify(output)
            elif not interview.allowed_to_initiate(has_roles=[role.name for role in current_user.roles]):
                return jsonify_with_status(word("You are not allowed to access this interview."), 403)
            elif not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                return jsonify_with_status(word("You are not allowed to access this interview."), 403)
            session_id = None
            if reset_fully:
                user_info['sessions'] = {}
            if (not need_to_reset) and (unique_sessions is True or (
                    isinstance(unique_sessions, list) and len(unique_sessions) and current_user.has_role(
                *unique_sessions))):
                session_id, encrypted = get_existing_session(yaml_filename, secret)
        else:
            unique_sessions = interview.consolidated_metadata.get('sessions are unique', False)
            if unique_sessions is not False and not current_user.is_authenticated:
                if yaml_filename in user_info['sessions']:
                    del user_info['sessions'][yaml_filename]
                output['redirect'] = url_for('user.login',
                                             next=url_for('index.index', i=yaml_filename, session=session_id, **url_args))
                return jsonify(output)
            if current_user.is_anonymous:
                if (not interview.allowed_to_initiate(is_anonymous=True)) or (
                        not interview.allowed_to_access(is_anonymous=True)):
                    output['redirect'] = url_for('user.login',
                                                 next=url_for('index.index', i=yaml_filename, session=session_id, **url_args))
                    return jsonify(output)
            elif not interview.allowed_to_initiate(has_roles=[role.name for role in current_user.roles]):
                if yaml_filename in user_info['sessions']:
                    del user_info['sessions'][yaml_filename]
                return jsonify_with_status(word("You are not allowed to access this interview."), 403)
            elif not interview.allowed_to_access(has_roles=[role.name for role in current_user.roles]):
                if yaml_filename in user_info['sessions']:
                    del user_info['sessions'][yaml_filename]
                return jsonify_with_status(word("You are not allowed to access this interview."), 403)
            if need_to_reset:
                reset_user_dict(session_id, yaml_filename)
        session_id = None
    if new_session:
        session_id = None
        if yaml_filename in user_info['sessions']:
            del user_info['sessions'][yaml_filename]
    if not session_id:
        if yaml_filename in user_info['sessions']:
            session_id = user_info['sessions'][yaml_filename]
        else:
            try:
                (encrypted, session_id) = create_new_interview(yaml_filename, secret, url_args=url_args,
                                                               referer=referer, req=request)
            except Exception as err:
                return jsonify_with_status(err.__class__.__name__ + ': ' + str(err), 400)
            user_info['sessions'][yaml_filename] = session_id
            changed = True
            is_new = True
        # output['session'] = session_id
    if changed:
        key = 'da:apiinterview:usercode:' + user_code
        pipe = r.pipeline()
        pipe.set(key, json.dumps(user_info))
        pipe.expire(key, 60 * 60 * 24 * 30)
        pipe.execute()
    if not is_new:
        if url_args is not None and isinstance(url_args, dict) and len(url_args) > 0:
            logmessage("url_args is " + repr(url_args))
            variables = {}
            for key, val in url_args.items():
                variables["url_args[%s]" % (repr(key),)] = val
            try:
                set_session_variables(yaml_filename, session_id, variables, secret=secret, use_lock=True)
            except Exception as the_err:
                return jsonify_with_status(str(the_err), 400)
    obtain_lock(session_id, yaml_filename)
    if request.method == 'POST' and command == 'action':
        action = post_data.get('action', None)
    if action is not None:
        if not isinstance(action, dict) or 'action' not in action or 'arguments' not in action:
            release_lock(session_id, yaml_filename)
            return jsonify_with_status("Invalid action", 400)
        try:
            data = get_question_data(yaml_filename, session_id, secret, save=True, use_lock=False, action=action,
                                     post_setting=True, advance_progress_meter=True, encode=True)
        except Exception as err:
            release_lock(session_id, yaml_filename)
            return jsonify_with_status(str(err), 400)
    else:
        try:
            data = get_question_data(yaml_filename, session_id, secret, save=False, use_lock=False, encode=True)
        except Exception as err:
            release_lock(session_id, yaml_filename)
            return jsonify_with_status(str(err), 400)
    if request.method == 'POST':
        if command == 'back':
            if data['allow_going_back']:
                try:
                    data = go_back_in_session(yaml_filename, session_id, secret=secret, return_question=True,
                                              encode=True)
                except Exception as the_err:
                    release_lock(session_id, yaml_filename)
                    return jsonify_with_status(str(the_err), 400)
        elif command is None:
            variables = post_data.get('variables', None)
            if not isinstance(variables, dict):
                release_lock(session_id, yaml_filename)
                return jsonify_with_status("variables must be a dictionary", 400)
            if variables is not None:
                variables = transform_json_variables(variables)
            valid_variables = {}
            if 'fields' in data:
                for field in data['fields']:
                    if 'variable_name' in field and field.get('active', False):
                        valid_variables[field['variable_name']] = field
                    if field.get('required', False) and 'variable_name' in field:
                        if field['variable_name'] not in variables:
                            release_lock(session_id, yaml_filename)
                            return jsonify_with_status("variable %s is missing" % (field['variable_name'],), 400)
            for key, val in variables.items():
                if key not in valid_variables:
                    release_lock(session_id, yaml_filename)
                    return jsonify_with_status("invalid variable name " + repr(key), 400)
            try:
                data = set_session_variables(yaml_filename, session_id, variables, secret=secret, return_question=True,
                                             event_list=data.get('event_list', None),
                                             question_name=data.get('questionName', None), encode=True)
            except Exception as the_err:
                release_lock(session_id, yaml_filename)
                return jsonify_with_status(str(the_err), 400)
        elif command != 'action':
            release_lock(session_id, yaml_filename)
            return jsonify_with_status("Invalid command", 400)
    if data.get('questionType', None) in ('response', 'sendfile'):
        output['question'] = {
            'questionType': data['questionType']
        }
    else:
        output['question'] = data
    release_lock(session_id, yaml_filename)
    if send_initial:
        output['setup'] = {}
        if 'google maps api key' in google_config:
            api_key = google_config.get('google maps api key')
        elif 'api key' in google_config:
            api_key = google_config.get('api key')
        else:
            api_key = None
        if api_key:
            output['setup']['googleApiKey'] = api_key
        if ga_configured and data['interview_options'].get('analytics on', True):
            interview_package = re.sub(r'^docassemble\.', '', re.sub(r':.*', '', yaml_filename))
            interview_filename = re.sub(r'\.ya?ml$', '', re.sub(r'.*[:\/]', '', yaml_filename), re.IGNORECASE)
            output['setup']['googleAnalytics'] = dict(enable=True, ga_id=google_config.get('analytics id'),
                                                      prefix=interview_package + '/' + interview_filename)
        else:
            output['setup']['googleAnalytics'] = dict(enable=False)
    return jsonify(output)
