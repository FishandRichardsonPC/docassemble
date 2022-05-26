import json
import os

import docassemble.base.interview_cache
import docassemble_flask_user.signals
from docassemble.base.config import daconfig
from docassemble.base.error import DAError
from docassemble.base.functions import word
from docassemble.base.logger import logmessage
from docassemble.webapp.app_object import csrf
from docassemble.webapp.authentication import current_info, delete_session_for_interview, manual_checkout
from docassemble.webapp.backend import fetch_user_dict, generate_csrf, get_session, guess_yaml_filename, \
    reset_user_dict, url_for
from docassemble.webapp.config_server import DEBUG, START_TIME, WEBAPP_PATH, exit_page, final_default_yaml_filename, \
    kv_session
from docassemble.webapp.global_values import global_css, global_js
from docassemble.webapp.daredis import r
from docassemble.webapp.page_values import additional_css, additional_scripts, standard_html_start, \
    standard_scripts
from docassemble.webapp.setup import da_version
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.util import fresh_dictionary, restart_all
from docassemble_flask_user import login_required, roles_required
from flask import Blueprint, Markup, abort, current_app, jsonify, make_response, redirect, render_template, \
    render_template_string, request, session
from flask_login import current_user, logout_user
from user_agents import parse as ua_parse

util = Blueprint('util', __name__)


@util.route('/goto', methods=['GET'])
def run_temp():
    code = request.args.get('c', None)
    if code is None:
        abort(403)
    ua_string = request.headers.get('User-Agent', None)
    if ua_string is not None:
        response = ua_parse(ua_string)
        if response.device.brand == 'Spider':
            return render_template_string('')
    the_key = 'da:temporary_url:' + str(code)
    data = r.get(the_key)
    if data is None:
        raise DAError(word("The link has expired."), code=403)
    try:
        data = json.loads(data.decode())
        if data.get('once', False):
            r.delete(the_key)
        url = data.get('url')
    except:
        r.delete(the_key)
        url = data.decode()
    return redirect(url)


@util.route('/headers', methods=['POST', 'GET'])
@csrf.exempt
def show_headers():
    return jsonify(headers=dict(request.headers), ipaddress=request.remote_addr)


@util.route("/leave", methods=['GET'])
def leave():
    the_exit_page = exit_page
    return redirect(the_exit_page)


@util.route("/exit", methods=['GET'])
def exit_endpoint():
    the_exit_page = exit_page
    yaml_filename = request.args.get('i', None)
    if yaml_filename is not None:
        session_info = get_session(yaml_filename)
        if session_info is not None:
            manual_checkout(manual_filename=yaml_filename)
            reset_user_dict(session_info['uid'], yaml_filename)
    delete_session_for_interview(i=yaml_filename)
    return redirect(the_exit_page)


@util.route("/exit_logout", methods=['GET'])
def exit_logout():
    the_exit_page = exit_page
    yaml_filename = request.args.get('i', guess_yaml_filename())
    if yaml_filename is not None:
        session_info = get_session(yaml_filename)
        if session_info is not None:
            manual_checkout(manual_filename=yaml_filename)
            reset_user_dict(session_info['uid'], yaml_filename)
    if current_user.is_authenticated:
        docassemble_flask_user.signals.user_logged_out.send(current_app._get_current_object(), user=current_user)
        logout_user()
    session.clear()
    response = redirect(the_exit_page)
    response.set_cookie('remember_token', '', expires=0)
    response.set_cookie('visitor_secret', '', expires=0)
    response.set_cookie('secret', '', expires=0)
    response.set_cookie('session', '', expires=0)
    return response


@util.route("/cleanup_sessions", methods=['GET'])
def cleanup_sessions():
    kv_session.cleanup_sessions()
    return render_template('base_templates/blank.html')


ready_file = os.path.join(os.path.dirname(WEBAPP_PATH), 'ready')


@util.route("/health_status", methods=['GET'])
def health_status():
    ok = True
    if request.args.get('ready', False):
        if not os.path.isfile(ready_file):
            ok = False
    return jsonify({'ok': ok, 'server_start_time': START_TIME, 'version': da_version})


@util.route("/health_check", methods=['GET'])
def health_check():
    if request.args.get('ready', False):
        if not os.path.isfile(ready_file):
            return ('', 400)
    response = make_response(render_template('pages/health_check.html', content="OK"), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@util.route("/restart_ajax", methods=['POST'])
@login_required
@roles_required(['admin', 'developer'])
def restart_ajax():
    if request.form.get('action', None) == 'restart' and current_user.has_role('admin', 'developer'):
        logmessage("restart_ajax: restarting")
        restart_all()
        return jsonify(success=True)
    return jsonify(success=False)


@util.route("/test_embed", methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def test_embed():
    setup_translation()
    yaml_filename = request.args.get('i', final_default_yaml_filename)
    user_dict = fresh_dictionary()
    interview = docassemble.base.interview_cache.get_interview(yaml_filename)
    the_current_info = current_info(yaml=yaml_filename, req=request, action=None, location=None, interface='web',
                                    device_id=request.cookies.get('ds', None))
    docassemble.base.functions.this_thread.current_info = the_current_info
    interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
    try:
        interview.assemble(user_dict, interview_status)
    except:
        pass
    current_language = docassemble.base.functions.get_language()
    page_title = word("Embed test")
    start_part = standard_html_start(interview_language=current_language, debug=False,
                                     bootstrap_theme=interview_status.question.interview.get_bootstrap_theme(),
                                     external=True, page_title=page_title, social=daconfig['social'],
                                     yaml_filename=yaml_filename) + global_css + additional_css(interview_status)
    scripts = standard_scripts(interview_language=current_language, external=True) + additional_scripts(
        interview_status, yaml_filename) + global_js
    response = make_response(render_template('pages/test_embed.html', scripts=scripts, start_part=start_part,
                                             interview_url=url_for('index.index', i=yaml_filename, js_target='dablock',
                                                                   _external=True), page_title=page_title), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@util.route("/vars", methods=['POST', 'GET'])
def get_variables():
    yaml_filename = request.args.get('i', None)
    if yaml_filename is None:
        return ("Invalid request", 400)
    session_info = get_session(yaml_filename)
    if session_info is None:
        return ("Invalid request", 400)
    session_id = session_info['uid']
    if 'visitor_secret' in request.cookies:
        secret = request.cookies['visitor_secret']
    else:
        secret = request.cookies.get('secret', None)
    if secret is not None:
        secret = str(secret)
    if session_id is None or yaml_filename is None:
        return jsonify(success=False)
    docassemble.base.functions.this_thread.current_info = current_info(yaml=yaml_filename, req=request,
                                                                       interface='vars',
                                                                       device_id=request.cookies.get('ds', None))
    try:
        steps, user_dict, is_encrypted = fetch_user_dict(session_id, yaml_filename, secret=secret)
        assert user_dict is not None
    except:
        return jsonify(success=False)
    if (not DEBUG) and '_internal' in user_dict and 'misc' in user_dict['_internal'] and 'variable_access' in \
            user_dict['_internal']['misc'] and user_dict['_internal']['misc']['variable_access'] is False:
        return jsonify(success=False)
    variables = docassemble.base.functions.serializable_dict(user_dict, include_internal=True)
    return jsonify(success=True, variables=variables, steps=steps, encrypted=is_encrypted, uid=session_id,
                   i=yaml_filename)

@util.route('/restart', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def restart_page():
    setup_translation()
    script = """
    <script>
      function daRestartCallback(data){
        //console.log("Restart result: " + data.success);
      }
      function daRestart(){
        $.ajax({
          type: 'POST',
          url: """ + json.dumps(url_for('util.restart_ajax')) + """,
          data: 'csrf_token=""" + generate_csrf() + """&action=restart',
          success: daRestartCallback,
          dataType: 'json'
        });
        return true;
      }
      $( document ).ready(function() {
        //console.log("restarting");
        setTimeout(daRestart, 100);
      });
    </script>"""
    next_url = current_app.user_manager.make_safe_url_function(
        request.args.get('next', url_for('interview.interview_list', post_restart=1)))
    extra_meta = """\n    <meta http-equiv="refresh" content="8;URL='""" + next_url + """'">"""
    response = make_response(render_template('pages/restart.html', version_warning=None, bodyclass='daadminbody',
                                             extra_meta=Markup(extra_meta), extra_js=Markup(script),
                                             tab_title=word('Restarting'), page_title=word('Restarting')), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response
