import codecs
import os
import re

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
from docassemble.base.config import daconfig, in_celery
from docassemble.base.functions import word
from docassemble.webapp.authentication import current_info
from docassemble.webapp.backend import directory_for, project_name, url_for
from docassemble.webapp.config_server import DEFAULT_LANGUAGE
from docassemble.webapp.develop import AddinUploadForm, FunctionFileForm
from docassemble.webapp.files import SavedFile
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.util import ensure_ml_file_exists, get_base_url, get_current_project, get_vars_in_use, \
    indent_by, secure_filename, variables_js
from flask import Blueprint, g
from flask_cors import cross_origin

if not in_celery:
    import docassemble.webapp.worker

from docassemble_flask_user import login_required, roles_required
from flask import make_response, render_template, request, current_app, Markup, jsonify
from flask_login import current_user

office = Blueprint('office', __name__)


@office.route('/officefunctionfile', methods=['GET', 'POST'])
@cross_origin(origins='*', methods=['GET', 'POST', 'HEAD'], automatic_options=True)
def playground_office_functionfile():
    g.embed = True
    docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    functionform = FunctionFileForm(request.form)
    response = make_response(render_template('pages/officefunctionfile.html', current_project=get_current_project(),
                                             page_title=word("Docassemble Playground"), tab_title=word("Playground"),
                                             parent_origin=daconfig.get('office addin url',
                                                                        daconfig.get('url root', get_base_url())),
                                             form=functionform), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@office.route('/officetaskpane', methods=['GET', 'POST'])
@cross_origin(origins='*', methods=['GET', 'POST', 'HEAD'], automatic_options=True)
def playground_office_taskpane():
    g.embed = True
    docassemble.base.functions.set_language(DEFAULT_LANGUAGE)
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    defaultDaServer = url_for('rootindex', _external=True)
    response = make_response(render_template('pages/officeouter.html', page_title=word("Docassemble Playground"),
                                             tab_title=word("Playground"), defaultDaServer=defaultDaServer,
                                             extra_js=Markup(
                                                 "\n        <script>" + indent_by(variables_js(office_mode=True),
                                                                                  9) + "        </script>")), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@office.route('/officeaddin', methods=['GET', 'POST'])
@cross_origin(origins='*', methods=['GET', 'POST', 'HEAD'], automatic_options=True)
@login_required
@roles_required(['developer', 'admin'])
def playground_office_addin():
    g.embed = True
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    if request.args.get('fetchfiles', None):
        playground = SavedFile(current_user.id, fix=True, section='playground')
        the_directory = directory_for(playground, current_project)
        files = sorted([f for f in os.listdir(the_directory) if
                        os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        return jsonify(success=True, files=files)
    pg_var_file = request.args.get('pgvars', None)
    # logmessage("playground_office_addin: YAML file is " + str(pg_var_file))
    use_html = request.args.get('html', False)
    uploadform = AddinUploadForm(request.form)
    if request.method == 'POST':
        area = SavedFile(current_user.id, fix=True, section='playgroundtemplate')
        filename = secure_filename(uploadform.filename.data)
        filename = re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_', filename)
        if filename == '':
            return jsonify({'success': False})
        content = str(uploadform.content.data)
        start_index = 0
        char_index = 0
        for char in content:
            char_index += 1
            if char == ',':
                start_index = char_index
                break
        area.write_content(codecs.decode(bytearray(content[start_index:], encoding='utf-8'), 'base64'),
                           filename=filename, binary=True)
        area.finalize()
        if use_html:
            if pg_var_file is None:
                pg_var_file = ''
        else:
            if pg_var_file is None or pg_var_file == '':
                return jsonify({'success': True, 'variables_json': [], 'vocab_list': []})
    if pg_var_file is not None:
        playground = SavedFile(current_user.id, fix=True, section='playground')
        the_directory = directory_for(playground, current_project)
        files = sorted([f for f in os.listdir(the_directory) if
                        os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        if pg_var_file in files:
            # logmessage("playground_office_addin: file " + str(pg_var_file) + " was found")
            interview_source = docassemble.base.parse.interview_source_from_string(
                'docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + pg_var_file)
            interview_source.set_testing(True)
        else:
            # logmessage("playground_office_addin: file " + str(pg_var_file) + " was not found")
            if pg_var_file == '' and current_project == 'default':
                pg_var_file = 'test.yml'
            content = "modules:\n  - docassemble.base.util\n---\nmandatory: True\nquestion: hi"
            interview_source = docassemble.base.parse.InterviewSourceString(content=content, directory=the_directory,
                                                                            package="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project),
                                                                            path="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project) + ":" + pg_var_file,
                                                                            testing=True)
        interview = interview_source.get_interview()
        ensure_ml_file_exists(interview, pg_var_file, current_project)
        the_current_info = current_info(
            yaml='docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + pg_var_file,
            req=request, action=None, device_id=request.cookies.get('ds', None))
        docassemble.base.functions.this_thread.current_info = the_current_info
        interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
        if use_html:
            variables_html, vocab_list, vocab_dict = get_vars_in_use(interview, interview_status, debug_mode=False,
                                                                     show_messages=False, show_jinja_help=True,
                                                                     current_project=current_project)
            return jsonify({'success': True, 'current_project': current_project, 'variables_html': variables_html,
                            'vocab_list': list(vocab_list), 'vocab_dict': vocab_dict})
        else:
            variables_json, vocab_list = get_vars_in_use(interview, interview_status, debug_mode=False,
                                                         return_json=True, current_project=current_project)
            return jsonify({'success': True, 'variables_json': variables_json, 'vocab_list': list(vocab_list)})
    parent_origin = re.sub(r'^(https?://[^/]+)/.*', r'\1', daconfig.get('office addin url', get_base_url()))
    response = make_response(render_template('pages/officeaddin.html', current_project=current_project,
                                             page_title=word("Docassemble Office Add-in"),
                                             tab_title=word("Office Add-in"), parent_origin=parent_origin,
                                             form=uploadform), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response
