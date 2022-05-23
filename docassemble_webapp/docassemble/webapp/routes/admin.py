from distutils.version import LooseVersion
import datetime
import json
import os
import re
import subprocess
import tempfile
import time
import zipfile
from distutils.version import LooseVersion
from subprocess import PIPE, Popen
from urllib.parse import quote as urllibquote
from urllib.request import urlretrieve

import docassemble.base.DA
import docassemble.base.DA
import docassemble.base.astparser
import docassemble.base.astparser
import docassemble.base.core  # for backward-compatibility with data pickled in earlier versions
import docassemble.base.core
import docassemble.base.functions
import docassemble.base.functions
import docassemble.base.interview_cache
import docassemble.base.interview_cache
import docassemble.base.parse
import docassemble.base.parse
import docassemble.base.pdftk
import docassemble.base.pdftk
import docassemble.base.util
import docassemble.base.util
import docassemble.webapp.backend
import docassemble.webapp.backend
import docassemble.webapp.clicksend
import docassemble.webapp.clicksend
import docassemble.webapp.machinelearning
import docassemble.webapp.machinelearning
import docassemble.webapp.setup
import docassemble.webapp.setup
import docassemble.webapp.telnyx
import docassemble.webapp.telnyx
import werkzeug.exceptions
import werkzeug.utils
from docassemble.base.config import in_celery
from docassemble.webapp.authentication import current_info
from docassemble.webapp.backend import directory_for, generate_csrf, project_name
from docassemble.webapp.config_server import CHECKIN_INTERVAL, DEBUG, NOTIFICATION_CONTAINER, NOTIFICATION_MESSAGE, \
    ROOT
from docassemble.webapp.page_values import standard_html_start, standard_scripts
from docassemble.webapp.util import ensure_ml_file_exists, get_vars_in_use, indent_by
from flask import jsonify

if not in_celery:
    import docassemble.webapp.worker

import docassemble.base.DA
import docassemble.base.astparser
import docassemble.base.core  # for backward-compatibility with data pickled in earlier versions
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
from docassemble.base.config import hostname, in_celery
from docassemble.webapp.config_server import SUPERVISORCTL, USING_SUPERVISOR

if not in_celery:
    import docassemble.webapp.worker

from flask import abort
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
from docassemble.base.functions import get_default_timezone
from docassemble.webapp.config_server import LOG_DIRECTORY
from docassemble.webapp.develop import LogForm
from docassemble.webapp.util import secure_filename_spaces_ok, true_or_false

if not in_celery:
    import docassemble.webapp.worker

from flask import send_file
import humanize
from backports import zoneinfo
import tailer

import docassemble.webapp.worker
import httplib2
from docassemble.base.config import daconfig
from docassemble.base.error import DAError
from docassemble.base.functions import word
from docassemble.base.generate_key import random_string
from docassemble.base.logger import logmessage
from docassemble.webapp.authentication import delete_ssh_keys, get_github_flow, get_next_link, \
    get_ssh_keys
from docassemble.webapp.backend import file_set_attributes, get_new_file_number, url_for
from docassemble.webapp.config_server import GITHUB_BRANCH, LOGSERVER, START_TIME, version_warning
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.develop import GitHubForm, UpdatePackageForm
from docassemble.webapp.files import SavedFile
from docassemble.webapp.package import get_master_branch, get_package_info, get_package_name_from_zip, \
    install_git_package, install_pip_package, install_zip_package, pypi_status, uninstall_package, user_can_edit_package
from docassemble.webapp.packages.models import Package
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.util import RedisCredStorage, secure_filename, should_run_create
from docassemble_flask_user import login_required, roles_required
from flask import Blueprint, Markup, current_app, flash, make_response, redirect, render_template, request, session
from flask_login import current_user
from sqlalchemy import select

admin = Blueprint('admin', __name__)


@admin.route('/github_configure', methods=['POST', 'GET'])
@login_required
@roles_required(['admin', 'developer'])
def github_configure():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if not current_app.config['USE_GITHUB']:
        return ('File not found', 404)
    setup_translation()
    storage = RedisCredStorage(app='github')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        state_string = random_string(16)
        session['github_next'] = json.dumps(dict(state=state_string, path='github_configure', arguments=request.args))
        flow = get_github_flow()
        uri = flow.step1_get_authorize_url(state=state_string)
        return redirect(uri)
    http = credentials.authorize(httplib2.Http())
    found = False
    resp, content = http.request("https://api.github.com/user/emails", "GET")
    if int(resp['status']) == 200:
        user_info_list = json.loads(content.decode())
        user_info = None
        for item in user_info_list:
            if item.get('email', None) and item.get('visibility', None) != 'private':
                user_info = item
        if user_info is None:
            raise DAError("github_configure: could not get e-mail address")
    else:
        raise DAError("github_configure: could not get information about user")
    resp, content = http.request("https://api.github.com/user/keys", "GET")
    if int(resp['status']) == 200:
        for key in json.loads(content.decode()):
            if key['title'] == current_app.config['APP_NAME'] or key['title'] == current_app.config[
                'APP_NAME'] + '_user_' + str(current_user.id):
                found = True
    else:
        raise DAError("github_configure: could not get information about ssh keys")
    while found is False:
        next_link = get_next_link(resp)
        if next_link:
            resp, content = http.request(next_link, "GET")
            if int(resp['status']) == 200:
                for key in json.loads(content.decode()):
                    if key['title'] == current_app.config['APP_NAME'] or key['title'] == current_app.config[
                        'APP_NAME'] + '_user_' + str(current_user.id):
                        found = True
            else:
                raise DAError("github_configure: could not get additional information about ssh keys")
        else:
            break
    if found:
        flash(word("Your GitHub integration has already been configured."), 'info')
    if not found:
        (private_key_file, public_key_file) = get_ssh_keys(user_info['email'])
        with open(public_key_file, 'r', encoding='utf-8') as fp:
            public_key = fp.read()
        headers = {'Content-Type': 'application/json'}
        body = json.dumps(dict(title=current_app.config['APP_NAME'] + '_user_' + str(current_user.id), key=public_key))
        resp, content = http.request("https://api.github.com/user/keys", "POST", headers=headers, body=body)
        if int(resp['status']) == 201:
            flash(word("GitHub integration was successfully configured."), 'info')
        else:
            raise DAError("github_configure: error setting public key")
    r.set('da:using_github:userid:' + str(current_user.id), json.dumps(dict(shared=True, orgs=True)))
    return redirect(url_for('github_menu'))


@admin.route('/github_unconfigure', methods=['POST', 'GET'])
@login_required
@roles_required(['admin', 'developer'])
def github_unconfigure():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if not current_app.config['USE_GITHUB']:
        return ('File not found', 404)
    setup_translation()
    storage = RedisCredStorage(app='github')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        state_string = random_string(16)
        session['github_next'] = json.dumps(dict(state=state_string, path='github_unconfigure', arguments=request.args))
        flow = get_github_flow()
        uri = flow.step1_get_authorize_url(state=state_string)
        return redirect(uri)
    http = credentials.authorize(httplib2.Http())
    ids_to_remove = []
    try:
        resp, content = http.request("https://api.github.com/user/keys", "GET")
        if int(resp['status']) == 200:
            for key in json.loads(content.decode()):
                if key['title'] == current_app.config['APP_NAME'] or key['title'] == current_app.config[
                    'APP_NAME'] + '_user_' + str(current_user.id):
                    ids_to_remove.append(key['id'])
        else:
            raise DAError("github_configure: could not get information about ssh keys")
        while True:
            next_link = get_next_link(resp)
            if next_link:
                resp, content = http.request(next_link, "GET")
                if int(resp['status']) == 200:
                    for key in json.loads(content.decode()):
                        if key['title'] == current_app.config['APP_NAME'] or key['title'] == current_app.config[
                            'APP_NAME'] + '_user_' + str(current_user.id):
                            ids_to_remove.append(key['id'])
                else:
                    raise DAError("github_unconfigure: could not get additional information about ssh keys")
            else:
                break
        for id_to_remove in ids_to_remove:
            resp, content = http.request("https://api.github.com/user/keys/" + str(id_to_remove), "DELETE")
            if int(resp['status']) != 204:
                raise DAError("github_unconfigure: error deleting public key " + str(id_to_remove) + ": " + str(
                    resp['status']) + " content: " + content.decode())
    except:
        logmessage("Error deleting SSH keys on GitHub")
    delete_ssh_keys()
    r.delete('da:github:userid:' + str(current_user.id))
    r.delete('da:using_github:userid:' + str(current_user.id))
    flash(word("GitHub integration was successfully disconnected."), 'info')
    return redirect(url_for('user_profile_page'))


@admin.route('/github_menu', methods=['POST', 'GET'])
@login_required
@roles_required(['admin', 'developer'])
def github_menu():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if not current_app.config['USE_GITHUB']:
        return ('File not found', 404)
    setup_translation()
    form = GitHubForm(request.form)
    if request.method == 'POST':
        if form.configure.data:
            return redirect(url_for('github_configure'))
        if form.unconfigure.data:
            return redirect(url_for('github_unconfigure'))
        if form.cancel.data:
            return redirect(url_for('user_profile_page'))
        if form.save.data:
            info = {}
            info['shared'] = bool(form.shared.data)
            info['orgs'] = bool(form.orgs.data)
            r.set('da:using_github:userid:' + str(current_user.id), json.dumps(info))
            flash(word("Your GitHub settings were saved."), 'info')
    uses_github = r.get('da:using_github:userid:' + str(current_user.id))
    if uses_github is not None:
        uses_github = uses_github.decode()
        if uses_github == '1':
            form.shared.data = True
            form.orgs.data = True
        else:
            info = json.loads(uses_github)
            form.shared.data = info['shared']
            form.orgs.data = info['orgs']
        description = word(
            "Your GitHub integration is currently turned on.  Below, you can change which repositories docassemble can access.  You can disable GitHub integration if you no longer wish to use it.")
    else:
        description = word(
            "If you have a GitHub account, you can turn on GitHub integration.  This will allow you to use GitHub as a version control system for packages from inside the Playground.")
    return render_template('pages/github.html', form=form, version_warning=None, title=word("GitHub Integration"),
                           tab_title=word("GitHub"), page_title=word("GitHub"), description=description,
                           uses_github=uses_github, bodyclass='daadminbody')


@admin.route('/updatepackage', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def update_package():
    setup_translation()
    if not current_app.config['ALLOW_UPDATES']:
        return ('File not found', 404)
    if 'taskwait' in session:
        del session['taskwait']
    if 'serverstarttime' in session:
        del session['serverstarttime']
    if request.method == 'GET' and current_app.config['USE_GITHUB'] and r.get(
            'da:using_github:userid:' + str(current_user.id)) is not None:
        storage = RedisCredStorage(app='github')
        credentials = storage.get()
        if not credentials or credentials.invalid:
            state_string = random_string(16)
            session['github_next'] = json.dumps(
                dict(state=state_string, path='playground_packages', arguments=request.args))
            flow = get_github_flow()
            uri = flow.step1_get_authorize_url(state=state_string)
            return redirect(uri)
    form = UpdatePackageForm(request.form)
    form.gitbranch.choices = [('', "Not applicable")]
    if form.gitbranch.data:
        form.gitbranch.choices.append((form.gitbranch.data, form.gitbranch.data))
    action = request.args.get('action', None)
    target = request.args.get('package', None)
    limitation = request.args.get('limitation', '')
    branch = None
    if action is not None and target is not None:
        package_list, package_auth = get_package_info()
        the_package = None
        for package in package_list:
            if package.package.name == target:
                the_package = package
                break
        if the_package is not None:
            if action == 'uninstall' and the_package.can_uninstall:
                uninstall_package(target)
            elif action == 'update' and the_package.can_update:
                existing_package = db.session.execute(
                    select(Package).filter_by(name=target, active=True).order_by(Package.id.desc())).scalar()
                if existing_package is not None:
                    if limitation and existing_package.limitation != limitation:
                        existing_package.limitation = limitation
                        db.session.commit()
                    if existing_package.type == 'git' and existing_package.giturl is not None:
                        if existing_package.gitbranch:
                            install_git_package(target, existing_package.giturl, existing_package.gitbranch)
                        else:
                            install_git_package(target, existing_package.giturl,
                                                get_master_branch(existing_package.giturl))
                    elif existing_package.type == 'pip':
                        if existing_package.name == 'docassemble.webapp' and existing_package.limitation and not limitation:
                            existing_package.limitation = None
                            db.session.commit()
                        install_pip_package(existing_package.name, existing_package.limitation)
        result = docassemble.webapp.worker.update_packages.apply_async(
            link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(target)))
        session['taskwait'] = result.id
        session['serverstarttime'] = START_TIME
        return redirect(url_for('update_package_wait'))
    if request.method == 'POST' and form.validate_on_submit():
        if 'zipfile' in request.files and request.files['zipfile'].filename:
            try:
                the_file = request.files['zipfile']
                filename = secure_filename(the_file.filename)
                file_number = get_new_file_number(None, filename)
                saved_file = SavedFile(file_number, extension='zip', fix=True, should_not_exist=True)
                file_set_attributes(file_number, private=False, persistent=True)
                zippath = saved_file.path
                the_file.save(zippath)
                saved_file.save()
                saved_file.finalize()
                pkgname = get_package_name_from_zip(zippath)
                if user_can_edit_package(pkgname=pkgname):
                    install_zip_package(pkgname, file_number)
                    result = docassemble.webapp.worker.update_packages.apply_async(
                        link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(pkgname)))
                    session['taskwait'] = result.id
                    session['serverstarttime'] = START_TIME
                    return redirect(url_for('update_package_wait'))
                else:
                    flash(word("You do not have permission to install this package."), 'error')
            except Exception as errMess:
                flash("Error of type " + str(type(errMess)) + " processing upload: " + str(errMess), "error")
        else:
            if form.giturl.data:
                giturl = form.giturl.data.strip().rstrip('/')
                branch = form.gitbranch.data.strip()
                if not branch:
                    branch = get_master_branch(giturl)
                packagename = re.sub(r'/*$', '', giturl)
                packagename = re.sub(r'^git+', '', packagename)
                packagename = re.sub(r'#.*', '', packagename)
                packagename = re.sub(r'\.git$', '', packagename)
                packagename = re.sub(r'.*/', '', packagename)
                packagename = re.sub(r'^docassemble-', 'docassemble.', packagename)
                if user_can_edit_package(giturl=giturl) and user_can_edit_package(pkgname=packagename):
                    install_git_package(packagename, giturl, branch)
                    result = docassemble.webapp.worker.update_packages.apply_async(
                        link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(packagename)))
                    session['taskwait'] = result.id
                    session['serverstarttime'] = START_TIME
                    return redirect(url_for('update_package_wait'))
                else:
                    flash(word("You do not have permission to install this package."), 'error')
            elif form.pippackage.data:
                m = re.match(r'([^>=<]+)([>=<]+.+)', form.pippackage.data)
                if m:
                    packagename = m.group(1)
                    limitation = m.group(2)
                else:
                    packagename = form.pippackage.data
                    limitation = None
                packagename = re.sub(r'[^A-Za-z0-9\_\-\.]', '', packagename)
                if user_can_edit_package(pkgname=packagename):
                    install_pip_package(packagename, limitation)
                    result = docassemble.webapp.worker.update_packages.apply_async(
                        link=docassemble.webapp.worker.reset_server.s(run_create=should_run_create(packagename)))
                    session['taskwait'] = result.id
                    session['serverstarttime'] = START_TIME
                    return redirect(url_for('update_package_wait'))
                else:
                    flash(word("You do not have permission to install this package."), 'error')
            else:
                flash(word('You need to supply a Git URL, upload a file, or supply the name of a package on PyPI.'),
                      'error')
    package_list, package_auth = get_package_info(exclude_core=True)
    form.pippackage.data = None
    form.giturl.data = None
    extra_js = """
    <script>
      var default_branch = """ + json.dumps(branch if branch else 'null') + """;
      function get_branches(){
        var elem = $("#gitbranch");
        elem.empty();
        var opt = $("<option><\/option>");
        opt.attr("value", "").text("Not applicable");
        elem.append(opt);
        var github_url = $("#giturl").val();
        if (!github_url){
          return;
        }
        $.get(""" + json.dumps(url_for('get_git_branches')) + """, { url: github_url }, "json")
        .done(function(data){
          //console.log(data);
          if (data.success){
            var n = data.result.length;
            if (n > 0){
              var default_to_use = default_branch;
              var to_try = [default_branch, """ + json.dumps(GITHUB_BRANCH) + """, 'master', 'main'];
            outer:
              for (var j = 0; j < 4; j++){
                for (var i = 0; i < n; i++){
                  if (data.result[i].name == to_try[j]){
                    default_to_use = to_try[j];
                    break outer;
                  }
                }
              }
              elem.empty();
              for (var i = 0; i < n; i++){
                opt = $("<option><\/option>");
                opt.attr("value", data.result[i].name).text(data.result[i].name);
                if (data.result[i].name == default_to_use){
                  opt.prop('selected', true);
                }
                $(elem).append(opt);
              }
            }
          }
        });
      }
      $( document ).ready(function() {
        get_branches();
        $("#giturl").on('change', get_branches);
      });
      $('#zipfile').on('change', function(){
        var fileName = $(this).val();
        fileName = fileName.replace(/.*\\\\/, '');
        fileName = fileName.replace(/.*\\//, '');
        $(this).next('.custom-file-label').html(fileName);
      });
    </script>"""
    python_version = daconfig.get('python version', word('Unknown'))
    version = word("Current") + ': <span class="badge bg-primary">' + str(python_version) + '</span>'
    dw_status = pypi_status('docassemble.webapp')
    if daconfig.get('stable version', False):
        if not dw_status['error'] and 'info' in dw_status and 'releases' in dw_status['info'] and isinstance(
                dw_status['info']['releases'], dict):
            stable_version = LooseVersion('1.1')
            latest_version = None
            for version_number, version_info in dw_status['info']['releases'].items():
                version_number_loose = LooseVersion(version_number)
                if version_number_loose >= stable_version:
                    continue
                if latest_version is None or version_number_loose > LooseVersion(latest_version):
                    latest_version = version_number
            if latest_version != str(python_version):
                version += ' ' + word("Available") + ': <span class="badge bg-success">' + latest_version + '</span>'
    else:
        if not dw_status['error'] and 'info' in dw_status and 'info' in dw_status['info'] and 'version' in \
                dw_status['info']['info'] and dw_status['info']['info']['version'] != str(python_version):
            version += ' ' + word("Available") + ': <span class="badge bg-success">' + dw_status['info']['info'][
                'version'] + '</span>'
    allowed_to_upgrade = current_user.has_role('admin') or user_can_edit_package(pkgname='docassemble.webapp')
    if daconfig.get('stable version', False):
        limitation = '<1.1'
    else:
        limitation = ''
    if daconfig.get('stable version', False):
        limitation = '<1.1.0'
    else:
        limitation = ''
    allowed_to_upgrade = current_user.has_role('admin') or user_can_edit_package(pkgname='docassemble.webapp')
    response = make_response(
        render_template('pages/update_package.html', version_warning=version_warning, bodyclass='daadminbody',
                        form=form, package_list=sorted(package_list, key=lambda y: (
            0 if y.package.name.startswith('docassemble') else 1, y.package.name.lower())),
                        tab_title=word('Package Management'), page_title=word('Package Management'),
                        extra_js=Markup(extra_js), version=Markup(version), allowed_to_upgrade=allowed_to_upgrade,
                        limitation=limitation), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response



@admin.route('/logfile/<filename>', methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def logfile(filename):
    if LOGSERVER is None:
        the_file = os.path.join(LOG_DIRECTORY, filename)
        if not os.path.isfile(the_file):
            return ('File not found', 404)
    else:
        h = httplib2.Http()
        resp, content = h.request("http://" + LOGSERVER + ':8082', "GET")
        try:
            the_file, headers = urlretrieve("http://" + LOGSERVER + ':8082/' + urllibquote(filename))
        except:
            return ('File not found', 404)
    response = send_file(the_file, as_attachment=True, mimetype='text/plain', attachment_filename=filename,
                         cache_timeout=0)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def call_sync():
    if not USING_SUPERVISOR:
        return
    args = [SUPERVISORCTL, '-s', 'http://localhost:9001', 'start', 'sync']
    result = subprocess.run(args, check=False).returncode
    if result == 0:
        pass
    else:
        logmessage("call_sync: call to supervisorctl on " + hostname + " was not successful")
        abort(404)
    in_process = 1
    counter = 10
    check_args = [SUPERVISORCTL, '-s', 'http://localhost:9001', 'status', 'sync']
    while in_process == 1 and counter > 0:
        output, err = Popen(check_args, stdout=PIPE, stderr=PIPE).communicate()
        if not re.search(r'RUNNING', output.decode()):
            in_process = 0
        else:
            time.sleep(1)
        counter -= 1

@admin.route('/logs', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def logs():
    setup_translation()
    form = LogForm(request.form)
    use_zip = true_or_false(request.args.get('zip', None))
    if LOGSERVER is None and use_zip:
        timezone = get_default_timezone()
        zip_archive = tempfile.NamedTemporaryFile(mode="wb", prefix="datemp", suffix=".zip", delete=False)
        zf = zipfile.ZipFile(zip_archive, mode='w')
        for f in os.listdir(LOG_DIRECTORY):
            zip_path = os.path.join(LOG_DIRECTORY, f)
            if f.startswith('.') or not os.path.isfile(zip_path):
                continue
            info = zipfile.ZipInfo(f)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.date_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(zip_path)).replace(
                tzinfo=datetime.timezone.utc).astimezone(zoneinfo.ZoneInfo(timezone)).timetuple()
            with open(zip_path, 'rb') as fp:
                zf.writestr(info, fp.read())
        zf.close()
        zip_file_name = re.sub(r'[^A-Za-z0-9_]+', '', current_app.config['APP_NAME']) + '_logs.zip'
        response = send_file(zip_archive.name, mimetype='application/zip', as_attachment=True,
                             attachment_filename=zip_file_name)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    the_file = request.args.get('file', None)
    if the_file is not None:
        the_file = secure_filename_spaces_ok(the_file)
    default_filter_string = request.args.get('q', '')
    if request.method == 'POST' and form.file_name.data:
        the_file = form.file_name.data
    if the_file is not None and (the_file.startswith('.') or the_file.startswith('/') or the_file == ''):
        the_file = None
    if the_file is not None:
        the_file = secure_filename_spaces_ok(the_file)
    total_bytes = 0
    if LOGSERVER is None:
        call_sync()
        files = []
        for f in os.listdir(LOG_DIRECTORY):
            path = os.path.join(LOG_DIRECTORY, f)
            if not os.path.isfile(path):
                continue
            files.append(f)
            total_bytes += os.path.getsize(path)
        files = sorted(files)
        total_bytes = humanize.naturalsize(total_bytes)
        if the_file is None and len(files):
            if 'docassemble.log' in files:
                the_file = 'docassemble.log'
            else:
                the_file = files[0]
        if the_file is not None:
            filename = os.path.join(LOG_DIRECTORY, the_file)
    else:
        h = httplib2.Http()
        resp, content = h.request("http://" + LOGSERVER + ':8082', "GET")
        if int(resp['status']) >= 200 and int(resp['status']) < 300:
            files = [f for f in content.decode().split("\n") if f != '' and f is not None]
        else:
            return ('File not found', 404)
        if len(files) > 0:
            if the_file is None:
                the_file = files[0]
            filename, headers = urlretrieve("http://" + LOGSERVER + ':8082/' + urllibquote(the_file))
    if len(files) > 0 and not os.path.isfile(filename):
        flash(word("The file you requested does not exist."), 'error')
        if len(files) > 0:
            the_file = files[0]
            filename = os.path.join(LOG_DIRECTORY, files[0])
    if len(files) > 0:
        if request.method == 'POST' and form.submit.data and form.filter_string.data:
            default_filter_string = form.filter_string.data
        try:
            reg_exp = re.compile(default_filter_string)
        except:
            flash(word("The regular expression you provided could not be parsed."), 'error')
            default_filter_string = ''
        if default_filter_string == '':
            try:
                lines = tailer.tail(open(filename, encoding='utf-8'), 30)
            except:
                lines = [word('Unable to read log file; please download.')]
        else:
            temp_file = tempfile.NamedTemporaryFile(mode='a+', encoding='utf-8')
            with open(filename, 'r', encoding='utf-8') as fp:
                for line in fp:
                    if reg_exp.search(line):
                        temp_file.write(line)
            temp_file.seek(0)
            try:
                lines = tailer.tail(temp_file, 30)
            except:
                lines = [word('Unable to read log file; please download.')]
            temp_file.close()
        content = "\n".join(map(lambda x: x, lines))
    else:
        content = "No log files available"
    show_download_all = bool(LOGSERVER is None)
    response = make_response(
        render_template('pages/logs.html', version_warning=version_warning, bodyclass='daadminbody',
                        tab_title=word("Logs"), page_title=word("Logs"), form=form, files=files, current_file=the_file,
                        content=content, default_filter_string=default_filter_string,
                        show_download_all=show_download_all, total_bytes=total_bytes), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@admin.route('/observer', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'advocate'])
def observer():
    setup_translation()
    session['observer'] = 1
    i = request.args.get('i', None)
    uid = request.args.get('uid', None)
    userid = request.args.get('userid', None)
    observation_script = """
    <script>
      var daMapInfo = null;
      var daWhichButton = null;
      var daSendChanges = false;
      var daNoConnectionCount = 0;
      var daConnected = false;
      var daConfirmed = false;
      var daObserverChangesInterval = null;
      var daInitialized = false;
      var daShowingSpinner = false;
      var daSpinnerTimeout = null;
      var daShowingHelp = false;
      var daInformedChanged = false;
      var daDisable = null;
      var daCsrf = """ + json.dumps(generate_csrf()) + """;
      var daShowIfInProcess = false;
      var daFieldsToSkip = ['_checkboxes', '_empties', '_ml_info', '_back_one', '_files', '_files_inline', '_question_name', '_the_image', '_save_as', '_success', '_datatypes', '_event', '_visible', '_tracker', '_track_location', '_varnames', '_next_action', '_next_action_to_set', 'ajax', 'json', 'informed', 'csrf_token', '_action', '_order_changes', '_collect', '_null_question'];
      var daVarLookup = Object();
      var daVarLookupRev = Object();
      var daVarLookupMulti = Object();
      var daVarLookupRevMulti = Object();
      var daVarLookupSelect = Object();
      var daTargetDiv = "#dabody";
      var daLocationBar = """ + json.dumps(url_for('index', i=i)) + """;
      var daPostURL = """ + json.dumps(url_for('index', i=i, _external=True)) + """;
      var daYamlFilename = """ + json.dumps(i) + """;
      var daGlobalEval = eval;
      var daShowHideHappened = false;
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
      function daDisableIfNotHidden(query, value){
        $(query).each(function(){
          var showIfParent = $(this).parents('.dashowif, .dajsshowif');
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
        scrollTarget = $(target).first().offset().top - 60;
        if (scrollTarget != null){
          $("html, body").animate({
            scrollTop: scrollTarget
          }, 500);
        }
      }
      function dabtoa(str) {
        return window.btoa(str).replace(/[\\n=]/g, '');
      }
      function daatob(str) {
        return window.atob(str);
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
        var elem = getField(fieldName);
        if (elem == null){
          return null;
        }
        var showifParents = $(elem).parents(".dajsshowif");
        if (showifParents.length !== 0 && !($(showifParents[0]).data("isVisible") == '1')){
          theVal = null;
        }
        else if ($(elem).attr('type') == "checkbox"){
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
        else{
          theVal = $(elem).val();
        }
        return theVal;
      }
      var da_val = val;
      window.daTurnOnControl = function(){
        //console.log("Turning on control");
        daSendChanges = true;
        daNoConnectionCount = 0;
        daResetPushChanges();
        daSocket.emit('observerStartControl', {uid: """ + json.dumps(uid) + """, i: """ + json.dumps(
        i) + """, userid: """ + json.dumps(str(userid)) + """});
      }
      window.daTurnOffControl = function(){
        //console.log("Turning off control");
        if (!daSendChanges){
          //console.log("Already turned off");
          return;
        }
        daSendChanges = false;
        daConfirmed = false;
        daStopPushChanges();
        daSocket.emit('observerStopControl', {uid: """ + json.dumps(uid) + """, i: """ + json.dumps(
        i) + """, userid: """ + json.dumps(str(userid)) + """});
        return;
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
        //console.log("observer: daValidationHandler");
        return(false);
      }
      function daStopPushChanges(){
        if (daObserverChangesInterval != null){
          clearInterval(daObserverChangesInterval);
        }
      }
      function daResetPushChanges(){
        if (daObserverChangesInterval != null){
          clearInterval(daObserverChangesInterval);
        }
        daObserverChangesInterval = setInterval(daPushChanges, """ + str(CHECKIN_INTERVAL) + """);
      }
      function daPushChanges(){
        //console.log("Pushing changes");
        if (daObserverChangesInterval != null){
          clearInterval(daObserverChangesInterval);
        }
        if (!daSendChanges || !daConnected){
          return;
        }
        daObserverChangesInterval = setInterval(daPushChanges, """ + str(CHECKIN_INTERVAL) + """);
        daSocket.emit('observerChanges', {uid: """ + json.dumps(uid) + """, i: """ + json.dumps(
        i) + """, userid: """ + json.dumps(str(userid)) + """, parameters: JSON.stringify($("#daform").serializeArray())});
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
      function daSubmitter(event){
        if (!daSendChanges || !daConnected){
          event.preventDefault();
          return false;
        }
        var theAction = null;
        if ($(this).hasClass('da-review-action')){
          theAction = $(this).data('action');
        }
        var embeddedJs = $(this).data('js');
        var embeddedAction = $(this).data('embaction');
        var linkNum = $(this).data('linknum');
        var theId = $(this).attr('id');
        if (theId == 'dapagetitle'){
          theId = 'daquestionlabel';
        }
        var theName = $(this).attr('name');
        var theValue = $(this).val();
        var skey;
        if (linkNum){
          skey = 'a[data-linknum="' + linkNum + '"]';
        }
        else if (embeddedAction){
          skey = 'a[data-embaction="' + embeddedAction.replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\\\$1') + '"]';
        }
        else if (theAction){
          skey = 'a[data-action="' + theAction.replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\\\$1') + '"]';
        }
        else if (theId){
          skey = '#' + theId.replace(/(:|\.|\[|\]|,|=|\/|\")/g, '\\\\$1');
        }
        else if (theName){
          skey = '#' + $(this).parents("form").attr('id') + ' ' + $(this).prop('tagName').toLowerCase() + '[name="' + theName.replace(/(:|\.|\[|\]|,|=|\/)/g, '\\\\$1') + '"]';
          if (typeof theValue !== 'undefined'){
            skey += '[value="' + theValue + '"]'
          }
        }
        else{
          skey = '#' + $(this).parents("form").attr('id') + ' ' + $(this).prop('tagName').toLowerCase() + '[type="submit"]';
        }
        //console.log("Need to click on " + skey);
        if (daObserverChangesInterval != null && embeddedJs == null && theId != "dabackToQuestion" && theId != "dahelptoggle" && theId != "daquestionlabel"){
          clearInterval(daObserverChangesInterval);
        }
        daSocket.emit('observerChanges', {uid: """ + json.dumps(uid) + """, i: """ + json.dumps(
        i) + """, userid: """ + json.dumps(str(userid)) + """, clicked: skey, parameters: JSON.stringify($("#daform").serializeArray())});
        if (embeddedJs != null){
          //console.log("Running the embedded js");
          daGlobalEval(decodeURIComponent(embeddedJs));
        }
        if (theId != "dabackToQuestion" && theId != "dahelptoggle" && theId != "daquestionlabel"){
          event.preventDefault();
          return false;
        }
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
      function daShowHelpTab(){
          //$('#dahelptoggle').tab('show');
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
      function JSON_stringify(s){
         var json = JSON.stringify(s);
         return json.replace(/[\\u007f-\\uffff]/g,
            function(c) {
              return '\\\\u'+('0000'+c.charCodeAt(0).toString(16)).slice(-4);
            }
         );
      }
      function url_action(action, args){
        //redo?
        if (args == null){
            args = {};
        }
        data = {action: action, arguments: args};
        var url;
        if (daJsEmbed){
          url = daPostURL + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        else{
          url = daLocationBar + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        return url;
      }
      var da_url_action = url_action;
      function action_call(action, args, callback){
        //redo?
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
          url = daLocationBar + "&action=" + encodeURIComponent(btoa(JSON_stringify(data)))
        }
        return $.ajax({
          type: "GET",
          url: url,
          success: callback,
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
        //redo
        if (args == null){
            args = {};
        }
        var data = {action: action, arguments: args};
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        return $.ajax({
          type: "POST",
          url: daLocationBar,
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
        //redo
        //console.log("action_perform_with_next: " + action + " | " + next_data)
        if (args == null){
            args = {};
        }
        var data = {action: action, arguments: args};
        daSpinnerTimeout = setTimeout(daShowSpinner, 1000);
        return $.ajax({
          type: "POST",
          url: daLocationBar,
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
          url: """ + '"' + url_for('get_variables', i=i) + '"' + """,
          success: callback,
          error: function(xhr, status, error){
            setTimeout(function(){
              daProcessAjaxError(xhr, status, error);
            }, 0);
          }
        });
      }
      var da_get_interview_variables = get_interview_variables;
      function daInitialize(doScroll){
        if (daSpinnerTimeout != null){
          clearTimeout(daSpinnerTimeout);
          daSpinnerTimeout = null;
        }
        if (daShowingSpinner){
          daHideSpinner();
        }
        $('button[type="submit"], input[type="submit"], a.da-review-action, #dabackToQuestion, #daquestionlabel, #dapagetitle, #dahelptoggle, a[data-linknum], a[data-embaction], #dabackbutton').click(daSubmitter);
        $(".da-to-labelauty").labelauty({ class: "labelauty da-active-invisible dafullwidth" });
        //$(".da-to-labelauty-icon").labelauty({ label: false });
        var navMain = $("#danavbar-collapse");
        navMain.on("click", "a", null, function () {
          if (!($(this).hasClass("dropdown-toggle"))){
            navMain.collapse('hide');
          }
        });
        var daPopoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
        var daPopoverList = daPopoverTriggerList.map(function (daPopoverTriggerEl) {
          return new bootstrap.Popover(daPopoverTriggerEl, {trigger: "focus", html: true});
        });
        $("input.danota-checkbox").click(function(){
          $(this).parent().find('input.danon-nota-checkbox').each(function(){
            if ($(this).prop('checked') != false){
              $(this).prop('checked', false);
              $(this).trigger('change');
            }
          });
        });
        $("input.danon-nota-checkbox").click(function(){
          $(this).parent().find('input.danota-checkbox').each(function(){
            if ($(this).prop('checked') != false){
              $(this).prop('checked', false);
              $(this).trigger('change');
            }
          });
        });
        $("input.dainput-embedded").on('keyup', daAdjustInputWidth);
        $("input.dainput-embedded").each(daAdjustInputWidth);
        // $(".dahelptrigger").click(function(e) {
        //   e.preventDefault();
        //   $(this).tab('show');
        // });
        //$("#daquestionlabel").click(function(e) {
        //  e.preventDefault();
        //  $(this).tab('show');
        //});
        $('#dapagetitle').click(function(e) {
          if ($(this).prop('href') == '#'){
            e.preventDefault();
            //$('#daquestionlabel').tab('show');
          }
        });
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
        $("#dahelp").on("shown.bs.tab", function(){
          window.scrollTo(0, 1);
          $("#dahelptoggle").removeClass('daactivetext')
          $("#dahelptoggle").blur();
        });
        $("#dasourcetoggle").on("click", function(){
          $(this).parent().toggleClass("active");
          $(this).blur();
        });
        $('#dabackToQuestion').click(function(event){
          $('#daquestionlabel').tab('show');
        });
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
        // daDisable = setTimeout(function(){
        //   $("#daform").find('button[type="submit"]').prop("disabled", true);
        //   //$("#daform").find(':input').prop("disabled", true);
        // }, 1);
        $("#daform").each(function(){
          $(this).find(':input').on('change', daPushChanges);
        });
        daInitialized = true;
        daShowingHelp = 0;
        setTimeout(function(){
          $("#daflash .alert-success").hide(300, function(){
            $(self).remove();
          });
        }, 3000);
        $(document).trigger('daPageLoad');
      }
      $( document ).ready(function(){
        daInitialize(1);
        var daDefaultAllowList = bootstrap.Tooltip.Default.allowList;
        daDefaultAllowList['*'].push('style');
        daDefaultAllowList['a'].push('style');
        daDefaultAllowList['img'].push('style');
        $( window ).bind('unload', function() {
          if (daSocket != null && daSocket.connected){
            daSocket.emit('terminate');
          }
        });
        if (location.protocol === 'http:' || document.location.protocol === 'http:'){
            daSocket = io.connect('http://' + document.domain + '/observer', {path: '""" + ROOT + """ws/socket.io', query: "i=" + daYamlFilename});
        }
        if (location.protocol === 'https:' || document.location.protocol === 'https:'){
            daSocket = io.connect('https://' + document.domain + '/observer', {path: '""" + ROOT + """ws/socket.io', query: "i=" + daYamlFilename});
        }
        if (typeof daSocket !== 'undefined') {
            daSocket.on('connect', function() {
                //console.log("Connected!");
                daSocket.emit('observe', {uid: """ + json.dumps(uid) + """, i: daYamlFilename, userid: """ + json.dumps(
        str(userid)) + """});
                daConnected = true;
            });
            daSocket.on('terminate', function() {
                //console.log("Terminating socket");
                daSocket.disconnect();
            });
            daSocket.on('disconnect', function() {
                //console.log("Disconnected socket");
                //daSocket = null;
            });
            daSocket.on('stopcontrolling', function(data) {
                window.parent.daStopControlling(data.key);
            });
            daSocket.on('start_being_controlled', function(data) {
                //console.log("Got start_being_controlled");
                daConfirmed = true;
                daPushChanges();
                window.parent.daGotConfirmation(data.key);
            });
            daSocket.on('abortcontrolling', function(data) {
                //console.log("Got abortcontrolling");
                //daSendChanges = false;
                //daConfirmed = false;
                //daStopPushChanges();
                window.parent.daAbortControlling(data.key);
            });
            daSocket.on('noconnection', function(data) {
                //console.log("warning: no connection");
                if (daNoConnectionCount++ > 2){
                    //console.log("error: no connection");
                    window.parent.daStopControlling(data.key);
                }
            });
            daSocket.on('newpage', function(incoming) {
                //console.log("Got newpage")
                var data = incoming.obj;
                $(daTargetDiv).html(data.body);
                $(daTargetDiv).parent().removeClass();
                $(daTargetDiv).parent().addClass(data.bodyclass);
                daInitialize(1);
                var tempDiv = document.createElement('div');
                tempDiv.innerHTML = data.extra_scripts;
                var scripts = tempDiv.getElementsByTagName('script');
                for (var i = 0; i < scripts.length; i++){
                  if (scripts[i].src != ""){
                    daAddScriptToHead(scripts[i].src);
                  }
                  else{
                    daGlobalEval(scripts[i].innerHTML);
                  }
                }
                for (var i = 0; i < data.extra_css.length; i++){
                  $("head").append(data.extra_css[i]);
                }
                document.title = data.browser_title;
                if ($("html").attr("lang") != data.lang){
                  $("html").attr("lang", data.lang);
                }
                daPushChanges();
            });
            daSocket.on('pushchanges', function(data) {
                //console.log("Got pushchanges: " + JSON.stringify(data));
                var valArray = Object();
                var values = data.parameters;
                for (var i = 0; i < values.length; i++) {
                    valArray[values[i].name] = values[i].value;
                }
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
            });
        }
        daObserverChangesInterval = setInterval(daPushChanges, """ + str(CHECKIN_INTERVAL) + """);
    });
    </script>
"""
    the_key = 'da:html:uid:' + str(uid) + ':i:' + str(i) + ':userid:' + str(userid)
    html = r.get(the_key)
    if html is not None:
        obj = json.loads(html.decode())
    else:
        logmessage("observer: failed to load JSON from key " + the_key)
        obj = {}
    page_title = word('Observation')
    output = standard_html_start(interview_language=obj.get('lang', 'en'), debug=DEBUG,
                                 bootstrap_theme=obj.get('bootstrap_theme', None))
    output += obj.get('global_css', '') + "\n" + indent_by("".join(obj.get('extra_css', [])), 4)
    output += '\n    <title>' + page_title + '</title>\n  </head>\n  <body class="' + obj.get('bodyclass',
                                                                                              'dabody da-pad-for-navbar da-pad-for-footer') + '">\n  <div id="dabody">\n  '
    output += obj.get('body', '')
    output += "    </div>\n    </div>" + standard_scripts(
        interview_language=obj.get('lang', 'en')) + observation_script + "\n    " + "".join(
        obj.get('extra_scripts', [])) + "\n  </body>\n</html>"
    response = make_response(output.encode('utf-8'), '200 OK')
    response.headers['Content-type'] = 'text/html; charset=utf-8'
    return response


@admin.route('/get_git_branches', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def get_git_branches():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if 'url' not in request.args:
        return ('File not found', 404)
    giturl = request.args['url'].strip()
    try:
        return jsonify(dict(success=True, result=get_branches_of_repo(giturl)))
    except Exception as err:
        return jsonify(dict(success=False, reason=str(err)))


@admin.route("/varsreport", methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def variables_report():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    playground = SavedFile(current_user.id, fix=True, section='playground')
    the_file = request.args.get('file', None)
    if the_file is not None:
        the_file = secure_filename_spaces_ok(the_file)
    current_project = werkzeug.utils.secure_filename(request.args.get('project', 'default'))
    the_directory = directory_for(playground, current_project)
    files = sorted([f for f in os.listdir(the_directory) if
                    os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    if len(files) == 0:
        return jsonify(success=False, reason=1)
    if the_file is None or the_file not in files:
        return jsonify(success=False, reason=2)
    interview_source = docassemble.base.parse.interview_source_from_string(
        'docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + the_file)
    interview_source.set_testing(True)
    interview = interview_source.get_interview()
    ensure_ml_file_exists(interview, the_file, current_project)
    yaml_file = 'docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + the_file
    the_current_info = current_info(yaml=yaml_file, req=request, action=None, device_id=request.cookies.get('ds', None))
    docassemble.base.functions.this_thread.current_info = the_current_info
    interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
    variables_html, vocab_list, vocab_dict = get_vars_in_use(interview, interview_status, debug_mode=False,
                                                             current_project=current_project)
    results = []
    result_dict = {}
    for name in vocab_list:
        if name in ('x', 'row_item', 'i', 'j', 'k', 'l', 'm', 'n') or name.startswith('x.') or name.startswith(
                'x[') or name.startswith('row_item.'):
            continue
        result = dict(name=name, questions=[])
        results.append(result)
        result_dict[name] = result
    for question in interview.questions_list:
        names_seen = {}
        for the_type, the_set in (
                ('in mako', question.mako_names), ('mentioned in', question.names_used),
                ('defined by', question.fields_used)):
            for name in the_set:
                the_name = name
                subnames = [the_name]
                while True:
                    if re.search(r'\[[^\]]\]$', the_name):
                        the_name = re.sub(r'\[[^\]]\]$', '', the_name)
                    elif '.' in the_name:
                        the_name = re.sub(r'\.[^\.]*$', '', the_name)
                    else:
                        break
                    subnames.append(the_name)
                on_first = True
                for subname in subnames:
                    if the_type == 'defined by' and not on_first:
                        the_type = 'mentioned in'
                    on_first = False
                    if subname not in result_dict:
                        continue
                    if subname not in names_seen:
                        names_seen[subname] = dict(yaml_file=question.from_source.path,
                                                   source_code=question.source_code.strip(), usage=[])
                        result_dict[subname]['questions'].append(names_seen[subname])
                    if the_type not in names_seen[subname]['usage']:
                        names_seen[subname]['usage'].append(the_type)
    return jsonify(success=True, yaml_file=yaml_file, items=results)
