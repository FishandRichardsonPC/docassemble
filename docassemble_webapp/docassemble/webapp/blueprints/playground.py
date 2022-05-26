import datetime
import filecmp
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import time
import zipfile
import ruamel.yaml
from io import TextIOWrapper
from urllib.parse import quote as urllibquote
from urllib.request import urlretrieve

import docassemble.base.DA
import docassemble.base.astparser
import docassemble.base.core
import docassemble.base.functions
import docassemble.base.interview_cache
import docassemble.base.interview_cache
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
from docassemble.base.error import DAError
from docassemble.base.functions import get_default_timezone, word
from docassemble.base.generate_key import random_string
from docassemble.base.logger import logmessage
from docassemble.base.pandoc import convertible_extensions, convertible_mimetypes, word_to_markdown
from docassemble.webapp.app_object import csrf
from docassemble.webapp.authentication import current_info, get_github_flow, get_next_link, get_ssh_keys, \
    needs_to_change_password
from docassemble.webapp.backend import Message, add_project, directory_for, file_set_attributes, fix_ml_files, \
    get_info_from_file_reference, get_new_file_number, project_name, url_for, write_ml_source
from docassemble.webapp.config_server import GITHUB_BRANCH, NOTIFICATION_CONTAINER, NOTIFICATION_MESSAGE, START_TIME, \
    default_playground_yaml, document_match, fix_initial, keymap, ok_extensions, ok_mimetypes, version_warning
from docassemble.webapp.daredis import r
from docassemble.webapp.develop import CreatePlaygroundPackageForm, DeleteProject, NewProject, PlaygroundFilesEditForm, \
    PlaygroundFilesForm, PlaygroundForm, PlaygroundPackagesForm, PlaygroundUploadForm, PullPlaygroundPackage, \
    RenameProject
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.onedrive import get_od_folder
from docassemble.webapp.package import get_master_branch, get_package_info, install_zip_package, pypi_status
from docassemble.webapp.playground import PlaygroundSection
from docassemble.webapp.setup import da_version
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.user_util import api_verify
from docassemble.webapp.util import RedisCredStorage, ensure_ml_file_exists, get_current_project, \
    get_vars_in_use, indent_by, jsonify_restart_task, jsonify_with_status, name_of_user, restart_all, safeid, \
    secure_filename, secure_filename_spaces_ok, should_run_create, splitall, true_or_false, variables_js
from flask import Blueprint, current_app
from docassemble.webapp.config_server import fix_tabs

if not in_celery:
    import docassemble.webapp.worker

import apiclient
from dateutil import tz
from docassemble_flask_user import login_required, roles_required
from flask import make_response, render_template, request, session, send_file, redirect, flash, Markup, jsonify, \
    Response
from flask_cors import cross_origin
from flask_login import current_user
import httplib2
import pkg_resources
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import YamlLexer
from backports import zoneinfo
import werkzeug.exceptions
import werkzeug.utils
import yaml
from docassemble.webapp.google_api import get_gd_folder

playground = Blueprint('playground', __name__)


def rename_gd_project(old_project, new_project):
    the_folder = get_gd_folder()
    if the_folder is None:
        logmessage('rename_gd_project: folder not configured')
        return False
    storage = RedisCredStorage(app='googledrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('rename_gd_project: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    service = apiclient.discovery.build('drive', 'v3', http=http)
    response = service.files().get(fileId=the_folder, fields="mimeType, id, name, trashed").execute()
    trashed = response.get('trashed', False)
    the_mime_type = response.get('mimeType', None)
    if trashed is True or the_mime_type != "application/vnd.google-apps.folder":
        logmessage('rename_gd_project: folder did not exist')
        return False
    for section in ['static', 'templates', 'questions', 'modules', 'sources']:
        logmessage("rename_gd_project: section is " + section)
        subdir = None
        page_token = None
        while True:
            response = service.files().list(spaces="drive", pageToken=page_token,
                                            fields="nextPageToken, files(id, name)",
                                            q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                                section) + "' and '" + str(the_folder) + "' in parents").execute()
            for the_file in response.get('files', []):
                if 'id' in the_file:
                    subdir = the_file['id']
                    break
            page_token = response.get('nextPageToken', None)
            if subdir is not None or page_token is None:
                break
        if subdir is None:
            logmessage('rename_gd_project: section ' + str(section) + ' could not be found')
            continue
        subsubdir = None
        page_token = None
        while True:
            response = service.files().list(spaces="drive", pageToken=page_token,
                                            fields="nextPageToken, files(id, name)",
                                            q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                                old_project) + "' and '" + str(subdir) + "' in parents").execute()
            for the_file in response.get('files', []):
                if 'id' in the_file:
                    subsubdir = the_file['id']
                    break
            page_token = response.get('nextPageToken', None)
            if subsubdir is not None or page_token is None:
                break
        if subsubdir is None:
            logmessage('rename_gd_project: project ' + str(old_project) + ' could not be found in ' + str(section))
            continue
        metadata = {'name': new_project}
        service.files().update(fileId=subsubdir, body=metadata, fields='name').execute()
        logmessage('rename_gd_project: folder ' + str(old_project) + ' renamed in section ' + str(section))
    return True


def trash_gd_project(old_project):
    the_folder = get_gd_folder()
    if the_folder is None:
        logmessage('trash_gd_project: folder not configured')
        return False
    storage = RedisCredStorage(app='googledrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('trash_gd_project: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    service = apiclient.discovery.build('drive', 'v3', http=http)
    response = service.files().get(fileId=the_folder, fields="mimeType, id, name, trashed").execute()
    trashed = response.get('trashed', False)
    the_mime_type = response.get('mimeType', None)
    if trashed is True or the_mime_type != "application/vnd.google-apps.folder":
        logmessage('trash_gd_project: folder did not exist')
        return False
    for section in ['static', 'templates', 'questions', 'modules', 'sources']:
        subdir = None
        page_token = None
        while True:
            response = service.files().list(spaces="drive", pageToken=page_token,
                                            fields="nextPageToken, files(id, name)",
                                            q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                                section) + "' and '" + str(the_folder) + "' in parents").execute()
            for the_file in response.get('files', []):
                if 'id' in the_file:
                    subdir = the_file['id']
                    break
            page_token = response.get('nextPageToken', None)
            if subdir is not None or page_token is None:
                break
        if subdir is None:
            logmessage('trash_gd_project: section ' + str(section) + ' could not be found')
            continue
        subsubdir = None
        page_token = None
        while True:
            response = service.files().list(spaces="drive", fields="nextPageToken, files(id, name)",
                                            q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                                old_project) + "' and '" + str(subdir) + "' in parents").execute()
            for the_file in response.get('files', []):
                if 'id' in the_file:
                    subsubdir = the_file['id']
                    break
            page_token = response.get('nextPageToken', None)
            if subsubdir is not None or page_token is None:
                break
        if subsubdir is None:
            logmessage('trash_gd_project: project ' + str(old_project) + ' could not be found in ' + str(section))
            continue
        service.files().delete(fileId=subsubdir).execute()
        logmessage('trash_gd_project: project ' + str(old_project) + ' deleted in section ' + str(section))
    return True


def trash_gd_file(section, filename, current_project):
    if section == 'template':
        section = 'templates'
    the_folder = get_gd_folder()
    if the_folder is None:
        logmessage('trash_gd_file: folder not configured')
        return False
    storage = RedisCredStorage(app='googledrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('trash_gd_file: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    service = apiclient.discovery.build('drive', 'v3', http=http)
    response = service.files().get(fileId=the_folder, fields="mimeType, id, name, trashed").execute()
    trashed = response.get('trashed', False)
    the_mime_type = response.get('mimeType', None)
    if trashed is True or the_mime_type != "application/vnd.google-apps.folder":
        logmessage('trash_gd_file: folder did not exist')
        return False
    subdir = None
    response = service.files().list(spaces="drive", fields="nextPageToken, files(id, name)",
                                    q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                        section) + "' and '" + str(the_folder) + "' in parents").execute()
    for the_file in response.get('files', []):
        if 'id' in the_file:
            subdir = the_file['id']
            break
    if subdir is None:
        logmessage('trash_gd_file: section ' + str(section) + ' could not be found')
        return False
    if current_project != 'default':
        response = service.files().list(spaces="drive", fields="nextPageToken, files(id, name)",
                                        q="mimeType='application/vnd.google-apps.folder' and trashed=false and name='" + str(
                                            current_project) + "' and '" + str(subdir) + "' in parents").execute()
        subdir = None
        for the_file in response.get('files', []):
            if 'id' in the_file:
                subdir = the_file['id']
                break
        if subdir is None:
            logmessage('trash_gd_file: project ' + str(current_project) + ' could not be found')
            return False
    id_of_filename = None
    response = service.files().list(spaces="drive", fields="nextPageToken, files(id, name)",
                                    q="mimeType!='application/vnd.google-apps.folder' and name='" + str(
                                        filename) + "' and '" + str(subdir) + "' in parents").execute()
    for the_file in response.get('files', []):
        if 'id' in the_file:
            id_of_filename = the_file['id']
            break
    if id_of_filename is None:
        logmessage('trash_gd_file: file ' + str(filename) + ' could not be found in ' + str(section))
        return False
    service.files().delete(fileId=id_of_filename).execute()
    logmessage('trash_gd_file: file ' + str(filename) + ' permanently deleted from ' + str(section))
    return True


def trash_od_file(section, filename, current_project):
    if section == 'template':
        section = 'templates'
    the_folder = get_od_folder()
    if the_folder is None:
        logmessage('trash_od_file: folder not configured')
        return False
    storage = RedisCredStorage(app='onedrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('trash_od_file: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(the_folder), "GET")
    if int(r['status']) != 200:
        trashed = True
    else:
        info = json.loads(content.decode())
        trashed = bool(info.get('deleted', None))
    if trashed is True or 'folder' not in info:
        logmessage('trash_od_file: folder did not exist')
        return False
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(
        the_folder) + "/children?$select=id,name,deleted,folder", "GET")
    subdir = None
    while True:
        if int(r['status']) != 200:
            logmessage('trash_od_file: could not obtain subfolders')
            return False
        info = json.loads(content.decode())
        for item in info['value']:
            if item.get('deleted', None) or 'folder' not in item:
                continue
            if item['name'] == section:
                subdir = item['id']
                break
        if subdir is not None or "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    if subdir is None:
        logmessage('trash_od_file: could not obtain subfolder')
        return False
    if current_project != 'default':
        r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(
            subdir) + "/children?$select=id,name,deleted,folder", "GET")
        subdir = None
        while True:
            if int(r['status']) != 200:
                logmessage('trash_od_file: could not obtain subfolders to find project')
                return False
            info = json.loads(content.decode())
            for item in info['value']:
                if item.get('deleted', None) or 'folder' not in item:
                    continue
                if item['name'] == current_project:
                    subdir = item['id']
                    break
            if subdir is not None or "@odata.nextLink" not in info:
                break
            r, content = http.request(info["@odata.nextLink"], "GET")
        if subdir is None:
            logmessage('trash_od_file: could not obtain subfolder')
            return False
    id_of_filename = None
    r, content = http.request(
        "https://graph.microsoft.com/v1.0/me/drive/items/" + str(subdir) + "/children?$select=id,name,deleted,folder",
        "GET")
    while True:
        if int(r['status']) != 200:
            logmessage('trash_od_file: could not obtain contents of subfolder')
            return False
        info = json.loads(content.decode())
        # logmessage("Found " + repr(info))
        for item in info['value']:
            if item.get('deleted', None) or 'folder' in item:
                continue
            if 'folder' in item:
                continue
            if item['name'] == filename:
                id_of_filename = item['id']
                break
        if id_of_filename is not None or "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(id_of_filename), "DELETE")
    if int(r['status']) != 204:
        logmessage('trash_od_file: could not delete ')
        return False
    logmessage('trash_od_file: file ' + str(filename) + ' trashed from ' + str(section))
    return True


def cloud_trash(use_gd, use_od, section, the_file, current_project):
    if use_gd:
        try:
            trash_gd_file(section, the_file, current_project)
        except Exception as the_err:
            logmessage("cloud_trash: unable to delete file on Google Drive.  " + str(the_err))
    elif use_od:
        try:
            trash_od_file(section, the_file, current_project)
        except Exception as the_err:
            try:
                logmessage("cloud_trash: unable to delete file on OneDrive.  " + str(the_err))
            except:
                logmessage("cloud_trash: unable to delete file on OneDrive.")


def fix_package_folder():
    use_gd = bool(current_app.config['USE_GOOGLE_DRIVE'] is True and get_gd_folder() is not None)
    use_od = bool(use_gd is False and current_app.config['USE_ONEDRIVE'] is True and get_od_folder() is not None)
    problem_exists = False
    area = SavedFile(current_user.id, fix=True, section='playgroundpackages')
    for f in os.listdir(area.directory):
        path = os.path.join(area.directory, f)
        if os.path.isfile(path) and not f.startswith('docassemble.') and not f.startswith('.'):
            os.rename(path, os.path.join(area.directory, 'docassemble.' + f))
            cloud_trash(use_gd, use_od, 'packages', f, 'default')
            problem_exists = True
        if os.path.isdir(path) and not f.startswith('.'):
            for e in os.listdir(path):
                if os.path.isfile(os.path.join(path, e)) and not e.startswith('docassemble.') and not e.startswith('.'):
                    os.rename(os.path.join(path, e), os.path.join(path, 'docassemble.' + e))
                    cloud_trash(use_gd, use_od, 'packages', e, f)
                    problem_exists = True
    if problem_exists:
        area.finalize()


def rename_project(user_id, old_name, new_name):
    fix_package_folder()
    for sec in ('', 'sources', 'static', 'template', 'modules', 'packages'):
        area = SavedFile(user_id, fix=True, section='playground' + sec)
        if os.path.isdir(os.path.join(area.directory, old_name)):
            os.rename(os.path.join(area.directory, old_name), os.path.join(area.directory, new_name))
            area.finalize()


def create_project(user_id, new_name):
    fix_package_folder()
    for sec in ('', 'sources', 'static', 'template', 'modules', 'packages'):
        area = SavedFile(user_id, fix=True, section='playground' + sec)
        new_dir = os.path.join(area.directory, new_name)
        if not os.path.isdir(new_dir):
            os.makedirs(new_dir)
        path = os.path.join(new_dir, '.placeholder')
        with open(path, 'a', encoding='utf-8'):
            os.utime(path, None)
        area.finalize()


def delete_project(user_id, project_name):
    fix_package_folder()
    for sec in ('', 'sources', 'static', 'template', 'modules', 'packages'):
        area = SavedFile(user_id, fix=True, section='playground' + sec)
        area.delete_directory(project_name)
        area.finalize()


def sanitize_arguments(*pargs):
    for item in pargs:
        if isinstance(item, str):
            if item.startswith('/') or item.startswith('.') or re.search(r'\s', item):
                raise Exception("Invalid parameter " + item)


def get_user_repositories(http):
    repositories = []
    resp, content = http.request("https://api.github.com/user/repos", "GET")
    if int(resp['status']) == 200:
        repositories.extend(json.loads(content.decode()))
        while True:
            next_link = get_next_link(resp)
            if next_link:
                resp, content = http.request(next_link, "GET")
                if int(resp['status']) != 200:
                    raise DAError("get_user_repositories: could not get information from next URL")
                else:
                    repositories.extend(json.loads(content.decode()))
            else:
                break
    else:
        raise DAError("playground_packages: could not get information about repositories")
    return repositories


def get_orgs_info(http):
    orgs_info = []
    resp, content = http.request("https://api.github.com/user/orgs", "GET")
    if int(resp['status']) == 200:
        orgs_info.extend(json.loads(content.decode()))
        while True:
            next_link = get_next_link(resp)
            if next_link:
                resp, content = http.request(next_link, "GET")
                if int(resp['status']) != 200:
                    raise DAError("get_orgs_info: could not get additional information about organizations")
                else:
                    orgs_info.extend(json.loads(content.decode()))
            else:
                break
    else:
        raise DAError("get_orgs_info: failed to get orgs using https://api.github.com/user/orgs")
    return orgs_info


@playground.route('/createplaygroundpackage', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def create_playground_package():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    fix_package_folder()
    current_project = get_current_project()
    form = CreatePlaygroundPackageForm(request.form)
    current_package = request.args.get('package', None)
    if current_package is not None:
        current_package = werkzeug.utils.secure_filename(current_package)
    do_pypi = request.args.get('pypi', False)
    do_github = request.args.get('github', False)
    do_install = request.args.get('install', False)
    branch = request.args.get('branch', None)
    if branch is not None:
        branch = branch.strip()
    if branch in ('', 'None'):
        branch = None
    new_branch = request.args.get('new_branch', None)
    if new_branch is not None and new_branch not in ('', 'None'):
        branch = new_branch
        branch_is_new = True
    else:
        branch_is_new = False
    force_branch_creation = False
    sanitize_arguments(do_pypi, do_github, do_install, branch, new_branch)
    if current_app.config['USE_GITHUB']:
        github_auth = r.get('da:using_github:userid:' + str(current_user.id))
    else:
        github_auth = None
    area = {}
    area['playgroundpackages'] = SavedFile(current_user.id, fix=True, section='playgroundpackages')
    if os.path.isfile(
            os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + current_package)):
        filename = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                'docassemble.' + current_package)
        info = {}
        with open(filename, 'r', encoding='utf-8') as fp:
            content = fp.read()
            info = yaml.load(content, Loader=yaml.FullLoader)
    else:
        info = {}
    if do_github:
        if not current_app.config['USE_GITHUB']:
            return ('File not found', 404)
        if current_package is None:
            logmessage('create_playground_package: package not specified')
            return ('File not found', 404)
        if not github_auth:
            logmessage('create_playground_package: github button called when github auth not enabled.')
            return ('File not found', 404)
        github_auth = github_auth.decode()
        if github_auth == '1':
            github_auth_info = dict(shared=True, orgs=True)
        else:
            github_auth_info = json.loads(github_auth)
        github_package_name = 'docassemble-' + re.sub(r'^docassemble-', r'', current_package)
        # github_package_name = re.sub(r'[^A-Za-z\_\-]', '', github_package_name)
        if github_package_name in ('docassemble-base', 'docassemble-webapp', 'docassemble-demo'):
            return ('File not found', 404)
        commit_message = request.args.get('commit_message', 'a commit')
        storage = RedisCredStorage(app='github')
        credentials = storage.get()
        if not credentials or credentials.invalid:
            state_string = random_string(16)
            session['github_next'] = json.dumps(
                dict(state=state_string, path='create_playground_package', arguments=request.args))
            flow = get_github_flow()
            uri = flow.step1_get_authorize_url(state=state_string)
            return redirect(uri)
        http = credentials.authorize(httplib2.Http())
        resp, content = http.request("https://api.github.com/user", "GET")
        if int(resp['status']) == 200:
            user_info = json.loads(content.decode())
            github_user_name = user_info.get('login', None)
            github_email = user_info.get('email', None)
        else:
            raise DAError("create_playground_package: could not get information about GitHub User")
        if github_email is None:
            resp, content = http.request("https://api.github.com/user/emails", "GET")
            if int(resp['status']) == 200:
                email_info = json.loads(content.decode())
                for item in email_info:
                    if item.get('email', None) and item.get('visibility', None) != 'private':
                        github_email = item['email']
        if github_user_name is None or github_email is None:
            raise DAError("create_playground_package: login and/or email not present in user info from GitHub")
        github_url_from_file = info.get('github_url', None)
        found = False
        found_strong = False
        commit_repository = None
        resp, content = http.request(
            "https://api.github.com/repos/" + str(github_user_name) + "/" + github_package_name, "GET")
        if int(resp['status']) == 200:
            repo_info = json.loads(content.decode('utf-8', 'ignore'))
            commit_repository = repo_info
            found = True
            if github_url_from_file is None or github_url_from_file in [repo_info['html_url'], repo_info['ssh_url']]:
                found_strong = True
        if found_strong is False and github_auth_info['shared']:
            repositories = get_user_repositories(http)
            for repo_info in repositories:
                if repo_info['name'] != github_package_name or (
                        commit_repository is not None and commit_repository.get('html_url', None) is not None and
                        commit_repository['html_url'] == repo_info['html_url']) or (
                        commit_repository is not None and commit_repository.get('ssh_url', None) is not None and
                        commit_repository['ssh_url'] == repo_info['ssh_url']):
                    continue
                if found and github_url_from_file is not None and github_url_from_file not in [repo_info['html_url'],
                                                                                               repo_info['ssh_url']]:
                    break
                commit_repository = repo_info
                found = True
                if github_url_from_file is None or github_url_from_file in [repo_info['html_url'],
                                                                            repo_info['ssh_url']]:
                    found_strong = True
                break
        if found_strong is False and github_auth_info['orgs']:
            orgs_info = get_orgs_info(http)
            for org_info in orgs_info:
                resp, content = http.request(
                    "https://api.github.com/repos/" + str(org_info['login']) + "/" + github_package_name, "GET")
                if int(resp['status']) == 200:
                    repo_info = json.loads(content.decode('utf-8', 'ignore'))
                    if found and github_url_from_file is not None and github_url_from_file not in [
                        repo_info['html_url'], repo_info['ssh_url']]:
                        break
                    commit_repository = repo_info
                    break
    file_list = {}
    the_directory = directory_for(area['playgroundpackages'], current_project)
    file_list['playgroundpackages'] = sorted([re.sub(r'^docassemble.', r'', f) for f in os.listdir(the_directory) if
                                              os.path.isfile(os.path.join(the_directory, f)) and re.search(
                                                  r'^[A-Za-z0-9]', f)])
    the_choices = []
    for file_option in file_list['playgroundpackages']:
        the_choices.append((file_option, file_option))
    form.name.choices = the_choices
    if request.method == 'POST':
        if form.validate():
            current_package = form.name.data
            # flash("form validated", 'success')
        else:
            the_error = ''
            for error in form.name.errors:
                the_error += str(error)
            flash("form did not validate with " + str(form.name.data) + " " + str(the_error) + " among " + str(
                form.name.choices), 'error')
    if current_package is not None:
        pkgname = re.sub(r'^docassemble-', r'', current_package)
        # if not user_can_edit_package(pkgname='docassemble.' + pkgname):
        #    flash(word('That package name is already in use by someone else.  Please change the name.'), 'error')
        #    current_package = None
    if current_package is not None and current_package not in file_list['playgroundpackages']:
        flash(word('Sorry, that package name does not exist in the playground'), 'error')
        current_package = None
    if current_package is not None:
        section_sec = {'playgroundtemplate': 'template', 'playgroundstatic': 'static', 'playgroundsources': 'sources',
                       'playgroundmodules': 'modules'}
        for sec in ('playground', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources', 'playgroundmodules'):
            area[sec] = SavedFile(current_user.id, fix=True, section=sec)
            the_directory = directory_for(area[sec], current_project)
            file_list[sec] = sorted([f for f in os.listdir(the_directory) if
                                     os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
        if os.path.isfile(os.path.join(directory_for(area['playgroundpackages'], current_project),
                                       'docassemble.' + current_package)):
            filename = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                    'docassemble.' + current_package)
            info = {}
            with open(filename, 'r', encoding='utf-8') as fp:
                content = fp.read()
                info = yaml.load(content, Loader=yaml.FullLoader)
            for field in (
                    'dependencies', 'interview_files', 'template_files', 'module_files', 'static_files',
                    'sources_files'):
                if field not in info:
                    info[field] = []
            info['dependencies'] = [x for x in
                                    [z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y), info['dependencies'])] if
                                    x not in ('docassemble', 'docassemble.base', 'docassemble.webapp')]
            info['modtime'] = os.path.getmtime(filename)
            author_info = {}
            author_info['author name and email'] = name_of_user(current_user, include_email=True)
            author_info['author name'] = name_of_user(current_user)
            author_info['author email'] = current_user.email
            author_info['first name'] = current_user.first_name
            author_info['last name'] = current_user.last_name
            author_info['id'] = current_user.id
            if do_pypi:
                if current_user.pypi_username is None or current_user.pypi_password is None or current_user.pypi_username == '' or current_user.pypi_password == '':
                    flash("Could not publish to PyPI because username and password were not defined")
                    return redirect(url_for('playground.playground_packages', project=current_project, file=current_package))
                if current_user.timezone:
                    the_timezone = current_user.timezone
                else:
                    the_timezone = get_default_timezone()
                fix_ml_files(author_info['id'], current_project)
                had_error, logmessages = docassemble.webapp.files.publish_package(pkgname, info, author_info,
                                                                                  current_project=current_project)
                flash(logmessages, 'danger' if had_error else 'info')
                if not do_install:
                    time.sleep(3.0)
                    return redirect(url_for('playground.playground_packages', project=current_project, file=current_package))
            if do_github:
                if commit_repository is not None:
                    resp, content = http.request(
                        "https://api.github.com/repos/" + commit_repository['full_name'] + "/commits?per_page=1", "GET")
                    if int(resp['status']) == 200:
                        commit_list = json.loads(content.decode('utf-8', 'ignore'))
                        if len(commit_list) == 0:
                            first_time = True
                            is_empty = True
                        else:
                            first_time = False
                            is_empty = False
                    else:
                        first_time = True
                        is_empty = True
                else:
                    first_time = True
                    is_empty = False
                    headers = {'Content-Type': 'application/json'}
                    the_license = 'mit' if re.search(r'MIT License', info.get('license', '')) else None
                    body = json.dumps(dict(name=github_package_name, description=info.get('description', None),
                                           homepage=info.get('url', None), license_template=the_license))
                    resp, content = http.request("https://api.github.com/user/repos", "POST", headers=headers,
                                                 body=body)
                    if int(resp['status']) != 201:
                        raise DAError("create_playground_package: unable to create GitHub repository: status " + str(
                            resp['status']) + " " + str(content))
                    resp, content = http.request(
                        "https://api.github.com/repos/" + str(github_user_name) + "/" + github_package_name, "GET")
                    if int(resp['status']) == 200:
                        commit_repository = json.loads(content.decode('utf-8', 'ignore'))
                    else:
                        raise DAError(
                            "create_playground_package: GitHub repository could not be found after creating it.")
                if first_time:
                    logmessage("Not checking for stored commit code because no target repository exists")
                    pulled_already = False
                else:
                    current_commit_file = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                                       '.' + github_package_name)
                    if os.path.isfile(current_commit_file):
                        with open(current_commit_file, 'r', encoding='utf-8') as fp:
                            commit_code = fp.read()
                        commit_code = commit_code.strip()
                        resp, content = http.request("https://api.github.com/repos/" + commit_repository[
                            'full_name'] + "/commits/" + commit_code, "GET")
                        if int(resp['status']) == 200:
                            logmessage("Stored commit code is valid")
                            pulled_already = True
                        else:
                            logmessage("Stored commit code is invalid")
                            pulled_already = False
                    else:
                        logmessage("Commit file not found")
                        pulled_already = False
                directory = tempfile.mkdtemp()
                (private_key_file, public_key_file) = get_ssh_keys(github_email)
                os.chmod(private_key_file, stat.S_IRUSR | stat.S_IWUSR)
                os.chmod(public_key_file, stat.S_IRUSR | stat.S_IWUSR)
                ssh_script = tempfile.NamedTemporaryFile(mode='w', prefix="datemp", suffix='.sh', delete=False,
                                                         encoding='utf-8')
                ssh_script.write(
                    '# /bin/bash\n\nssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -i "' + str(
                        private_key_file) + '" $1 $2 $3 $4 $5 $6')
                ssh_script.close()
                os.chmod(ssh_script.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
                git_prefix = "GIT_SSH=" + ssh_script.name + " "
                ssh_url = commit_repository.get('ssh_url', None)
                github_url = commit_repository.get('html_url', None)
                commit_branch = commit_repository.get('default_branch', GITHUB_BRANCH)
                if ssh_url is None:
                    raise DAError("create_playground_package: could not obtain ssh_url for package")
                output = ''
                if branch:
                    branch_option = '-b ' + str(branch) + ' '
                else:
                    branch_option = '-b ' + commit_branch + ' '
                tempbranch = 'playground' + random_string(5)
                packagedir = os.path.join(directory, 'docassemble-' + str(pkgname))
                the_user_name = str(current_user.first_name) + " " + str(current_user.last_name)
                if the_user_name == ' ':
                    the_user_name = 'Anonymous User'
                if is_empty:
                    os.makedirs(packagedir)
                    output += "Doing git init\n"
                    try:
                        output += subprocess.check_output(["git", "init"], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output
                        raise DAError("create_playground_package: error running git init.  " + output)
                    with open(os.path.join(packagedir, 'README.md'), 'w', encoding='utf-8') as the_file:
                        the_file.write("")
                    output += "Doing git config user.email " + json.dumps(github_email) + "\n"
                    try:
                        output += subprocess.check_output(["git", "config", "user.email", json.dumps(github_email)],
                                                          cwd=packagedir, stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git config user.email.  " + output)
                    output += "Doing git config user.name " + json.dumps(the_user_name) + "\n"
                    try:
                        output += subprocess.check_output(["git", "config", "user.name", json.dumps(the_user_name)],
                                                          cwd=packagedir, stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git config user.name.  " + output)
                    output += "Doing git add README.MD\n"
                    try:
                        output += subprocess.check_output(["git", "add", "README.md"], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git add README.md.  " + output)
                    output += "Doing git commit -m \"first commit\"\n"
                    try:
                        output += subprocess.check_output(["git", "commit", "-m", "first commit"], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError(
                            "create_playground_package: error running git commit -m \"first commit\".  " + output)
                    output += "Doing git branch -M " + commit_branch + "\n"
                    try:
                        output += subprocess.check_output(["git", "branch", "-M", commit_branch], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError(
                            "create_playground_package: error running git branch -M " + commit_branch + ".  " + output)
                    output += "Doing git remote add origin " + ssh_url + "\n"
                    try:
                        output += subprocess.check_output(["git", "remote", "add", "origin", ssh_url], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git remote add origin.  " + output)
                    output += "Doing " + git_prefix + "git push -u origin " + '"' + commit_branch + '"' + "\n"
                    try:
                        output += subprocess.check_output(
                            git_prefix + "git push -u origin " + '"' + commit_branch + '"', cwd=packagedir,
                            stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running first git push.  " + output)
                else:
                    output += "Doing " + git_prefix + "git clone " + ssh_url + "\n"
                    try:
                        output += subprocess.check_output(git_prefix + "git clone " + ssh_url, cwd=directory,
                                                          stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git clone.  " + output)
                if not os.path.isdir(packagedir):
                    raise DAError("create_playground_package: package directory did not exist")
                if pulled_already:
                    output += "Doing git checkout " + commit_code + "\n"
                    try:
                        output += subprocess.check_output(git_prefix + "git checkout " + '"' + commit_code + '"',
                                                          cwd=packagedir, stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        # raise DAError("create_playground_package: error running git checkout.  " + output)
                if current_user.timezone:
                    the_timezone = current_user.timezone
                else:
                    the_timezone = get_default_timezone()
                fix_ml_files(author_info['id'], current_project)
                docassemble.webapp.files.make_package_dir(pkgname, info, author_info, directory=directory,
                                                          current_project=current_project)
                if branch:
                    the_branch = branch
                else:
                    the_branch = commit_branch
                output += "Going to use " + the_branch + " as the branch.\n"
                if not is_empty:
                    output += "Doing git config user.email " + json.dumps(github_email) + "\n"
                    try:
                        output += subprocess.check_output(["git", "config", "user.email", json.dumps(github_email)],
                                                          cwd=packagedir, stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git config user.email.  " + output)
                    output += "Doing git config user.name " + json.dumps(the_user_name) + "\n"
                    try:
                        output += subprocess.check_output(["git", "config", "user.name", json.dumps(the_user_name)],
                                                          cwd=packagedir, stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git config user.email.  " + output)
                    output += "Trying git checkout " + the_branch + "\n"
                    try:
                        output += subprocess.check_output(["git", "checkout", the_branch], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += the_branch + " is a new branch\n"
                        force_branch_creation = True
                        branch = the_branch
                output += "Doing git checkout -b " + tempbranch + "\n"
                try:
                    output += subprocess.check_output(git_prefix + "git checkout -b " + tempbranch, cwd=packagedir,
                                                      stderr=subprocess.STDOUT, shell=True).decode()
                except subprocess.CalledProcessError as err:
                    output += err.output.decode()
                    raise DAError("create_playground_package: error running git checkout.  " + output)
                output += "Doing git add .\n"
                try:
                    output += subprocess.check_output(["git", "add", "."], cwd=packagedir,
                                                      stderr=subprocess.STDOUT).decode()
                except subprocess.CalledProcessError as err:
                    output += err.output
                    raise DAError("create_playground_package: error running git add.  " + output)
                output += "Doing git status\n"
                try:
                    output += subprocess.check_output(["git", "status"], cwd=packagedir,
                                                      stderr=subprocess.STDOUT).decode()
                except subprocess.CalledProcessError as err:
                    output += err.output.decode()
                    raise DAError("create_playground_package: error running git status.  " + output)
                output += "Doing git commit -m " + json.dumps(str(commit_message)) + "\n"
                try:
                    output += subprocess.check_output(["git", "commit", "-am", str(commit_message)], cwd=packagedir,
                                                      stderr=subprocess.STDOUT).decode()
                except subprocess.CalledProcessError as err:
                    output += err.output.decode()
                    raise DAError("create_playground_package: error running git commit.  " + output)
                output += "Trying git checkout " + the_branch + "\n"
                try:
                    output += subprocess.check_output(git_prefix + "git checkout " + '"' + the_branch + '"',
                                                      cwd=packagedir, stderr=subprocess.STDOUT, shell=True).decode()
                    branch_exists = True
                except subprocess.CalledProcessError as err:
                    branch_exists = False
                if not branch_exists:
                    output += "Doing git checkout -b " + the_branch + "\n"
                    try:
                        output += subprocess.check_output(git_prefix + "git checkout -b " + '"' + the_branch + '"',
                                                          cwd=packagedir, stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError(
                            "create_playground_package: error running git checkout -b " + the_branch + ".  " + output)
                else:
                    output += "Doing git merge --squash " + tempbranch + "\n"
                    try:
                        output += subprocess.check_output(git_prefix + "git merge --squash " + tempbranch,
                                                          cwd=packagedir, stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError(
                            "create_playground_package: error running git merge --squash " + tempbranch + ".  " + output)
                    output += "Doing git commit\n"
                    try:
                        output += subprocess.check_output(["git", "commit", "-am", str(commit_message)], cwd=packagedir,
                                                          stderr=subprocess.STDOUT).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git commit -am " + str(
                            commit_message) + ".  " + output)
                if branch:
                    output += "Doing " + git_prefix + "git push --set-upstream origin " + str(branch) + "\n"
                    try:
                        output += subprocess.check_output(
                            git_prefix + "git push --set-upstream origin " + '"' + str(branch) + '"', cwd=packagedir,
                            stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git push.  " + output)
                else:
                    output += "Doing " + git_prefix + "git push\n"
                    try:
                        output += subprocess.check_output(git_prefix + "git push", cwd=packagedir,
                                                          stderr=subprocess.STDOUT, shell=True).decode()
                    except subprocess.CalledProcessError as err:
                        output += err.output.decode()
                        raise DAError("create_playground_package: error running git push.  " + output)
                logmessage(output)
                flash(word("Pushed commit to GitHub.") + "<br>" + re.sub(r'[\n\r]+', '<br>', output), 'info')
                time.sleep(3.0)
                shutil.rmtree(directory)
                the_args = dict(project=current_project, pull='1', github_url=ssh_url, show_message='0')
                do_pypi_also = true_or_false(request.args.get('pypi_also', False))
                do_install_also = true_or_false(request.args.get('install_also', False))
                if do_pypi_also or do_install_also:
                    the_args['file'] = current_package
                    if do_pypi_also:
                        the_args['pypi_also'] = '1'
                    if do_install_also:
                        the_args['install_also'] = '1'
                if branch:
                    the_args['branch'] = branch
                return redirect(url_for('playground.playground_packages', **the_args))
            nice_name = 'docassemble-' + str(pkgname) + '.zip'
            file_number = get_new_file_number(None, nice_name)
            file_set_attributes(file_number, private=False, persistent=True)
            saved_file = SavedFile(file_number, extension='zip', fix=True, should_not_exist=True)
            if current_user.timezone:
                the_timezone = current_user.timezone
            else:
                the_timezone = get_default_timezone()
            fix_ml_files(author_info['id'], current_project)
            zip_file = docassemble.webapp.files.make_package_zip(pkgname, info, author_info, the_timezone,
                                                                 current_project=current_project)
            saved_file.copy_from(zip_file.name)
            saved_file.finalize()
            if do_install:
                install_zip_package('docassemble.' + pkgname, file_number)
                result = docassemble.webapp.worker.update_packages.apply_async(
                    link=docassemble.webapp.worker.reset_server.s(
                        run_create=should_run_create('docassemble.' + pkgname)))
                session['taskwait'] = result.id
                session['serverstarttime'] = START_TIME
                return redirect(url_for('admin.update_package_wait',
                                        next=url_for('playground.playground_packages', project=current_project,
                                                     file=current_package)))
            else:
                response = send_file(saved_file.path, mimetype='application/zip', as_attachment=True,
                                     attachment_filename=nice_name)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
    response = make_response(render_template('pages/create_playground_package.html', current_project=current_project,
                                             version_warning=version_warning, bodyclass='daadminbody', form=form,
                                             current_package=current_package,
                                             package_names=file_list['playgroundpackages'],
                                             tab_title=word('Playground Packages'),
                                             page_title=word('Playground Packages')), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@playground.route('/playground_poll', methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def playground_poll():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    script = """
    <script>
      function daPollCallback(data){
        if (data.success){
          window.location.replace(data.url);
        }
      }
      function daPoll(){
        $.ajax({
          type: 'GET',
          url: """ + json.dumps(url_for('playground.playground_redirect_poll')) + """,
          success: daPollCallback,
          dataType: 'json'
        });
        return true;
      }
      $( document ).ready(function() {
        //console.log("polling");
        setInterval(daPoll, 4000);
      });
    </script>"""
    response = make_response(
        render_template('pages/playground_poll.html', version_warning=None, bodyclass='daadminbody',
                        extra_js=Markup(script), tab_title=word('Waiting'), page_title=word('Waiting')), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@playground.route('/playgroundstatic/<current_project>/<userid>/<path:filename>', methods=['GET'])
def playground_static(current_project, userid, filename):
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    # filename = re.sub(r'[^A-Za-z0-9\-\_\. ]', '', filename)
    try:
        attach = int(request.args.get('attach', 0))
    except:
        attach = 0
    area = SavedFile(userid, fix=True, section='playgroundstatic')
    the_directory = directory_for(area, current_project)
    filename = filename.replace('/', os.path.sep)
    path = os.path.join(the_directory, filename)
    if os.path.join('..', '') in path:
        return ('File not found', 404)
    if os.path.isfile(path):
        filename = os.path.basename(filename)
        extension, mimetype = get_ext_and_mimetype(filename)
        response = send_file(path, mimetype=str(mimetype), download_name=filename)
        if attach:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
        return response
    return ('File not found', 404)


@playground.route('/playgroundmodules/<current_project>/<userid>/<path:filename>', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def playground_modules(current_project, userid, filename):
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    # filename = re.sub(r'[^A-Za-z0-9\-\_\. ]', '', filename)
    try:
        attach = int(request.args.get('attach', 0))
    except:
        attach = 0
    area = SavedFile(userid, fix=True, section='playgroundmodules')
    the_directory = directory_for(area, current_project)
    filename = filename.replace('/', os.path.sep)
    path = os.path.join(the_directory, filename)
    if os.path.join('..', '') in path:
        return ('File not found', 404)
    if os.path.isfile(path):
        filename = os.path.basename(filename)
        extension, mimetype = get_ext_and_mimetype(filename)
        response = send_file(path, mimetype=str(mimetype), download_name=filename)
        if attach:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    return ('File not found', 404)


@playground.route('/playgroundsources/<current_project>/<userid>/<path:filename>', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def playground_sources(current_project, userid, filename):
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    try:
        attach = int(request.args.get('attach', 0))
    except:
        attach = 0
    # filename = re.sub(r'[^A-Za-z0-9\-\_\(\)\. ]', '', filename)
    filename = filename.replace('/', os.path.sep)
    area = SavedFile(userid, fix=True, section='playgroundsources')
    reslt = write_ml_source(area, userid, current_project, filename)
    the_directory = directory_for(area, current_project)
    path = os.path.join(the_directory, filename)
    if os.path.join('..', '') in path:
        return ('File not found', 404)
    if os.path.isfile(path):
        filename = os.path.basename(filename)
        extension, mimetype = get_ext_and_mimetype(filename)
        response = send_file(path, mimetype=str(mimetype), download_name=filename)
        if attach:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    return ('File not found', 404)


@playground.route('/playgroundtemplate/<current_project>/<userid>/<path:filename>', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def playground_template(current_project, userid, filename):
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    # filename = re.sub(r'[^A-Za-z0-9\-\_\. ]', '', filename)
    setup_translation()
    try:
        attach = int(request.args.get('attach', 0))
    except:
        attach = 0
    area = SavedFile(userid, fix=True, section='playgroundtemplate')
    the_directory = directory_for(area, current_project)
    filename = filename.replace('/', os.path.sep)
    path = os.path.join(the_directory, filename)
    if os.path.join('..', '') in path:
        return ('File not found', 404)
    if os.path.isfile(path):
        filename = os.path.basename(filename)
        extension, mimetype = get_ext_and_mimetype(filename)
        response = send_file(path, mimetype=str(mimetype), download_name=filename)
        if attach:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    return ('File not found', 404)


@playground.route('/playgrounddownload/<current_project>/<userid>/<path:filename>', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def playground_download(current_project, userid, filename):
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    # filename = re.sub(r'[^A-Za-z0-9\-\_\. ]', '', filename)
    area = SavedFile(userid, fix=True, section='playground')
    the_directory = directory_for(area, current_project)
    filename = filename.replace('/', os.path.sep)
    path = os.path.join(the_directory, filename)
    if os.path.join('..', '') in path:
        return ('File not found', 404)
    if os.path.isfile(path):
        filename = os.path.basename(filename)
        extension, mimetype = get_ext_and_mimetype(path)
        response = send_file(path, mimetype=str(mimetype))
        response.headers['Content-type'] = 'text/plain; charset=utf-8'
        response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    return ('File not found', 404)


def trash_od_project(old_project):
    the_folder = get_od_folder()
    if the_folder is None:
        logmessage('trash_od_project: folder not configured')
        return False
    storage = RedisCredStorage(app='onedrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('trash_od_project: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(the_folder), "GET")
    if int(r['status']) != 200:
        trashed = True
    else:
        info = json.loads(content.decode())
        # logmessage("Found " + repr(info))
        trashed = bool(info.get('deleted', None))
    if trashed is True or 'folder' not in info:
        logmessage('trash_od_project: folder did not exist')
        return False
    subdir = {}
    for section in ['static', 'templates', 'questions', 'modules', 'sources']:
        subdir[section] = None
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(
        the_folder) + "/children?$select=id,name,deleted,folder", "GET")
    while True:
        if int(r['status']) != 200:
            logmessage('trash_od_project: could not obtain subfolders')
            return False
        info = json.loads(content.decode())
        for item in info['value']:
            if item.get('deleted', None) or 'folder' not in item:
                continue
            if item['name'] in subdir:
                subdir[item['name']] = item['id']
        if "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    for section in subdir.keys():
        if subdir[section] is None:
            logmessage('trash_od_project: could not obtain subfolder for ' + str(section))
            continue
        subsubdir = None
        r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(
            subdir[section]) + "/children?$select=id,name,deleted,folder", "GET")
        while True:
            if int(r['status']) != 200:
                logmessage('trash_od_project: could not obtain contents of subfolder for ' + str(section))
                break
            info = json.loads(content.decode())
            for item in info['value']:
                if item.get('deleted', None) or 'folder' not in item:
                    continue
                if item['name'] == old_project:
                    subsubdir = item['id']
                    break
            if subsubdir is not None or "@odata.nextLink" not in info:
                break
            r, content = http.request(info["@odata.nextLink"], "GET")
        if subsubdir is None:
            logmessage("Could not find subdirectory " + old_project + " in section " + str(section))
        else:
            r, content = http.request(
                "https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(subsubdir) + "/children?$select=id",
                "GET")
            to_delete = []
            while True:
                if int(r['status']) != 200:
                    logmessage('trash_od_project: could not obtain contents of project folder')
                    return False
                info = json.loads(content.decode())
                for item in info.get('value', []):
                    if 'id' in item:
                        to_delete.append(item['id'])
                if "@odata.nextLink" not in info:
                    break
                r, content = http.request(info["@odata.nextLink"], "GET")
            for item_id in to_delete:
                r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(item_id), "DELETE")
                if int(r['status']) != 204:
                    logmessage(
                        'trash_od_project: could not delete file ' + str(item_id) + ".  Result: " + repr(content))
                    return False
            r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(subsubdir), "DELETE")
            if int(r['status']) != 204:
                logmessage(
                    'trash_od_project: could not delete project ' + str(old_project) + ".  Result: " + repr(content))
                return False
            logmessage('trash_od_project: project ' + str(old_project) + ' trashed in section ' + str(section))
    return True


def rename_od_project(old_project, new_project):
    the_folder = get_od_folder()
    if the_folder is None:
        logmessage('rename_od_project: folder not configured')
        return False
    storage = RedisCredStorage(app='onedrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        logmessage('rename_od_project: credentials missing or expired')
        return False
    http = credentials.authorize(httplib2.Http())
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(the_folder), "GET")
    if int(r['status']) != 200:
        trashed = True
    else:
        info = json.loads(content.decode())
        # logmessage("Found " + repr(info))
        trashed = bool(info.get('deleted', None))
    if trashed is True or 'folder' not in info:
        logmessage('rename_od_project: folder did not exist')
        return False
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + urllibquote(
        the_folder) + "/children?$select=id,name,deleted,folder", "GET")
    subdir = {}
    for section in ['static', 'templates', 'questions', 'modules', 'sources']:
        subdir[section] = None
    while True:
        if int(r['status']) != 200:
            logmessage('rename_od_project: could not obtain subfolders')
            return False
        info = json.loads(content.decode())
        for item in info.get('value', []):
            if item.get('deleted', None) or 'folder' not in item:
                continue
            if item['name'] in subdir:
                subdir[item['name']] = item['id']
        if "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    for section in subdir.keys():
        if subdir[section] is None:
            logmessage('rename_od_project: could not obtain subfolder for ' + str(section))
            continue
        subsubdir = None
        r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(
            subdir[section]) + "/children?$select=id,name,deleted,folder", "GET")
        while True:
            if int(r['status']) != 200:
                logmessage('rename_od_project: could not obtain contents of subfolder for ' + str(section))
                break
            info = json.loads(content.decode())
            for item in info.get('value', []):
                if item.get('deleted', None) or 'folder' not in item:
                    continue
                if item['name'] == old_project:
                    subsubdir = item['id']
                    break
            if subsubdir is not None or "@odata.nextLink" not in info:
                break
            r, content = http.request(info["@odata.nextLink"], "GET")
        if subsubdir is None:
            logmessage("rename_od_project: subdirectory " + str(old_project) + " not found")
        else:
            headers = {'Content-Type': 'application/json'}
            r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(subsubdir), "PATCH",
                                      headers=headers, body=json.dumps(dict(name=new_project)))
            if int(r['status']) != 200:
                logmessage('rename_od_project: could not rename folder ' + str(old_project) + " in " + str(
                    section) + " because " + repr(content))
                continue
        logmessage('rename_od_project: project ' + str(old_project) + ' rename in section ' + str(section))
    return True


def set_current_project(new_name):
    key = 'da:playground:project:' + str(current_user.id)
    pipe = r.pipeline()
    pipe.set(key, new_name)
    pipe.expire(key, 2592000)
    pipe.execute()
    return new_name


def get_variable_file(current_project):
    key = 'da:playground:project:' + str(current_user.id) + ':' + current_project + ':variablefile'
    variable_file = r.get(key)
    if variable_file is not None:
        variable_file = variable_file.decode()
    return variable_file


def delete_variable_file(current_project):
    key = 'da:playground:project:' + str(current_user.id) + ':' + current_project + ':variablefile'
    r.delete(key)


def get_current_file(current_project, section):
    key = 'da:playground:project:' + str(current_user.id) + ':playground' + section + ':' + current_project
    current_file = r.get(key)
    if current_file is None:
        return ''
    return current_file.decode()


def delete_current_file(current_project, section):
    key = 'da:playground:project:' + str(current_user.id) + ':playground' + section + ':' + current_project
    r.delete(key)


def formatted_current_time():
    if current_user.timezone:
        the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
    else:
        the_timezone = zoneinfo.ZoneInfo(get_default_timezone())
    return datetime.datetime.utcnow().replace(tzinfo=tz.tzutc()).astimezone(the_timezone).strftime('%H:%M:%S %Z')


def flash_as_html(message, message_type="info", is_ajax=True):
    if message_type == 'error':
        message_type = 'danger'
    output = "\n        " + (NOTIFICATION_MESSAGE % (message_type, str(message))) + "\n"
    if not is_ajax:
        flash(message, message_type)
    return output


def assign_opacity(files):
    if len(files) == 1:
        files[0]['opacity'] = 1.0
    else:
        indexno = 0.0
        max_indexno = float(len(files) - 1)
        for file_dict in sorted(files, key=lambda x: x['modtime']):
            file_dict['opacity'] = round(0.2 + 0.8 * (indexno / max_indexno), 2)
            indexno += 1.0


def set_current_file(current_project, section, new_name):
    key = 'da:playground:project:' + str(current_user.id) + ':playground' + section + ':' + current_project
    pipe = r.pipeline()
    pipe.set(key, new_name)
    pipe.expire(key, 2592000)
    pipe.execute()
    return new_name


def search_js(form=None):
    if form is None:
        form = 'form'
    return """
var origPosition = null;
var searchMatches = null;

function searchReady(){
  $("#""" + form + """ input[name='search_term']").on("focus", function(event){
    origPosition = daCodeMirror.getCursor('from');
  });
  $("#""" + form + """ input[name='search_term']").change(update_search);
  $("#""" + form + """ input[name='search_term']").on("keydown", enter_search);
  $("#""" + form + """ input[name='search_term']").on("keyup", update_search);
  $("#daSearchPrevious").click(function(event){
    var query = $("#""" + form + """ input[name='search_term']").val();
    if (query.length == 0){
      clear_matches();
      daCodeMirror.setCursor(daCodeMirror.getCursor('from'));
      $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
      return;
    }
    origPosition = daCodeMirror.getCursor('from');
    var sc = daCodeMirror.getSearchCursor(query, origPosition);
    show_matches(query);
    var found = sc.findPrevious();
    if (found){
      daCodeMirror.setSelection(sc.from(), sc.to());
      scroll_to_selection();
      $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
    }
    else{
      var lastLine = daCodeMirror.lastLine()
      var lastChar = daCodeMirror.lineInfo(lastLine).text.length
      origPosition = { line: lastLine, ch: lastChar, xRel: 1 }
      sc = daCodeMirror.getSearchCursor(query, origPosition);
      show_matches(query);
      var found = sc.findPrevious();
      if (found){
        daCodeMirror.setSelection(sc.from(), sc.to());
        scroll_to_selection();
        $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
      }
      else{
        $("#""" + form + """ input[name='search_term']").addClass("da-search-error");
      }
    }
    event.preventDefault();
    return false;
  });
  $("#daSearchNext").click(function(event){
    var query = $("#""" + form + """ input[name='search_term']").val();
    if (query.length == 0){
      clear_matches();
      daCodeMirror.setCursor(daCodeMirror.getCursor('from'));
      $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
      return;
    }
    origPosition = daCodeMirror.getCursor('to');
    var sc = daCodeMirror.getSearchCursor(query, origPosition);
    show_matches(query);
    var found = sc.findNext();
    if (found){
      daCodeMirror.setSelection(sc.from(), sc.to());
      scroll_to_selection();
      $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
    }
    else{
      origPosition = { line: 0, ch: 0, xRel: 1 }
      sc = daCodeMirror.getSearchCursor(query, origPosition);
      show_matches(query);
      var found = sc.findNext();
      if (found){
        daCodeMirror.setSelection(sc.from(), sc.to());
        scroll_to_selection();
        $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
      }
      else{
        $("#""" + form + """ input[name='search_term']").addClass("da-search-error");
      }
    }
    event.preventDefault();
    return false;
  });
}

function show_matches(query){
  clear_matches();
  if (query.length == 0){
    daCodeMirror.setCursor(daCodeMirror.getCursor('from'));
    $("#""" + form + """ input[name='search_term']").removeClass("da-search-error");
    return;
  }
  searchMatches = daCodeMirror.showMatchesOnScrollbar(query);
}

function clear_matches(){
  if (searchMatches != null){
    try{
      searchMatches.clear();
    }
    catch(err){}
  }
}

function scroll_to_selection(){
  daCodeMirror.scrollIntoView(daCodeMirror.getCursor('from'))
  var t = daCodeMirror.charCoords(daCodeMirror.getCursor('from'), "local").top;
  daCodeMirror.scrollTo(null, t);
}

function enter_search(event){
  var theCode = event.which || event.keyCode;
  if(theCode == 13) {
    event.preventDefault();
    $("#daSearchNext").click();
    return false;
  }
}

function update_search(event){
  var query = $(this).val();
  if (query.length == 0){
    clear_matches();
    daCodeMirror.setCursor(daCodeMirror.getCursor('from'));
    $(this).removeClass("da-search-error");
    return;
  }
  var theCode = event.which || event.keyCode;
  if(theCode == 13) {
    event.preventDefault();
    return false;
  }
  var sc = daCodeMirror.getSearchCursor(query, origPosition);
  show_matches(query);

  var found = sc.findNext();
  if (found){
    daCodeMirror.setSelection(sc.from(), sc.to());
    scroll_to_selection();
    $(this).removeClass("da-search-error");
  }
  else{
    origPosition = { line: 0, ch: 0, xRel: 1 }
    sc = daCodeMirror.getSearchCursor(query, origPosition);
    show_matches(query);
    var found = sc.findNext();
    if (found){
      daCodeMirror.setSelection(sc.from(), sc.to());
      scroll_to_selection();
      $(this).removeClass("da-search-error");
    }
    else{
      $(this).addClass("da-search-error");
    }
  }
}

"""


@playground.route('/playgroundfiles', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_files():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    current_project = get_current_project()
    use_gd = bool(current_app.config['USE_GOOGLE_DRIVE'] is True and get_gd_folder() is not None)
    use_od = bool(use_gd is False and current_app.config['USE_ONEDRIVE'] is True and get_od_folder() is not None)
    form = PlaygroundFilesForm(request.form)
    formtwo = PlaygroundFilesEditForm(request.form)
    is_ajax = bool('ajax' in request.form and int(request.form['ajax']))
    section = werkzeug.utils.secure_filename(request.args.get('section', 'template'))
    the_file = secure_filename_spaces_ok(request.args.get('file', ''))
    scroll = False
    if the_file != '':
        scroll = True
    if request.method == 'GET':
        is_new = true_or_false(request.args.get('new', False))
    else:
        is_new = False
    if is_new:
        scroll = True
        the_file = ''
    if request.method == 'POST':
        form_validated = bool((form.purpose.data == 'upload' and form.validate()) or (
                formtwo.purpose.data == 'edit' and formtwo.validate()))
        if form_validated:
            if form.section.data:
                section = form.section.data
            if formtwo.file_name.data:
                the_file = formtwo.file_name.data
                the_file = re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_', the_file)
    else:
        form_validated = None
    if section not in ("template", "static", "sources", "modules", "packages"):
        section = "template"
    pgarea = SavedFile(current_user.id, fix=True, section='playground')
    the_directory = directory_for(pgarea, current_project)
    if current_project != 'default' and not os.path.isdir(the_directory):
        current_project = set_current_project('default')
        the_directory = directory_for(pgarea, current_project)
    pulldown_files = sorted([f for f in os.listdir(the_directory) if
                             os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    current_variable_file = get_variable_file(current_project)
    if current_variable_file is not None:
        if current_variable_file in pulldown_files:
            active_file = current_variable_file
        else:
            delete_variable_file(current_project)
            active_file = None
    else:
        active_file = None
    if active_file is None:
        current_file = get_current_file(current_project, 'questions')
        if current_file in pulldown_files:
            active_file = current_file
        elif len(pulldown_files) > 0:
            delete_current_file(current_project, 'questions')
            active_file = pulldown_files[0]
        else:
            delete_current_file(current_project, 'questions')
    area = SavedFile(current_user.id, fix=True, section='playground' + section)
    the_directory = directory_for(area, current_project)
    if request.args.get('delete', False):
        argument = request.args.get('delete')
        if argument:
            the_directory = directory_for(area, current_project)
            the_file = add_project(argument, current_project)
            filename = os.path.join(the_directory, argument)
            if os.path.exists(filename):
                os.remove(filename)
                area.finalize()
                for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':*'):
                    r.incr(key.decode())
                cloud_trash(use_gd, use_od, section, argument, current_project)
                flash(word("Deleted file: ") + the_file, "success")
                for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':*'):
                    r.incr(key.decode())
                return redirect(url_for('playground.playground_files', section=section, project=current_project))
            else:
                flash(word("File not found: ") + argument, "error")
    if request.args.get('convert', False):
        # argument = re.sub(r'[^A-Za-z0-9\-\_\. ]', '', request.args.get('convert'))
        argument = request.args.get('convert')
        if argument:
            filename = os.path.join(the_directory, argument)
            if os.path.exists(filename):
                to_file = os.path.splitext(argument)[0] + '.md'
                to_path = os.path.join(the_directory, to_file)
                if not os.path.exists(to_path):
                    extension, mimetype = get_ext_and_mimetype(argument)
                    if mimetype and mimetype in convertible_mimetypes:
                        the_format = convertible_mimetypes[mimetype]
                    elif extension and extension in convertible_extensions:
                        the_format = convertible_extensions[extension]
                    else:
                        flash(word("File format not understood: ") + argument, "error")
                        return redirect(url_for('playground.playground_files', section=section, project=current_project))
                    result = word_to_markdown(filename, the_format)
                    if result is None:
                        flash(word("File could not be converted: ") + argument, "error")
                        return redirect(url_for('playground.playground_files', section=section, project=current_project))
                    shutil.copyfile(result.name, to_path)
                    flash(word("Created new Markdown file called ") + to_file + word("."), "success")
                    area.finalize()
                    return redirect(url_for('playground.playground_files', section=section, file=to_file, project=current_project))
            else:
                flash(word("File not found: ") + argument, "error")
    if request.method == 'POST' and form_validated:
        if 'uploadfile' in request.files:
            the_files = request.files.getlist('uploadfile')
            if the_files:
                need_to_restart = False
                for up_file in the_files:
                    try:
                        filename = werkzeug.utils.secure_filename(up_file.filename)
                        extension, mimetype = get_ext_and_mimetype(filename)
                        if section == 'modules' and extension != 'py':
                            flash(word(
                                "Sorry, only .py files can be uploaded here.  To upload other types of files, use other Folders."),
                                'error')
                            return redirect(url_for('playground.playground_files', section=section, project=current_project))
                        filename = re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_', filename)
                        the_file = filename
                        filename = os.path.join(the_directory, filename)
                        up_file.save(filename)
                        for key in r.keys(
                                'da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                                    current_project) + ':*'):
                            r.incr(key.decode())
                        area.finalize()
                        if section == 'modules':
                            need_to_restart = True
                    except Exception as errMess:
                        flash("Error of type " + str(type(errMess)) + " processing upload: " + str(errMess), "error")
                if need_to_restart:
                    flash(word(
                        'Since you uploaded a Python module, the server needs to restart in order to load your module.'),
                        'info')
                    return redirect(url_for('util.restart_page',
                                            next=url_for('playground.playground_files', section=section, file=the_file,
                                                         project=current_project)))
                flash(word("Upload successful"), "success")
        if formtwo.delete.data:
            if the_file != '':
                filename = os.path.join(the_directory, the_file)
                if os.path.exists(filename):
                    os.remove(filename)
                    for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                            current_project) + ':*'):
                        r.incr(key.decode())
                    area.finalize()
                    flash(word("Deleted file: ") + the_file, "success")
                    return redirect(url_for('playground.playground_files', section=section, project=current_project))
                else:
                    flash(word("File not found: ") + the_file, "error")
        if formtwo.submit.data and formtwo.file_content.data:
            if the_file != '':
                if section == 'modules' and not re.search(r'\.py$', the_file):
                    the_file = re.sub(r'\..*', '', the_file) + '.py'
                if formtwo.original_file_name.data and formtwo.original_file_name.data != the_file:
                    old_filename = os.path.join(the_directory, formtwo.original_file_name.data)
                    cloud_trash(use_gd, use_od, section, formtwo.original_file_name.data, current_project)
                    if os.path.isfile(old_filename):
                        os.remove(old_filename)
                filename = os.path.join(the_directory, the_file)
                with open(filename, 'w', encoding='utf-8') as fp:
                    fp.write(re.sub(r'\r\n', r'\n', formtwo.file_content.data))
                the_time = formatted_current_time()
                for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':*'):
                    r.incr(key.decode())
                area.finalize()
                if formtwo.active_file.data and formtwo.active_file.data != the_file:
                    r.incr('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':' + formtwo.active_file.data)
                flash_message = flash_as_html(str(the_file) + ' ' + word('was saved at') + ' ' + the_time + '.',
                                              message_type='success', is_ajax=is_ajax)
                if section == 'modules':
                    flash(word(
                        'Since you changed a Python module, the server needs to restart in order to load your module.'),
                        'info')
                    return redirect(url_for('util.restart_page',
                                            next=url_for('playground.playground_files', section=section, file=the_file,
                                                         project=current_project)))
                if is_ajax:
                    return jsonify(success=True, flash_message=flash_message)
                else:
                    return redirect(
                        url_for('playground.playground_files', section=section, file=the_file, project=current_project))
            else:
                flash(word('You need to type in a name for the file'), 'error')
    if is_ajax and not form_validated:
        errors = []
        for fieldName, errorMessages in formtwo.errors.items():
            for err in errorMessages:
                errors.append(dict(fieldName=fieldName, err=err))
        return jsonify(success=False, errors=errors)
    files = sorted([f for f in os.listdir(the_directory) if
                    os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])

    editable_files = []
    convertible_files = []
    trainable_files = {}
    mode = "yaml"
    for a_file in files:
        extension, mimetype = get_ext_and_mimetype(a_file)
        if (mimetype and mimetype in ok_mimetypes) or (extension and extension in ok_extensions) or (
                mimetype and mimetype.startswith('text')):
            if section == 'sources' and re.match(r'ml-.*\.json$', a_file):
                trainable_files[a_file] = re.sub(r'^ml-|\.json$', '', a_file)
            else:
                editable_files.append(dict(name=a_file, modtime=os.path.getmtime(os.path.join(the_directory, a_file))))
    assign_opacity(editable_files)
    editable_file_listing = [x['name'] for x in editable_files]
    for a_file in files:
        extension, mimetype = get_ext_and_mimetype(a_file)
        b_file = os.path.splitext(a_file)[0] + '.md'
        if b_file not in editable_file_listing and ((mimetype and mimetype in convertible_mimetypes) or (
                extension and extension in convertible_extensions)):
            convertible_files.append(a_file)
    if the_file and not is_new and the_file not in editable_file_listing:
        the_file = ''
    if not the_file and not is_new:
        current_file = get_current_file(current_project, section)
        if current_file in editable_file_listing:
            the_file = current_file
        else:
            delete_current_file(current_project, section)
            if len(editable_files) > 0:
                the_file = sorted(editable_files, key=lambda x: x['modtime'])[-1]['name']
            else:
                if section == 'modules':
                    the_file = 'test.py'
                elif section == 'sources':
                    the_file = 'test.json'
                else:
                    the_file = 'test.md'
    if the_file in editable_file_listing:
        set_current_file(current_project, section, the_file)
    if the_file != '':
        extension, mimetype = get_ext_and_mimetype(the_file)
        if mimetype and mimetype in ok_mimetypes:
            mode = ok_mimetypes[mimetype]
        elif extension and extension in ok_extensions:
            mode = ok_extensions[extension]
        elif mimetype and mimetype.startswith('text'):
            mode = 'null'
    if mode != 'markdown':
        active_file = None
    if section == 'modules':
        mode = 'python'
    formtwo.original_file_name.data = the_file
    formtwo.file_name.data = the_file
    if the_file != '' and os.path.isfile(os.path.join(the_directory, the_file)):
        filename = os.path.join(the_directory, the_file)
    else:
        filename = None
    if filename is not None:
        area.finalize()
        with open(filename, 'r', encoding='utf-8') as fp:
            try:
                content = fp.read()
            except:
                filename = None
                content = ''
    elif formtwo.file_content.data:
        content = re.sub(r'\r\n', r'\n', formtwo.file_content.data)
    else:
        content = ''
    lowerdescription = None
    description = None
    if section == "template":
        header = word("Templates")
        description = 'Add files here that you want want to include in your interviews using <a target="_blank" href="https://docassemble.org/docs/documents.html#docx template file"><code>docx template file</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#pdf template file"><code>pdf template file</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#content file"><code>content file</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#initial yaml"><code>initial yaml</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#additional yaml"><code>additional yaml</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#template file"><code>template file</code></a>, <a target="_blank" href="https://docassemble.org/docs/documents.html#rtf template file"><code>rtf template file</code></a>, or <a target="_blank" href="https://docassemble.org/docs/documents.html#docx reference file"><code>docx reference file</code></a>.'
        upload_header = word("Upload a template file")
        list_header = word("Existing template files")
        edit_header = word('Edit text files')
        after_text = None
    elif section == "static":
        header = word("Static Files")
        description = 'Add files here that you want to include in your interviews with <a target="_blank" href="https://docassemble.org/docs/initial.html#images"><code>images</code></a>, <a target="_blank" href="https://docassemble.org/docs/initial.html#image sets"><code>image sets</code></a>, <a target="_blank" href="https://docassemble.org/docs/markup.html#inserting%20images"><code>[FILE]</code></a> or <a target="_blank" href="https://docassemble.org/docs/functions.html#url_of"><code>url_of()</code></a>.'
        upload_header = word("Upload a static file")
        list_header = word("Existing static files")
        edit_header = word('Edit text files')
        after_text = None
    elif section == "sources":
        header = word("Source Files")
        description = 'Add files here that you want to use as a data source in your interview code, such as word translation files and training data for machine learning.  For Python source code, see the Modules folder.'
        upload_header = word("Upload a source file")
        list_header = word("Existing source files")
        edit_header = word('Edit source files')
        after_text = None
    elif section == "modules":
        header = word("Modules")
        upload_header = word("Upload a Python module")
        list_header = word("Existing module files")
        edit_header = word('Edit module files')
        description = 'You can use this page to add Python module files (.py files) that you want to include in your interviews using <a target="_blank" href="https://docassemble.org/docs/initial.html#modules"><code>modules</code></a> or <a target="_blank" href="https://docassemble.org/docs/initial.html#imports"><code>imports</code></a>.'
        lowerdescription = Markup(
            """<p>To use this in an interview, write a <a target="_blank" href="https://docassemble.org/docs/initial.html#modules"><code>modules</code></a> block that refers to this module using Python's syntax for specifying a "relative import" of a module (i.e., prefix the module name with a period).</p>""" + highlight(
                '---\nmodules:\n  - .' + re.sub(r'\.py$', '', the_file) + '\n---', YamlLexer(), HtmlFormatter()))
        after_text = None
    if scroll:
        extra_command = """
        if ($("#file_name").val().length > 0){
          daCodeMirror.focus();
        }
        else{
          $("#file_name").focus()
        }
        scrollBottom();"""
    else:
        extra_command = ""
    if keymap:
        kbOpt = 'keyMap: "' + keymap + '", cursorBlinkRate: 0, '
        kbLoad = '<script src="' + url_for('static', filename="codemirror/keymap/" + keymap + ".js",
                                           v=da_version) + '"></script>\n    '
    else:
        kbOpt = ''
        kbLoad = ''
    extra_js = """
    <script>
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
      var daCodeMirror;
      var daTextArea;
      var vocab = [];
      var currentFile = """ + json.dumps(the_file) + """;
      var daIsNew = """ + ('true' if is_new else 'false') + """;
      var existingFiles = """ + json.dumps(files) + """;
      var daSection = """ + '"' + section + '";' + """
      var attrs_showing = Object();
      var currentProject = """ + json.dumps(current_project) + """;
""" + indent_by(variables_js(form='formtwo'), 6) + """
""" + indent_by(search_js(form='formtwo'), 6) + """
      var daExpireSession = null;
      function resetExpireSession(){
        if (daExpireSession != null){
          window.clearTimeout(daExpireSession);
        }
        daExpireSession = setTimeout(function(){
          alert(""" + json.dumps(word(
        "Your browser session has expired and you have been signed out.  You will not be able to save your work.  Please log in again.")) + """);
        }, """ + str(999 * int(daconfig.get('session lifetime seconds', 43200))) + """);
      }
      function saveCallback(data){
        if (!data.success){
          var n = data.errors.length;
          for (var i = 0; i < n; ++i){
            $('input[name="' + data.errors[i].fieldName + '"]').parents('.input-group').addClass("da-group-has-error").after('<div class="da-has-error invalid-feedback">' + data.errors[i].err + '</div>');
          }
          return;
        }
        $('.da-has-error').remove();
        $('.da-group-has-error').removeClass('da-group-has-error');
        fetchVars(true);
        if ($("#daflash").length){
          $("#daflash").html(data.flash_message);
        }
        else{
          $("#damain").prepend(daSprintf(daNotificationContainer, data.flash_message));
        }
      }
      function scrollBottom(){
        $("html, body").animate({
          scrollTop: $("#editnav").offset().top - 53
        }, "slow");
      }
      $( document ).ready(function() {
        resetExpireSession();
        $("#file_name").on('change', function(){
          var newFileName = $(this).val();
          if ((!daIsNew) && newFileName == currentFile){
            return;
          }
          for (var i = 0; i < existingFiles.length; i++){
            if (newFileName == existingFiles[i]){
              alert(""" + json.dumps(
        word("Warning: a file by that name already exists.  If you save, you will overwrite it.")) + """);
              return;
            }
          }
          return;
        });
        $("#dauploadbutton").click(function(event){
          if ($("#uploadfile").val() == ""){
            event.preventDefault();
            return false;
          }
        });
        daTextArea = document.getElementById("file_content");
        daCodeMirror = CodeMirror.fromTextArea(daTextArea, {mode: """ + (
                   '{name: "markdown", underscoresBreakWords: false}' if mode == 'markdown' else json.dumps(
                       mode)) + """, """ + kbOpt + """tabSize: 2, tabindex: 580, autofocus: false, lineNumbers: true, matchBrackets: true, lineWrapping: """ + (
                   'true' if daconfig.get('wrap lines in playground', True) else 'false') + """});
        $(window).bind("beforeunload", function(){
          daCodeMirror.save();
          $("#formtwo").trigger("checkform.areYouSure");
        });
        $("#daDelete").click(function(event){
          if (!confirm(""" + json.dumps(word("Are you sure that you want to delete this file?")) + """)){
            event.preventDefault();
          }
        });
        $("#formtwo").areYouSure(""" + json.dumps(
        json.dumps({'message': word("There are unsaved changes.  Are you sure you wish to leave this page?")})) + """);
        $("#formtwo").bind("submit", function(e){
          daCodeMirror.save();
          $("#formtwo").trigger("reinitialize.areYouSure");
          if (daSection != 'modules' && !daIsNew){
            var extraVariable = ''
            if ($("#daVariables").length){
              extraVariable = '&active_file=' + encodeURIComponent($("#daVariables").val());
            }
            $.ajax({
              type: "POST",
              url: """ + '"' + url_for('playground.playground_files', project=current_project) + '"' + """,
              data: $("#formtwo").serialize() + extraVariable + '&submit=Save&ajax=1',
              success: function(data){
                if (data.action && data.action == 'reload'){
                  location.reload(true);
                }
                resetExpireSession();
                saveCallback(data);
                setTimeout(function(){
                  $("#daflash .alert-success").hide(300, function(){
                    $(self).remove();
                  });
                }, 3000);
              },
              dataType: 'json'
            });
            e.preventDefault();
            return false;
          }
          return true;
        });
        daCodeMirror.setOption("extraKeys", { Tab: function(cm) { var spaces = Array(cm.getOption("indentUnit") + 1).join(" "); cm.replaceSelection(spaces); }, "F11": function(cm) { cm.setOption("fullScreen", !cm.getOption("fullScreen")); }, "Esc": function(cm) { if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false); }});
        daCodeMirror.setOption("coverGutterNextToScrollbar", true);
        searchReady();
        variablesReady();
        fetchVars(false);""" + extra_command + """
      });
      searchReady();
      $('#uploadfile').on('change', function(){
        var fileName = $(this).val();
        fileName = fileName.replace(/.*\\\\/, '');
        fileName = fileName.replace(/.*\\//, '');
        $(this).next('.custom-file-label').html(fileName);
      });
    </script>"""
    if keymap:
        kbOpt = 'keyMap: "' + keymap + '", cursorBlinkRate: 0, '
        kbLoad = '<script src="' + url_for('static',
                                           filename="codemirror/keymap/" + keymap + ".js") + '"></script>\n    '
    else:
        kbOpt = ''
        kbLoad = ''
    any_files = bool(len(editable_files) > 0)
    back_button = Markup('<span class="navbar-brand navbar-nav dabackicon me-3"><a href="' + url_for('playground.playground_page',
                                                                                                     project=current_project) + '" class="dabackbuttoncolor nav-link" title=' + json.dumps(
        word(
            "Go back to the main Playground page")) + '><i class="fas fa-chevron-left"></i><span class="daback">' + word(
        'Back') + '</span></a></span>')
    cm_mode = ''
    if mode == 'null':
        modes = []
    elif mode == 'htmlmixed':
        modes = ['css', 'xml', 'htmlmixed']
    else:
        modes = [mode]
    for the_mode in modes:
        cm_mode += '\n    <script src="' + url_for('static', filename="codemirror/mode/" + the_mode + "/" + (
            'damarkdown' if the_mode == 'markdown' else the_mode) + ".js", v=da_version) + '"></script>'
    if current_project != 'default':
        header += " / " + current_project
    response = make_response(
        render_template('pages/playgroundfiles.html', current_project=current_project, version_warning=None,
                        bodyclass='daadminbody', use_gd=use_gd, use_od=use_od, back_button=back_button,
                        tab_title=header, page_title=header, extra_css=Markup(
                '\n    <link href="' + url_for('static', filename='app/playgroundbundle.css',
                                               v=da_version) + '" rel="stylesheet">'), extra_js=Markup(
                '\n    <script src="' + url_for('static', filename="app/playgroundbundle.js",
                                                v=da_version) + '"></script>\n    ' + kbLoad + cm_mode + extra_js),
                        header=header, upload_header=upload_header, list_header=list_header, edit_header=edit_header,
                        description=Markup(description), lowerdescription=lowerdescription, form=form,
                        files=sorted(files, key=lambda y: y.lower()), section=section, userid=current_user.id,
                        editable_files=sorted(editable_files, key=lambda y: y['name'].lower()),
                        editable_file_listing=editable_file_listing, trainable_files=trainable_files,
                        convertible_files=convertible_files, formtwo=formtwo, current_file=the_file, content=content,
                        after_text=after_text, is_new=str(is_new), any_files=any_files,
                        pulldown_files=sorted(pulldown_files, key=lambda y: y.lower()), active_file=active_file,
                        playground_package='docassemble.playground' + str(current_user.id) + project_name(
                            current_project)), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def copy_if_different(source, destination):
    if (not os.path.isfile(destination)) or filecmp.cmp(source, destination) is False:
        shutil.copyfile(source, destination)


def do_playground_pull(area, current_project, github_url=None, branch=None, pypi_package=None,
                       can_publish_to_github=False, github_user_name=None, github_email=None, pull_only=False):
    area_sec = dict(templates='playgroundtemplate', static='playgroundstatic', sources='playgroundsources',
                    questions='playground')
    readme_text = ''
    setup_py = ''
    if branch in ('', 'None'):
        branch = None
    if branch:
        branch = werkzeug.utils.secure_filename(branch)
        branch_option = '-b "' + branch + '" '
    else:
        branch_option = ''
    need_to_restart = False
    extracted = {}
    data_files = dict(templates=[], static=[], sources=[], interviews=[], modules=[], questions=[])
    directory = tempfile.mkdtemp()
    output = ''
    pypi_url = daconfig.get('pypi url', 'https://pypi.python.org/pypi')
    expected_name = 'unknown'
    if github_url:
        github_url = re.sub(r'[^A-Za-z0-9\-\.\_\~\:\/\#\[\]\@\$\+\,\=]', '', github_url)
        repo_name = re.sub(r'/*$', '', github_url)
        repo_name = re.sub(r'^http.*github.com/', '', repo_name)
        repo_name = re.sub(r'.*@github.com:', '', repo_name)
        repo_name = re.sub(r'.git$', '', repo_name)
        if not 'x-oauth-basic@github.com' in github_url and can_publish_to_github and github_email:
            github_url = f'git@github.com:{repo_name}.git'
            expected_name = re.sub(r'.*/', '', github_url)
            expected_name = re.sub(r'\.git', '', expected_name)
            expected_name = re.sub(r'docassemble-', '', expected_name)
            (private_key_file, public_key_file) = get_ssh_keys(github_email)
            os.chmod(private_key_file, stat.S_IRUSR | stat.S_IWUSR)
            os.chmod(public_key_file, stat.S_IRUSR | stat.S_IWUSR)
            ssh_script = tempfile.NamedTemporaryFile(mode='w', prefix="datemp", suffix='.sh', delete=False,
                                                     encoding='utf-8')
            ssh_script.write(
                '# /bin/bash\n\nssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -i "' + str(
                    private_key_file) + '" $1 $2 $3 $4 $5 $6')
            ssh_script.close()
            os.chmod(ssh_script.name, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
            # git_prefix = "GIT_SSH_COMMAND='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o GlobalKnownHostsFile=/dev/null -i \"" + str(private_key_file) + "\"' "
            git_prefix = "GIT_SSH=" + ssh_script.name + " "
            output += "Doing " + git_prefix + "git clone " + branch_option + github_url + "\n"
            try:
                output += subprocess.check_output(git_prefix + "git clone " + branch_option + '"' + github_url + '"',
                                                  cwd=directory, stderr=subprocess.STDOUT, shell=True).decode()
            except subprocess.CalledProcessError as err:
                output += err.output.decode()
                return dict(action="error", message="error running git clone.  " + output)
        else:
            if not github_url.startswith('http'):
                github_url = f'https://github.com/{repo_name}'
            expected_name = re.sub(r'.*/', '', github_url)
            expected_name = re.sub(r'\.git', '', expected_name)
            expected_name = re.sub(r'docassemble-', '', expected_name)
            try:
                if branch is not None:
                    logmessage("Doing git clone -b " + branch + " " + github_url)
                    output += subprocess.check_output(['git', 'clone', '-b', branch, github_url], cwd=directory,
                                                      stderr=subprocess.STDOUT).decode()
                else:
                    logmessage("Doing git clone " + github_url)
                    output += subprocess.check_output(['git', 'clone', github_url], cwd=directory,
                                                      stderr=subprocess.STDOUT).decode()
            except subprocess.CalledProcessError as err:
                output += err.output.decode()
                return dict(action="error", message="error running git clone.  " + output)
        logmessage(output)
        dirs_inside = [f for f in os.listdir(directory) if
                       os.path.isdir(os.path.join(directory, f)) and re.search(r'^[A-Za-z0-9]', f)]
        if len(dirs_inside) == 1:
            commit_file = os.path.join(directory_for(area['playgroundpackages'], current_project), '.' + dirs_inside[0])
            packagedir = os.path.join(directory, dirs_inside[0])
            try:
                current_commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=packagedir,
                                                         stderr=subprocess.STDOUT).decode()
            except subprocess.CalledProcessError as err:
                output = err.output.decode()
                return dict(action="error", message="error running git rev-parse.  " + output)
            with open(commit_file, 'w', encoding='utf-8') as fp:
                fp.write(current_commit.strip())
            logmessage("Wrote " + current_commit.strip() + " to " + commit_file)
        else:
            logmessage("Did not find a single directory inside repo")
        if pull_only:
            return dict(action='pull_only')
    elif pypi_package:
        pypi_package = re.sub(r'[^A-Za-z0-9\-\.\_\:\/\@\+\=]', '', pypi_package)
        pypi_package = 'docassemble.' + re.sub(r'^docassemble\.', '', pypi_package)
        package_file = tempfile.NamedTemporaryFile(suffix='.tar.gz')
        try:
            http = httplib2.Http()
            resp, content = http.request(pypi_url + "/" + str(pypi_package) + "/json", "GET")
            the_pypi_url = None
            if int(resp['status']) == 200:
                pypi_response = json.loads(content.decode())
                for file_option in pypi_response['releases'][pypi_response['info']['version']]:
                    if file_option['packagetype'] == 'sdist':
                        the_pypi_url = file_option['url']
                        break
            else:
                return dict(action='fail', message=word("The package you specified could not be downloaded from PyPI."))
            if the_pypi_url is None:
                return dict(action='fail', message=word(
                    "The package you specified could not be downloaded from PyPI as a tar.gz file."))
        except Exception as err:
            return dict(action='error', message="error getting information about PyPI package.  " + str(err))
        try:
            urlretrieve(the_pypi_url, package_file.name)
        except Exception as err:
            return dict(action='error', message="error downloading PyPI package.  " + str(err))
        try:
            tar = tarfile.open(package_file.name)
            tar.extractall(path=directory)
            tar.close()
        except Exception as err:
            return dict(action='error', message="error unpacking PyPI package.  " + str(err))
        package_file.close()
    initial_directories = len(splitall(directory)) + 1
    for root, dirs, files in os.walk(directory):
        at_top_level = bool('setup.py' in files and 'docassemble' in dirs)
        for a_file in files:
            orig_file = os.path.join(root, a_file)
            # output += "Original file is " + orig_file + "\n"
            thefilename = os.path.join(*splitall(orig_file)[initial_directories:])
            (the_directory, filename) = os.path.split(thefilename)
            if filename.startswith('#') or filename.endswith('~'):
                continue
            dirparts = splitall(the_directory)
            if '.git' in dirparts:
                continue
            levels = re.findall(r'/', the_directory)
            for sec in ('templates', 'static', 'sources', 'questions'):
                if the_directory.endswith('data/' + sec) and filename != 'README.md':
                    data_files[sec].append(filename)
                    target_filename = os.path.join(directory_for(area[area_sec[sec]], current_project), filename)
                    copy_if_different(orig_file, target_filename)
            if filename == 'README.md' and at_top_level:
                with open(orig_file, 'r', encoding='utf-8') as fp:
                    readme_text = fp.read()
            if filename == 'setup.py' and at_top_level:
                with open(orig_file, 'r', encoding='utf-8') as fp:
                    setup_py = fp.read()
            elif len(levels) >= 1 and filename.endswith(
                    '.py') and filename != '__init__.py' and 'tests' not in dirparts and 'data' not in dirparts:
                data_files['modules'].append(filename)
                target_filename = os.path.join(directory_for(area['playgroundmodules'], current_project), filename)
                # output += "Copying " + orig_file + "\n"
                if (not os.path.isfile(target_filename)) or filecmp.cmp(orig_file, target_filename) is False:
                    need_to_restart = True
                copy_if_different(orig_file, target_filename)
    # output += "setup.py is " + str(len(setup_py)) + " characters long\n"
    setup_py = re.sub(r'.*setup\(', '', setup_py, flags=re.DOTALL)
    for line in setup_py.splitlines():
        m = re.search(r"^ *([a-z_]+) *= *\(?'(.*)'", line)
        if m:
            extracted[m.group(1)] = m.group(2)
        m = re.search(r'^ *([a-z_]+) *= *\(?"(.*)"', line)
        if m:
            extracted[m.group(1)] = m.group(2)
        m = re.search(r'^ *([a-z_]+) *= *\[(.*)\]', line)
        if m:
            the_list = []
            for item in re.split(r', *', m.group(2)):
                inner_item = re.sub(r"'$", '', item)
                inner_item = re.sub(r"^'", '', inner_item)
                inner_item = re.sub(r'"+$', '', inner_item)
                inner_item = re.sub(r'^"+', '', inner_item)
                the_list.append(inner_item)
            extracted[m.group(1)] = the_list
    info_dict = dict(readme=readme_text, interview_files=data_files['questions'], sources_files=data_files['sources'],
                     static_files=data_files['static'], module_files=data_files['modules'],
                     template_files=data_files['templates'], dependencies=extracted.get('install_requires', []),
                     description=extracted.get('description', ''), author_name=extracted.get('author', ''),
                     author_email=extracted.get('author_email', ''), license=extracted.get('license', ''),
                     url=extracted.get('url', ''), version=extracted.get('version', ''), github_url=github_url,
                     github_branch=branch, pypi_package_name=pypi_package)
    info_dict['dependencies'] = [x for x in
                                 [z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y), info_dict['dependencies'])] if
                                 x not in ('docassemble', 'docassemble.base', 'docassemble.webapp')]
    # output += "info_dict is set\n"
    package_name = re.sub(r'^docassemble\.', '', extracted.get('name', expected_name))
    # if not user_can_edit_package(pkgname='docassemble.' + package_name):
    #     index = 1
    #     orig_package_name = package_name
    #     while index < 100 and not user_can_edit_package(pkgname='docassemble.' + package_name):
    #         index += 1
    #         package_name = orig_package_name + str(index)
    with open(os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + package_name),
              'w', encoding='utf-8') as fp:
        the_yaml = yaml.safe_dump(info_dict, default_flow_style=False, default_style='|')
        fp.write(str(the_yaml))
    for sec in area:
        area[sec].finalize()
    for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + ':*'):
        r.incr(key.decode())
    return dict(action='finished', need_to_restart=need_to_restart, package_name=package_name)


@playground.route('/pullplaygroundpackage', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def pull_playground_package():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    form = PullPlaygroundPackage(request.form)
    if request.method == 'POST':
        if form.pull.data:
            if form.github_url.data and form.pypi.data:
                flash(word(
                    "You cannot pull from GitHub and PyPI at the same time.  Please fill in one and leave the other blank."),
                    'error')
            elif form.github_url.data:
                return redirect(url_for('playground.playground_packages', project=current_project, pull='1',
                                        github_url=re.sub(r'/*$', '', str(form.github_url.data).strip()),
                                        branch=form.github_branch.data))
            elif form.pypi.data:
                return redirect(url_for('playground.playground_packages', project=current_project, pull='1', pypi=form.pypi.data))
        if form.cancel.data:
            return redirect(url_for('playground.playground_packages', project=current_project))
    elif 'github' in request.args:
        form.github_url.data = re.sub(r'[^A-Za-z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\`]', '',
                                      request.args['github'])
    elif 'pypi' in request.args:
        form.pypi.data = re.sub(r'[^A-Za-z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\`]', '', request.args['pypi'])
    form.github_branch.choices = []
    description = word(
        "Enter a URL of a GitHub repository containing an extension package.  When you press Pull, the contents of that repository will be copied into the Playground, overwriting any files with the same names.  Or, put in the name of a PyPI package and it will do the same with the package on PyPI.")
    branch = request.args.get('branch')
    extra_js = """
    <script>
      var default_branch = """ + json.dumps(branch if branch else GITHUB_BRANCH) + """;
      function get_branches(){
        var elem = $("#github_branch");
        elem.empty();
        var opt = $("<option><\/option>");
        opt.attr("value", "").text("Not applicable");
        elem.append(opt);
        var github_url = $("#github_url").val();
        if (!github_url){
          return;
        }
        $.get(""" + json.dumps(url_for('admin.get_git_branches')) + """, { url: github_url }, "json")
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
        $("#github_url").on('change', get_branches);
      });
    </script>
"""
    response = make_response(render_template('pages/pull_playground_package.html',
                                             current_project=current_project,
                                             form=form,
                                             description=description,
                                             version_warning=version_warning,
                                             bodyclass='daadminbody',
                                             title=word("Pull GitHub or PyPI Package"),
                                             tab_title=word("Pull"),
                                             page_title=word("Pull"),
                                             extra_js=Markup(extra_js)), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def get_branch_info(http, full_name):
    branch_info = []
    resp, content = http.request("https://api.github.com/repos/" + str(full_name) + '/branches', "GET")
    if int(resp['status']) == 200:
        branch_info.extend(json.loads(content.decode()))
        while True:
            next_link = get_next_link(resp)
            if next_link:
                resp, content = http.request(next_link, "GET")
                if int(resp['status']) != 200:
                    raise DAError("get_branch_info: could not get additional information from next URL")
                else:
                    branch_info.extend(json.loads(content))
            else:
                break
    else:
        logmessage(
            "get_branch_info: could not get info from https://api.github.com/repos/" + str(full_name) + '/branches')
    return branch_info


def get_github_username_and_email():
    storage = RedisCredStorage(app='github')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        raise Exception('GitHub integration expired.')
    http = credentials.authorize(httplib2.Http())
    resp, content = http.request("https://api.github.com/user", "GET")
    if int(resp['status']) == 200:
        info = json.loads(content.decode('utf-8', 'ignore'))
        github_user_name = info.get('login', None)
        github_author_name = info.get('name', None)
        github_email = info.get('email', None)
    else:
        raise DAError("playground_packages: could not get information about GitHub User")
    if github_email is None:
        resp, content = http.request("https://api.github.com/user/emails", "GET")
        if int(resp['status']) == 200:
            info = json.loads(content.decode('utf-8', 'ignore'))
            for item in info:
                if item.get('email', None) and item.get('visibility', None) != 'private':
                    github_email = item['email']
    if github_user_name is None or github_email is None:
        raise DAError("playground_packages: login not present in user info from GitHub")
    return github_user_name, github_email, github_author_name


def upload_js():
    return """
        $("#uploadlink").on('click', function(event){
          $("#uploadlabel").click();
          event.preventDefault();
          return false;
        });
        $("#uploadlabel").on('click', function(event){
          event.stopPropagation();
          event.preventDefault();
          $("#uploadfile").click();
          return false;
        });
        $("#uploadfile").on('click', function(event){
          event.stopPropagation();
        });
        $("#uploadfile").on('change', function(event){
          $("#fileform").submit();
        });"""


def github_as_http(url):
    if url.startswith('http'):
        return url
    return re.sub('^[^@]+@([^:]+):(.*)\.git$', r'https://\1/\2', url)


@playground.route('/playgroundpackages', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_packages():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    fix_package_folder()
    current_project = get_current_project()
    form = PlaygroundPackagesForm(request.form)
    fileform = PlaygroundUploadForm(request.form)
    the_file = secure_filename_spaces_ok(request.args.get('file', ''))
    no_file_specified = bool(the_file == '')
    scroll = False
    allow_pypi = daconfig.get('pypi', False)
    pypi_username = current_user.pypi_username
    pypi_password = current_user.pypi_password
    pypi_url = daconfig.get('pypi url', 'https://pypi.python.org/pypi')
    can_publish_to_pypi = bool(
        allow_pypi is True and pypi_username is not None and pypi_password is not None and pypi_username != '' and pypi_password != '')
    if current_app.config['USE_GITHUB']:
        github_auth = r.get('da:using_github:userid:' + str(current_user.id))
        if github_auth is not None:
            github_auth = github_auth.decode()
            if github_auth == '1':
                github_auth_info = dict(shared=True, orgs=True)
            else:
                github_auth_info = json.loads(github_auth)
            can_publish_to_github = True
        else:
            can_publish_to_github = False
    else:
        can_publish_to_github = None
    if can_publish_to_github and request.method == 'GET':
        storage = RedisCredStorage(app='github')
        credentials = storage.get()
        if not credentials or credentials.invalid:
            state_string = random_string(16)
            session['github_next'] = json.dumps(
                dict(state=state_string, path='playground_packages', arguments=request.args))
            flow = get_github_flow()
            uri = flow.step1_get_authorize_url(state=state_string)
            return redirect(uri)
    show_message = true_or_false(request.args.get('show_message', True))
    github_message = None
    pypi_message = None
    pypi_version = None
    package_list, package_auth = get_package_info()
    package_names = sorted([package.package.name for package in package_list])
    for default_package in ('docassemble', 'docassemble.base', 'docassemble.webapp'):
        if default_package in package_names:
            package_names.remove(default_package)
    # if the_file:
    #     scroll = True
    if request.method == 'GET':
        is_new = true_or_false(request.args.get('new', False))
    else:
        is_new = False
    if is_new:
        # scroll = True
        the_file = ''
    area = {}
    file_list = {}
    section_name = {'playground': 'Interview files', 'playgroundpackages': 'Packages',
                    'playgroundtemplate': 'Template files', 'playgroundstatic': 'Static files',
                    'playgroundsources': 'Source files', 'playgroundmodules': 'Modules'}
    section_sec = {'playgroundtemplate': 'template', 'playgroundstatic': 'static', 'playgroundsources': 'sources',
                   'playgroundmodules': 'modules'}
    section_field = {'playground': form.interview_files, 'playgroundtemplate': form.template_files,
                     'playgroundstatic': form.static_files, 'playgroundsources': form.sources_files,
                     'playgroundmodules': form.module_files}
    for sec in ('playground', 'playgroundpackages', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources',
                'playgroundmodules'):
        area[sec] = SavedFile(current_user.id, fix=True, section=sec)
        the_directory = directory_for(area[sec], current_project)
        if sec == 'playground' and current_project != 'default' and not os.path.isdir(the_directory):
            current_project = set_current_project('default')
            the_directory = directory_for(area[sec], current_project)
        file_list[sec] = sorted([f for f in os.listdir(the_directory) if
                                 os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    for sec, field in section_field.items():
        the_list = []
        for item in file_list[sec]:
            the_list.append((item, item))
        field.choices = the_list
    the_list = []
    for item in package_names:
        the_list.append((item, item))
    form.dependencies.choices = the_list
    validated = False
    form.github_branch.choices = []
    if form.github_branch.data:
        form.github_branch.choices.append((form.github_branch.data, form.github_branch.data))
    else:
        form.github_branch.choices.append(('', ''))
    if request.method == 'POST' and 'uploadfile' not in request.files and form.validate():
        the_file = form.file_name.data
        validated = True
        # else:
        # the_error = ''
        # for attrib in ('original_file_name', 'file_name', 'license', 'description', 'author_name', 'author_email', 'version', 'url', 'dependencies', 'interview_files', 'template_files', 'module_files', 'static_files', 'sources_files', 'readme', 'github_branch', 'commit_message', 'submit', 'download', 'install', 'pypi', 'github', 'cancel', 'delete'):
        #     the_field = getattr(form, attrib)
        #     for error in the_field.errors:
        #         the_error += str(error)
        # raise DAError("Form did not validate with " + str(the_error))
    the_file = re.sub(r'[^A-Za-z0-9\-\_\.]+', '-', the_file)
    the_file = re.sub(r'^docassemble-', r'', the_file)
    the_directory = directory_for(area['playgroundpackages'], current_project)
    files = sorted([f for f in os.listdir(the_directory) if
                    os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    editable_files = []
    mode = "yaml"
    for a_file in files:
        editable_files.append(dict(name=re.sub(r'^docassemble.', r'', a_file),
                                   modtime=os.path.getmtime(os.path.join(the_directory, a_file))))
    assign_opacity(editable_files)
    editable_file_listing = [x['name'] for x in editable_files]
    if request.method == 'GET' and not the_file and not is_new:
        current_file = get_current_file(current_project, 'packages')
        if not current_file.startswith('docassemble.'):
            current_file = 'docassemble.' + current_file
            set_current_file(current_project, 'packages', current_file)
        if re.sub(r'^docassemble.', r'', current_file) in editable_file_listing:
            the_file = re.sub(r'^docassemble.', r'', current_file)
        else:
            delete_current_file(current_project, 'packages')
            if len(editable_files) > 0:
                the_file = sorted(editable_files, key=lambda x: x['modtime'])[-1]['name']
            else:
                the_file = ''
    # if the_file != '' and not user_can_edit_package(pkgname='docassemble.' + the_file):
    #    flash(word('Sorry, that package name,') + ' ' + the_file + word(', is already in use by someone else'), 'error')
    #    validated = False
    if request.method == 'GET' and the_file in editable_file_listing:
        set_current_file(current_project, 'packages', 'docassemble.' + the_file)
    if the_file == '' and len(file_list['playgroundpackages']) and not is_new:
        the_file = file_list['playgroundpackages'][0]
        the_file = re.sub(r'^docassemble.', r'', the_file)
    old_info = {}
    on_github = False
    branch_info = []
    github_http = None
    github_ssh = None
    github_use_ssh = False
    github_user_name = None
    github_email = None
    github_author_name = None
    github_url_from_file = None
    pypi_package_from_file = None
    expected_name = 'unknown'
    if request.method == 'GET' and the_file != '':
        if the_file != '' and os.path.isfile(
                os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + the_file)):
            filename = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                    'docassemble.' + the_file)
            with open(filename, 'r', encoding='utf-8') as fp:
                content = fp.read()
                old_info = yaml.load(content, Loader=yaml.FullLoader)
                if isinstance(old_info, dict):
                    github_url_from_file = old_info.get('github_url', None)
                    pypi_package_from_file = old_info.get('pypi_package_name', None)
                    for field in ('license', 'description', 'author_name', 'author_email', 'version', 'url', 'readme'):
                        if field in old_info:
                            form[field].data = old_info[field]
                        else:
                            form[field].data = ''
                    if 'dependencies' in old_info and isinstance(old_info['dependencies'], list) and len(
                            old_info['dependencies']):
                        old_info['dependencies'] = [z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y),
                                                                   old_info['dependencies'])]
                        for item in ('docassemble', 'docassemble.base', 'docassemble.webapp'):
                            if item in old_info['dependencies']:
                                del old_info['dependencies'][item]
                    for field in ('dependencies', 'interview_files', 'template_files', 'module_files', 'static_files',
                                  'sources_files'):
                        if field in old_info and isinstance(old_info[field], list) and len(old_info[field]):
                            form[field].data = old_info[field]
                else:
                    raise Exception("YAML yielded " + repr(old_info) + " from " + repr(content))
        else:
            filename = None
    if the_file != '' and can_publish_to_github and not is_new:
        github_package_name = 'docassemble-' + the_file
        try:
            storage = RedisCredStorage(app='github')
            credentials = storage.get()
            if not credentials or credentials.invalid:
                if form.github.data:
                    state_string = random_string(16)
                    session['github_next'] = json.dumps(
                        dict(state=state_string, path='playground_packages', arguments=request.args))
                    flow = get_github_flow()
                    uri = flow.step1_get_authorize_url(state=state_string)
                    return redirect(uri)
                else:
                    raise Exception('GitHub integration expired.')
            http = credentials.authorize(httplib2.Http())
            resp, content = http.request("https://api.github.com/user", "GET")
            if int(resp['status']) == 200:
                info = json.loads(content.decode('utf-8', 'ignore'))
                github_user_name = info.get('login', None)
                github_author_name = info.get('name', None)
                github_email = info.get('email', None)
            else:
                raise DAError("playground_packages: could not get information about GitHub User")
            if github_email is None:
                resp, content = http.request("https://api.github.com/user/emails", "GET")
                if int(resp['status']) == 200:
                    info = json.loads(content.decode('utf-8', 'ignore'))
                    for item in info:
                        if item.get('email', None) and item.get('visibility', None) != 'private':
                            github_email = item['email']
            if github_user_name is None or github_email is None:
                raise DAError("playground_packages: login not present in user info from GitHub")
            found = False
            found_strong = False
            resp, content = http.request(
                "https://api.github.com/repos/" + str(github_user_name) + "/" + github_package_name, "GET")
            if int(resp['status']) == 200:
                repo_info = json.loads(content.decode('utf-8', 'ignore'))
                github_http = repo_info['html_url']
                github_ssh = repo_info['ssh_url']
                if repo_info['private']:
                    github_use_ssh = True
                github_message = word('This package is') + ' <a target="_blank" href="' + repo_info.get('html_url',
                                                                                                        'about:blank') + '">' + word(
                    "published on GitHub") + '</a>.'
                if github_author_name:
                    github_message += "  " + word("The author is") + " " + github_author_name + "."
                on_github = True
                branch_info = get_branch_info(http, repo_info['full_name'])
                found = True
                if github_url_from_file is None or github_url_from_file in [github_ssh, github_http]:
                    found_strong = True
            if found_strong is False and github_auth_info['shared']:
                repositories = get_user_repositories(http)
                for repo_info in repositories:
                    if repo_info['name'] != github_package_name or (
                            github_http is not None and github_http == repo_info['html_url']) or (
                            github_ssh is not None and github_ssh == repo_info['ssh_url']):
                        continue
                    if found and github_url_from_file is not None and github_url_from_file not in [
                        repo_info['html_url'], repo_info['ssh_url']]:
                        break
                    github_http = repo_info['html_url']
                    github_ssh = repo_info['ssh_url']
                    if repo_info['private']:
                        github_use_ssh = True
                    github_message = word('This package is') + ' <a target="_blank" href="' + repo_info.get('html_url',
                                                                                                            'about:blank') + '">' + word(
                        "published on GitHub") + '</a>.'
                    on_github = True
                    branch_info = get_branch_info(http, repo_info['full_name'])
                    found = True
                    if github_url_from_file is None or github_url_from_file in [github_ssh, github_http]:
                        found_strong = True
                    break
            if found_strong is False and github_auth_info['orgs']:
                orgs_info = get_orgs_info(http)
                for org_info in orgs_info:
                    resp, content = http.request(
                        "https://api.github.com/repos/" + str(org_info['login']) + "/" + github_package_name, "GET")
                    if int(resp['status']) == 200:
                        repo_info = json.loads(content.decode('utf-8', 'ignore'))
                        if found and github_url_from_file is not None and github_url_from_file not in [
                            repo_info['html_url'], repo_info['ssh_url']]:
                            break
                        github_http = repo_info['html_url']
                        github_ssh = repo_info['ssh_url']
                        if repo_info['private']:
                            github_use_ssh = True
                        github_message = word('This package is') + ' <a target="_blank" href="' + repo_info.get(
                            'html_url', 'about:blank') + '">' + word("published on GitHub") + '</a>.'
                        on_github = True
                        branch_info = get_branch_info(http, repo_info['full_name'])
                        found = True
                        if github_url_from_file is None or github_url_from_file in [github_ssh, github_http]:
                            found_strong = True
                        break
            if found is False:
                github_message = word('This package is not yet published on your GitHub account.')
        except Exception as e:
            logmessage('playground_packages: GitHub error.  ' + str(e))
            on_github = None
            github_message = word('Unable to determine if the package is published on your GitHub account.')
    if request.method == 'POST' and 'uploadfile' in request.files:
        the_files = request.files.getlist('uploadfile')
        need_to_restart = False
        if current_user.timezone:
            the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
        else:
            the_timezone = zoneinfo.ZoneInfo(get_default_timezone())
        epoch_date = datetime.datetime(1970, 1, 1).replace(tzinfo=datetime.timezone.utc)
        if the_files:
            for up_file in the_files:
                zip_filename = werkzeug.utils.secure_filename(up_file.filename)
                zippath = tempfile.NamedTemporaryFile(mode="wb", suffix=".zip", prefix="datemp", delete=False)
                up_file.save(zippath.name)
                area_sec = dict(templates='playgroundtemplate', static='playgroundstatic', sources='playgroundsources',
                                questions='playground')
                zippath.close()
                with zipfile.ZipFile(zippath.name, mode='r') as zf:
                    readme_text = ''
                    setup_py = ''
                    extracted = {}
                    data_files = dict(templates=[], static=[], sources=[], interviews=[], modules=[], questions=[])
                    has_docassemble_dir = set()
                    has_setup_file = set()
                    for zinfo in zf.infolist():
                        if zinfo.is_dir():
                            if zinfo.filename.endswith('/docassemble/'):
                                has_docassemble_dir.add(re.sub(r'/docassemble/$', '', zinfo.filename))
                            if zinfo.filename == 'docassemble/':
                                has_docassemble_dir.add('')
                        elif zinfo.filename.endswith('/setup.py'):
                            (directory, filename) = os.path.split(zinfo.filename)
                            has_setup_file.add(directory)
                        elif zinfo.filename == 'setup.py':
                            has_setup_file.add('')
                    root_dir = None
                    for directory in has_docassemble_dir.union(has_setup_file):
                        if root_dir is None or len(directory) < len(root_dir):
                            root_dir = directory
                    if root_dir is None:
                        flash(word("The zip file did not contain a docassemble add-on package."), 'error')
                        return redirect(url_for('playground.playground_packages', project=current_project, file=the_file))
                    for zinfo in zf.infolist():
                        # logmessage("Found a " + zinfo.filename)
                        if zinfo.filename.endswith('/'):
                            continue
                        (directory, filename) = os.path.split(zinfo.filename)
                        if filename.startswith('#') or filename.endswith('~'):
                            continue
                        dirparts = splitall(directory)
                        if '.git' in dirparts:
                            continue
                        levels = re.findall(r'/', directory)
                        time_tuple = zinfo.date_time
                        the_time = time.mktime(datetime.datetime(*time_tuple).timetuple())
                        for sec in ('templates', 'static', 'sources', 'questions'):
                            if directory.endswith('data/' + sec) and filename != 'README.md':
                                data_files[sec].append(filename)
                                target_filename = os.path.join(directory_for(area[area_sec[sec]], current_project),
                                                               filename)
                                with zf.open(zinfo) as source_fp, open(target_filename, 'wb') as target_fp:
                                    shutil.copyfileobj(source_fp, target_fp)
                                os.utime(target_filename, (the_time, the_time))
                        if filename == 'README.md' and directory == root_dir:
                            with zf.open(zinfo) as f:
                                the_file_obj = TextIOWrapper(f, encoding='utf8')
                                readme_text = the_file_obj.read()
                        if filename == 'setup.py' and directory == root_dir:
                            with zf.open(zinfo) as f:
                                the_file_obj = TextIOWrapper(f, encoding='utf8')
                                setup_py = the_file_obj.read()
                        elif len(levels) >= 2 and filename.endswith(
                                '.py') and filename != '__init__.py' and 'tests' not in dirparts and 'data' not in dirparts:
                            need_to_restart = True
                            data_files['modules'].append(filename)
                            target_filename = os.path.join(directory_for(area['playgroundmodules'], current_project),
                                                           filename)
                            with zf.open(zinfo) as source_fp, open(target_filename, 'wb') as target_fp:
                                shutil.copyfileobj(source_fp, target_fp)
                                os.utime(target_filename, (the_time, the_time))
                    setup_py = re.sub(r'.*setup\(', '', setup_py, flags=re.DOTALL)
                    for line in setup_py.splitlines():
                        m = re.search(r"^ *([a-z_]+) *= *\(?'(.*)'", line)
                        if m:
                            extracted[m.group(1)] = m.group(2)
                        m = re.search(r'^ *([a-z_]+) *= *\(?"(.*)"', line)
                        if m:
                            extracted[m.group(1)] = m.group(2)
                        m = re.search(r'^ *([a-z_]+) *= *\[(.*)\]', line)
                        if m:
                            the_list = []
                            for item in re.split(r', *', m.group(2)):
                                inner_item = re.sub(r"'$", '', item)
                                inner_item = re.sub(r"^'", '', inner_item)
                                inner_item = re.sub(r'"+$', '', inner_item)
                                inner_item = re.sub(r'^"+', '', inner_item)
                                the_list.append(inner_item)
                            extracted[m.group(1)] = the_list
                    info_dict = dict(readme=readme_text, interview_files=data_files['questions'],
                                     sources_files=data_files['sources'], static_files=data_files['static'],
                                     module_files=data_files['modules'], template_files=data_files['templates'],
                                     dependencies=[z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y),
                                                                  extracted.get('install_requires', []))],
                                     description=extracted.get('description', ''),
                                     author_name=extracted.get('author', ''),
                                     author_email=extracted.get('author_email', ''),
                                     license=extracted.get('license', ''), url=extracted.get('url', ''),
                                     version=extracted.get('version', ''))

                    info_dict['dependencies'] = [x for x in [z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y),
                                                                            info_dict['dependencies'])] if
                                                 x not in ('docassemble', 'docassemble.base', 'docassemble.webapp')]
                    package_name = re.sub(r'^docassemble\.', '', extracted.get('name', expected_name))
                    with open(os.path.join(directory_for(area['playgroundpackages'], current_project),
                                           'docassemble.' + package_name), 'w', encoding='utf-8') as fp:
                        the_yaml = yaml.safe_dump(info_dict, default_flow_style=False, default_style='|')
                        fp.write(str(the_yaml))
                    for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                            current_project) + ':*'):
                        r.incr(key.decode())
                    for sec in area:
                        area[sec].finalize()
                    the_file = package_name
                zippath.close()
        if show_message:
            flash(word("The package was unpacked into the Playground."), 'success')
        if need_to_restart:
            return redirect(
                url_for('util.restart_page', next=url_for('playground.playground_packages', project=current_project, file=the_file)))
        return redirect(url_for('playground.playground_packages', project=current_project, file=the_file))
    if request.method == 'GET' and 'pull' in request.args and int(request.args['pull']) == 1 and (
            'github_url' in request.args or 'pypi' in request.args):
        if can_publish_to_github and (github_user_name is None or github_email is None):
            (github_user_name, github_email, github_author_name) = get_github_username_and_email()
        github_url = request.args.get('github_url', None)
        pypi_package = request.args.get('pypi', None)
        branch = request.args.get('branch', None)
        do_pypi_also = true_or_false(request.args.get('pypi_also', False))
        do_install_also = true_or_false(request.args.get('install_also', False))
        result = do_playground_pull(area, current_project, github_url=github_url, branch=branch,
                                    pypi_package=pypi_package, can_publish_to_github=can_publish_to_github,
                                    github_email=github_email, pull_only=(do_pypi_also or do_install_also))
        if result['action'] == 'error':
            raise DAError("playground_packages: " + result['message'])
        if result['action'] == 'fail':
            flash(result['message'], 'error')
            return redirect(url_for('playground.playground_packages', project=current_project))
        if result['action'] == 'pull_only':
            the_args = dict(package=the_file, project=current_project)
            if do_pypi_also:
                the_args['pypi'] = '1'
            if do_install_also:
                the_args['install'] = '1'
            area['playgroundpackages'].finalize()
            return redirect(url_for('playground.create_playground_package', **the_args))
        if result['action'] == 'finished':
            the_file = result['package_name']
            if show_message:
                flash(word("The package was unpacked into the Playground."), 'success')
            # shutil.rmtree(directory)
            if result['need_to_restart']:
                return redirect(url_for('util.restart_page',
                                        next=url_for('playground.playground_packages', file=the_file, project=current_project)))
            return redirect(url_for('playground.playground_packages', project=current_project, file=the_file))
    if request.method == 'POST' and validated and form.delete.data and the_file != '' and the_file == form.file_name.data and os.path.isfile(
            os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + the_file)):
        os.remove(os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + the_file))
        dotfile = os.path.join(directory_for(area['playgroundpackages'], current_project), '.docassemble-' + the_file)
        if os.path.exists(dotfile):
            os.remove(dotfile)
        area['playgroundpackages'].finalize()
        flash(word("Deleted package"), "success")
        return redirect(url_for('playground.playground_packages', project=current_project))
    if not is_new:
        pkgname = 'docassemble.' + the_file
        pypi_info = pypi_status(pkgname)
        if can_publish_to_pypi:
            if pypi_info['error']:
                pypi_message = word("Unable to determine if the package is published on PyPI.")
            else:
                if pypi_info['exists'] and 'info' in pypi_info['info']:
                    pypi_version = pypi_info['info']['info'].get('version', None)
                    pypi_message = word(
                        'This package is') + ' <a target="_blank" href="' + pypi_url + '/' + pkgname + '/' + pypi_version + '">' + word(
                        "published on PyPI") + '</a>.'
                    pypi_author = pypi_info['info']['info'].get('author', None)
                    if pypi_author:
                        pypi_message += "  " + word("The author is") + " " + pypi_author + "."
                    if pypi_version != form['version'].data:
                        pypi_message += "  " + word("The version on PyPI is") + " " + str(pypi_version) + ".  " + word(
                            "Your version is") + " " + str(form['version'].data) + "."
                else:
                    pypi_message = word('This package is not yet published on PyPI.')
    if request.method == 'POST' and validated:
        new_info = {}
        for field in (
                'license', 'description', 'author_name', 'author_email', 'version', 'url', 'readme', 'dependencies',
                'interview_files', 'template_files', 'module_files', 'static_files', 'sources_files'):
            new_info[field] = form[field].data
        # logmessage("found " + str(new_info))
        if form.submit.data or form.download.data or form.install.data or form.pypi.data or form.github.data:
            if the_file != '':
                area['playgroundpackages'].finalize()
                if form.original_file_name.data and form.original_file_name.data != the_file:
                    old_filename = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                                'docassemble.' + form.original_file_name.data)
                    if os.path.isfile(old_filename):
                        os.remove(old_filename)
                if form.pypi.data and pypi_version is not None:
                    if not new_info['version']:
                        new_info['version'] = pypi_version
                    while 'releases' in pypi_info['info'] and new_info['version'] in pypi_info['info'][
                        'releases'].keys():
                        versions = new_info['version'].split(".")
                        versions[-1] = str(int(versions[-1]) + 1)
                        new_info['version'] = ".".join(versions)
                filename = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                        'docassemble.' + the_file)
                if os.path.isfile(filename):
                    with open(filename, 'r', encoding='utf-8') as fp:
                        content = fp.read()
                        old_info = yaml.load(content, Loader=yaml.FullLoader)
                    for name in ('github_url', 'github_branch', 'pypi_package_name'):
                        if old_info.get(name, None):
                            new_info[name] = old_info[name]
                with open(filename, 'w', encoding='utf-8') as fp:
                    the_yaml = yaml.safe_dump(new_info, default_flow_style=False, default_style='|')
                    fp.write(str(the_yaml))
                area['playgroundpackages'].finalize()
                if form.download.data:
                    return redirect(url_for('playground.create_playground_package', package=the_file, project=current_project))
                if form.install.data:
                    return redirect(
                        url_for('playground.create_playground_package', package=the_file, project=current_project, install='1'))
                if form.pypi.data:
                    if form.install_also.data:
                        return redirect(
                            url_for('playground.create_playground_package', package=the_file, project=current_project, pypi='1',
                                    install='1'))
                    else:
                        return redirect(
                            url_for('playground.create_playground_package', package=the_file, project=current_project, pypi='1'))
                if form.github.data:
                    the_branch = form.github_branch.data
                    if the_branch == "<new>":
                        the_branch = re.sub(r'[^A-Za-z0-9\_\-]', r'', str(form.github_branch_new.data))
                        return redirect(
                            url_for('playground.create_playground_package', project=current_project, package=the_file, github='1',
                                    commit_message=form.commit_message.data, new_branch=str(the_branch),
                                    pypi_also=('1' if form.pypi_also.data else '0'),
                                    install_also=('1' if form.install_also.data else '0')))
                    else:
                        return redirect(
                            url_for('playground.create_playground_package', project=current_project, package=the_file, github='1',
                                    commit_message=form.commit_message.data, branch=str(the_branch),
                                    pypi_also=('1' if form.pypi_also.data else '0'),
                                    install_also=('1' if form.install_also.data else '0')))
                the_time = formatted_current_time()
                if show_message:
                    flash(word('The package information was saved.'), 'success')
    form.original_file_name.data = the_file
    form.file_name.data = the_file
    if the_file != '' and os.path.isfile(
            os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + the_file)):
        filename = os.path.join(directory_for(area['playgroundpackages'], current_project), 'docassemble.' + the_file)
    else:
        filename = None
    header = word("Packages")
    upload_header = None
    edit_header = None
    description = Markup("""Describe your package and choose the files from your Playground that will go into it.""")
    after_text = None
    if scroll:
        extra_command = "        scrollBottom();"
    else:
        extra_command = ""
    extra_command += upload_js() + """
        $("#daCancelPyPI").click(function(event){
          var daWhichButton = this;
          $("#pypi_message_div").hide();
          $(".btn-da").each(function(){
            if (this != daWhichButton && $(this).attr('id') != 'daCancelGitHub' && $(this).is(":hidden")){
              $(this).show();
            }
          });
          $("#daPyPI").html(""" + json.dumps(word("PyPI")) + """);
          $(this).hide();
          event.preventDefault();
          return false;
        });
        $("#daCancelGitHub").click(function(event){
          var daWhichButton = this;
          $("#commit_message_div").hide();
          $(".btn-da").each(function(){
            if (this != daWhichButton && $(this).attr('id') != 'daCancelPyPI' && $(this).is(":hidden")){
              $(this).show();
            }
          });
          $("#daGitHub").html(""" + json.dumps(word("GitHub")) + """);
          $(this).hide();
          event.preventDefault();
          return false;
        });
        if ($("#github_branch option").length == 0){
          $("#github_branch_div").hide();
        }
        $("#github_branch").on('change', function(event){
          if ($(this).val() == '<new>'){
            $("#new_branch_div").show();
          }
          else{
            $("#new_branch_div").hide();
          }
        });
        $("#daPyPI").click(function(event){
          if (existingPypiVersion != null && existingPypiVersion == $("#version").val()){
            alert(""" + json.dumps(word("You need to increment the version before publishing to PyPI.")) + """);
            $('html, body').animate({
              scrollTop: $("#version").offset().top-90,
              scrollLeft: 0
            });
            $("#version").focus();
            var tmpStr = $("#version").val();
            $("#version").val('');
            $("#version").val(tmpStr);
            event.preventDefault();
            return false;
          }
          var daWhichButton = this;
          if ($("#pypi_message_div").is(":hidden")){
            $("#pypi_message_div").show();
            $(".btn-da").each(function(){
              if (this != daWhichButton && $(this).is(":visible")){
                $(this).hide();
              }
            });
            $(this).html(""" + json.dumps(word("Publish")) + """);
            $("#daCancelPyPI").show();
            window.scrollTo(0, document.body.scrollHeight);
            event.preventDefault();
            return false;
          }
        });
        $("#daGitHub").click(function(event){
          var daWhichButton = this;
          if ($("#commit_message").val().length == 0 || $("#commit_message_div").is(":hidden")){
            if ($("#commit_message_div").is(":visible")){
              $("#commit_message").addClass("is-invalid");
            }
            else{
              $("#commit_message_div").show();
              $(".btn-da").each(function(){
                if (this != daWhichButton && $(this).is(":visible")){
                  $(this).hide();
                }
              });
              $(this).html(""" + json.dumps(word("Commit")) + """);
              $("#daCancelGitHub").show();
            }
            $("#commit_message").focus();
            window.scrollTo(0, document.body.scrollHeight);
            event.preventDefault();
            return false;
          }
          if ($("#pypi_also").prop('checked') && existingPypiVersion != null && existingPypiVersion == $("#version").val()){
            alert(""" + json.dumps(word("You need to increment the version before publishing to PyPI.")) + """);
            $('html, body').animate({
              scrollTop: $("#version").offset().top-90,
              scrollLeft: 0
            });
            $("#version").focus();
            var tmpStr = $("#version").val();
            $("#version").val('');
            $("#version").val(tmpStr);
            event.preventDefault();
            return false;
          }
        });
        $(document).on('keydown', function(e){
          if (e.which == 13){
            var tag = $( document.activeElement ).prop("tagName");
            if (tag != "TEXTAREA" && tag != "A" && tag != "LABEL" && tag != "BUTTON"){
              e.preventDefault();
              e.stopPropagation();
            }
          }
        });"""
    if keymap:
        kbOpt = 'keyMap: "' + keymap + '", cursorBlinkRate: 0, '
        kbLoad = '<script src="' + url_for('static', filename="codemirror/keymap/" + keymap + ".js",
                                           v=da_version) + '"></script>\n    '
    else:
        kbOpt = ''
        kbLoad = ''
    any_files = len(editable_files) > 0
    back_button = Markup('<span class="navbar-brand navbar-nav dabackicon me-3"><a href="' + url_for('playground.playground_page',
                                                                                                     project=current_project) + '" class="dabackbuttoncolor nav-link" title=' + json.dumps(
        word(
            "Go back to the main Playground page")) + '><i class="fas fa-chevron-left"></i><span class="daback">' + word(
        'Back') + '</span></a></span>')
    if can_publish_to_pypi:
        if pypi_message is not None:
            pypi_message = Markup(pypi_message)
    else:
        pypi_message = None
    extra_js = '\n    <script src="' + url_for('static', filename="app/playgroundbundle.js",
                                               v=da_version) + '"></script>\n    '
    extra_js += kbLoad
    extra_js += """<script>
      var existingPypiVersion = """ + json.dumps(pypi_version) + """;
      var isNew = """ + json.dumps(is_new) + """;
      var existingFiles = """ + json.dumps(files) + """;
      var currentFile = """ + json.dumps(the_file) + """;
      var daExpireSession = null;
      function resetExpireSession(){
        if (daExpireSession != null){
          window.clearTimeout(daExpireSession);
        }
        daExpireSession = setTimeout(function(){
          alert(""" + json.dumps(word(
        "Your browser session has expired and you have been signed out.  You will not be able to save your work.  Please log in again.")) + """);
        }, """ + str(999 * int(daconfig.get('session lifetime seconds', 43200))) + """);
      }
      function scrollBottom(){
        $("html, body").animate({ scrollTop: $(document).height() }, "slow");
      }
      $( document ).ready(function() {
        resetExpireSession();
        $("#file_name").on('change', function(){
          var newFileName = $(this).val();
          if ((!isNew) && newFileName == currentFile){
            return;
          }
          for (var i = 0; i < existingFiles.length; i++){
            if (newFileName == existingFiles[i]){
              alert(""" + json.dumps(
        word("Warning: a package definition by that name already exists.  If you save, you will overwrite it.")) + """);
              return;
            }
          }
          return;
        });
        $("#daDelete").click(function(event){
          if (!confirm(""" + '"' + word("Are you sure that you want to delete this package?") + '"' + """)){
            event.preventDefault();
          }
        });
        daTextArea = document.getElementById("readme");
        var daCodeMirror = CodeMirror.fromTextArea(daTextArea, {mode: "markdown", """ + kbOpt + """tabSize: 2, tabindex: 70, autofocus: false, lineNumbers: true, matchBrackets: true, lineWrapping: """ + (
                    'true' if daconfig.get('wrap lines in playground', True) else 'false') + """});
        $(window).bind("beforeunload", function(){
          daCodeMirror.save();
          $("#form").trigger("checkform.areYouSure");
        });
        $("#form").areYouSure(""" + json.dumps(
        {'message': word("There are unsaved changes.  Are you sure you wish to leave this page?")}) + """);
        $("#form").bind("submit", function(){
          daCodeMirror.save();
          $("#form").trigger("reinitialize.areYouSure");
          return true;
        });
        daCodeMirror.setOption("extraKeys", { Tab: function(cm){ var spaces = Array(cm.getOption("indentUnit") + 1).join(" "); cm.replaceSelection(spaces); }, "F11": function(cm) { cm.setOption("fullScreen", !cm.getOption("fullScreen")); }, "Esc": function(cm) { if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false); }});
        daCodeMirror.setOption("coverGutterNextToScrollbar", true);""" + extra_command + """
      });
    </script>"""
    if github_use_ssh:
        the_github_url = github_ssh
    else:
        the_github_url = github_http
    if the_github_url is None and github_url_from_file is not None:
        the_github_url = github_url_from_file
    if the_github_url is None:
        the_pypi_package_name = pypi_package_from_file
    else:
        the_pypi_package_name = None
    if github_message is not None and github_url_from_file is not None and github_url_from_file != github_http and github_url_from_file != github_ssh:
        github_message += '  ' + word(
            "This package was originally pulled from") + ' <a target="_blank" href="' + github_as_http(
            github_url_from_file) + '">' + word('a GitHub repository') + '</a>.'
    if github_message is not None and old_info.get('github_branch', None) and (github_http or github_url_from_file):
        html_url = github_http or github_url_from_file
        commit_code = None
        current_commit_file = os.path.join(directory_for(area['playgroundpackages'], current_project),
                                           '.' + github_package_name)
        if os.path.isfile(current_commit_file):
            with open(current_commit_file, 'r', encoding='utf-8') as fp:
                commit_code = fp.read().strip()
            if current_user.timezone:
                the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
            else:
                the_timezone = zoneinfo.ZoneInfo(get_default_timezone())
            commit_code_date = datetime.datetime.utcfromtimestamp(os.path.getmtime(current_commit_file)).replace(
                tzinfo=datetime.timezone.utc).astimezone(the_timezone).strftime("%Y-%m-%d %H:%M:%S %Z")
        if commit_code:
            github_message += '  ' + word('The current branch is %s and the current commit is %s.') % (
                '<a target="_blank" href="' + html_url + '/tree/' + old_info['github_branch'] + '">' + old_info[
                    'github_branch'] + '</a>',
                '<a target="_blank" href="' + html_url + '/commit/' + commit_code + '"><code>' + commit_code[
                                                                                                 0:7] + '</code></a>') + '  ' + word(
                'The commit was saved locally at %s.') % commit_code_date
        else:
            github_message += '  ' + word('The current branch is %s.') % (
                '<a target="_blank" href="' + html_url + '/tree/' + old_info['github_branch'] + '">' + old_info[
                    'github_branch'] + '</a>',)
    if github_message is not None:
        github_message = Markup(github_message)
    branch = old_info.get('github_branch', None)
    if branch is not None:
        branch = branch.strip()
    branch_choices = []
    if len(branch_info) > 0:
        branch_choices.append(("<new>", word("(New branch)")))
    branch_names = set()
    for br in branch_info:
        branch_names.add(br['name'])
        branch_choices.append((br['name'], br['name']))
    if branch and branch in branch_names:
        form.github_branch.data = branch
        default_branch = branch
    elif 'master' in branch_names:
        form.github_branch.data = 'master'
        default_branch = 'master'
    elif 'main' in branch_names:
        form.github_branch.data = 'main'
        default_branch = 'main'
    else:
        default_branch = GITHUB_BRANCH
    form.github_branch.choices = branch_choices
    if form.author_name.data in ('', None) and current_user.first_name and current_user.last_name:
        form.author_name.data = current_user.first_name + " " + current_user.last_name
    if form.author_email.data in ('', None) and current_user.email:
        form.author_email.data = current_user.email
    if current_project != 'default':
        header += " / " + current_project
    response = make_response(
        render_template('pages/playgroundpackages.html', current_project=current_project, branch=default_branch,
                        version_warning=None, bodyclass='daadminbody', can_publish_to_pypi=can_publish_to_pypi,
                        pypi_message=pypi_message, can_publish_to_github=can_publish_to_github,
                        github_message=github_message, github_url=the_github_url,
                        pypi_package_name=the_pypi_package_name, back_button=back_button, tab_title=header,
                        page_title=header, extra_css=Markup(
                '\n    <link href="' + url_for('static', filename='app/playgroundbundle.css',
                                               v=da_version) + '" rel="stylesheet">'), extra_js=Markup(extra_js),
                        header=header, upload_header=upload_header, edit_header=edit_header, description=description,
                        form=form, fileform=fileform, files=files, file_list=file_list, userid=current_user.id,
                        editable_files=sorted(editable_files, key=lambda y: y['name'].lower()), current_file=the_file,
                        after_text=after_text, section_name=section_name, section_sec=section_sec,
                        section_field=section_field, package_names=sorted(package_names, key=lambda y: y.lower()),
                        any_files=any_files), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@playground.route('/playground_redirect_poll', methods=['GET'])
@login_required
@roles_required(['developer', 'admin'])
def playground_redirect_poll():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    key = 'da:runplayground:' + str(current_user.id)
    the_url = r.get(key)
    # logmessage("playground_redirect: key " + str(key) + " is " + str(the_url))
    if the_url is not None:
        the_url = the_url.decode()
        r.delete(key)
        return jsonify(dict(success=True, url=the_url))
    return jsonify(dict(success=False, url=the_url))


@playground.route('/playground_redirect', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_redirect():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    key = 'da:runplayground:' + str(current_user.id)
    counter = 0
    while counter < 15:
        the_url = r.get(key)
        # logmessage("playground_redirect: key " + str(key) + " is " + str(the_url))
        if the_url is not None:
            the_url = the_url.decode()
            r.delete(key)
            return redirect(the_url)
        time.sleep(1)
        counter += 1
    return ('File not found', 404)


def set_variable_file(current_project, variable_file):
    key = 'da:playground:project:' + str(current_user.id) + ':' + current_project + ':variablefile'
    pipe = r.pipeline()
    pipe.set(key, variable_file)
    pipe.expire(key, 2592000)
    pipe.execute()
    return variable_file


@playground.route('/playgroundvariables', methods=['POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_variables():
    current_project = get_current_project()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    playground = SavedFile(current_user.id, fix=True, section='playground')
    the_directory = directory_for(playground, current_project)
    files = sorted([f for f in os.listdir(the_directory) if
                    os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9]', f)])
    if len(files) == 0:
        return jsonify(success=False, reason=1)
    post_data = request.form.copy()
    if request.method == 'POST' and 'variablefile' in post_data:
        active_file = post_data['variablefile']
        if post_data['variablefile'] in files:
            if 'changed' in post_data and int(post_data['changed']):
                set_variable_file(current_project, active_file)
            interview_source = docassemble.base.parse.interview_source_from_string(
                'docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + active_file)
            interview_source.set_testing(True)
        else:
            if active_file == '' and current_project == 'default':
                active_file = 'test.yml'
            content = ''
            if 'playground_content' in post_data:
                content = re.sub(r'\r\n', r'\n', post_data['playground_content'])
            interview_source = docassemble.base.parse.InterviewSourceString(content=content, directory=the_directory,
                                                                            package="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project),
                                                                            path="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project) + ":" + active_file,
                                                                            testing=True)
        interview = interview_source.get_interview()
        ensure_ml_file_exists(interview, active_file, current_project)
        the_current_info = current_info(
            yaml='docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + active_file,
            req=request, action=None, device_id=request.cookies.get('ds', None))
        docassemble.base.functions.this_thread.current_info = the_current_info
        interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
        variables_html, vocab_list, vocab_dict = get_vars_in_use(interview, interview_status, debug_mode=False,
                                                                 current_project=current_project)
        return jsonify(success=True, variables_html=variables_html, vocab_list=vocab_list,
                       current_project=current_project)
    return jsonify(success=False, reason=2)


@playground.route('/playground_run', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_page_run():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    current_project = get_current_project()
    the_file = secure_filename_spaces_ok(request.args.get('file'))
    if the_file:
        active_interview_string = 'docassemble.playground' + str(current_user.id) + project_name(
            current_project) + ':' + the_file
        the_url = url_for('index.index', reset=1, i=active_interview_string)
        key = 'da:runplayground:' + str(current_user.id)
        # logmessage("Setting key " + str(key) + " to " + str(the_url))
        pipe = r.pipeline()
        pipe.set(key, the_url)
        pipe.expire(key, 25)
        pipe.execute()
        return redirect(url_for('playground.playground_page', file=the_file, project=current_project))
    return redirect(url_for('playground.playground_page', project=current_project))


@playground.route('/playgroundproject', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_project():
    setup_translation()
    use_gd = bool(current_app.config['USE_GOOGLE_DRIVE'] is True and get_gd_folder() is not None)
    use_od = bool(use_gd is False and current_app.config['USE_ONEDRIVE'] is True and get_od_folder() is not None)
    current_project = get_current_project()
    if request.args.get('rename'):
        form = RenameProject(request.form)
        mode = 'rename'
        description = word("You are renaming the project called %s.") % (current_project,)
        page_title = word("Rename project")
        if request.method == 'POST' and form.validate():
            if current_project == 'default':
                flash(word("You cannot rename the default Playground project"), 'error')
            else:
                rename_project(current_user.id, current_project, form.name.data)
                if use_gd:
                    try:
                        rename_gd_project(current_project, form.name.data)
                    except Exception as the_err:
                        logmessage("playground_project: unable to rename project on Google Drive.  " + str(the_err))
                elif use_od:
                    try:
                        rename_od_project(current_project, form.name.data)
                    except Exception as the_err:
                        try:
                            logmessage("playground_project: unable to rename project on OneDrive.  " + str(the_err))
                        except:
                            logmessage("playground_project: unable to rename project on OneDrive.")
                current_project = set_current_project(form.name.data)
                flash(word('Since you renamed a project, the server needs to restart in order to reload any modules.'),
                      'info')
                return redirect(url_for('util.restart_page', next=url_for('playground.playground_project', project=current_project)))
    elif request.args.get('new'):
        form = NewProject(request.form)
        mode = 'new'
        description = word("Enter the name of the new project you want to create.")
        page_title = word("New project")
        if request.method == 'POST' and form.validate():
            if form.name.data == 'default' or form.name.data in get_list_of_projects(current_user.id):
                flash(word("The project name %s is not available.") % (form.name.data,), "error")
            else:
                create_project(current_user.id, form.name.data)
                current_project = set_current_project(form.name.data)
                mode = 'standard'
                return redirect(url_for('playground.playground_page', project=current_project))
    elif request.args.get('delete'):
        form = DeleteProject(request.form)
        mode = 'delete'
        description = word(
            "WARNING!  If you press Delete, the contents of the %s project will be permanently deleted.") % (
                          current_project,)
        page_title = word("Delete project")
        if request.method == 'POST' and form.validate():
            if current_project == 'default':
                flash(word("The default project cannot be deleted."), "error")
            else:
                if use_gd:
                    try:
                        trash_gd_project(current_project)
                    except Exception as the_err:
                        logmessage("playground_project: unable to delete project on Google Drive.  " + str(the_err))
                elif use_od:
                    try:
                        trash_od_project(current_project)
                    except Exception as the_err:
                        try:
                            logmessage("playground_project: unable to delete project on OneDrive.  " + str(the_err))
                        except:
                            logmessage("playground_project: unable to delete project on OneDrive.")
                delete_project(current_user.id, current_project)
                flash(word("The project %s was deleted.") % (current_project,), "success")
                current_project = set_current_project('default')
                return redirect(url_for('playground.playground_project', project=current_project))
    else:
        form = None
        mode = 'standard'
        page_title = word("Projects")
        description = word(
            "You can divide up your Playground into multiple separate areas, apart from your default Playground area.  Each Project has its own question files and Folders.")
    back_button = Markup('<span class="navbar-brand navbar-nav dabackicon me-3"><a href="' + url_for('playground.playground_page',
                                                                                                     project=current_project) + '" class="dabackbuttoncolor nav-link" title=' + json.dumps(
        word(
            "Go back to the main Playground page")) + '><i class="fas fa-chevron-left"></i><span class="daback">' + word(
        'Back') + '</span></a></span>')
    response = make_response(
        render_template('pages/manage_projects.html', version_warning=None, bodyclass='daadminbody',
                        back_button=back_button, tab_title=word("Projects"), description=description,
                        page_title=page_title, projects=get_list_of_projects(current_user.id),
                        current_project=current_project, mode=mode, form=form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response



def proc_example_list(example_list, package, directory, examples):
    for example in example_list:
        if isinstance(example, dict):
            for key, value in example.items():
                sublist = []
                proc_example_list(value, package, directory, sublist)
                examples.append({'title': str(key), 'list': sublist})
                break
            continue
        result = {}
        result['id'] = example
        result['interview'] = url_for('index.index', reset=1, i=package + ":data/questions/" + directory + example + ".yml")
        example_file = package + ":data/questions/" + directory + example + '.yml'
        if package == 'docassemble.base':
            result['image'] = url_for('static', filename=directory + example + ".png", v=da_version)
        else:
            result['image'] = url_for('files.package_static', package=package, filename=example + ".png")
        file_info = get_info_from_file_reference(example_file)
        start_block = 1
        end_block = 2
        if 'fullpath' not in file_info or file_info['fullpath'] is None:
            logmessage("proc_example_list: could not find " + example_file)
            continue
        with open(file_info['fullpath'], 'r', encoding='utf-8') as fp:
            content = fp.read()
            content = fix_tabs.sub('  ', content)
            content = fix_initial.sub('', content)
            blocks = list(map(lambda x: x.strip(), document_match.split(content)))
            if len(blocks) > 0:
                has_context = False
                for block in blocks:
                    if re.search(r'metadata:', block):
                        try:
                            the_block = ruamel.yaml.safe_load(block)
                            if isinstance(the_block, dict) and 'metadata' in the_block:
                                the_metadata = the_block['metadata']
                                result['title'] = the_metadata.get('title',
                                                                   the_metadata.get('short title', word('Untitled')))
                                if isinstance(result['title'], dict):
                                    result['title'] = result['title'].get('en', word('Untitled'))
                                result['title'] = result['title'].rstrip()
                                result['documentation'] = the_metadata.get('documentation', None)
                                start_block = int(the_metadata.get('example start', 1))
                                end_block = int(the_metadata.get('example end', start_block)) + 1
                                break
                        except Exception as err:
                            logmessage("proc_example_list: error processing " + example_file + ": " + str(err))
                            continue
                if 'title' not in result:
                    logmessage("proc_example_list: no title in " + example_file)
                    continue
                if re.search(r'metadata:', blocks[0]) and start_block > 0:
                    initial_block = 1
                else:
                    initial_block = 0
                if start_block > initial_block:
                    result['before_html'] = highlight("\n---\n".join(blocks[initial_block:start_block]) + "\n---",
                                                      YamlLexer(), HtmlFormatter())
                    has_context = True
                else:
                    result['before_html'] = ''
                if len(blocks) > end_block:
                    result['after_html'] = highlight("---\n" + "\n---\n".join(blocks[end_block:len(blocks)]),
                                                     YamlLexer(), HtmlFormatter())
                    has_context = True
                else:
                    result['after_html'] = ''
                result['source'] = "\n---\n".join(blocks[start_block:end_block])
                result['html'] = highlight(result['source'], YamlLexer(), HtmlFormatter())
                result['has_context'] = has_context
            else:
                logmessage("proc_example_list: no blocks in " + example_file)
                continue
        examples.append(result)

def get_examples():
    examples = []
    file_list = daconfig.get('playground examples', ['docassemble.base:data/questions/example-list.yml'])
    if not isinstance(file_list, list):
        file_list = [file_list]
    for the_file in file_list:
        if not isinstance(the_file, str):
            continue
        example_list_file = get_info_from_file_reference(the_file)
        if 'fullpath' in example_list_file and example_list_file['fullpath'] is not None:
            if 'package' in example_list_file:
                the_package = example_list_file['package']
            else:
                continue
            if the_package == 'docassemble.base':
                the_directory = 'examples/'
            else:
                the_directory = ''
            if os.path.exists(example_list_file['fullpath']):
                try:
                    with open(example_list_file['fullpath'], 'r', encoding='utf-8') as fp:
                        content = fp.read()
                        content = fix_tabs.sub('  ', content)
                        proc_example_list(ruamel.yaml.safe_load(content), the_package, the_directory, examples)
                except Exception as the_err:
                    logmessage("There was an error loading the Playground examples:" + str(the_err))
    return examples


def make_example_html(examples, first_id, example_html, data_dict):
    example_html.append('          <ul class="nav flex-column nav-pills da-example-list da-example-hidden">\n')
    for example in examples:
        if 'list' in example:
            example_html.append(
                '          <li class="nav-item"><a tabindex="0" class="nav-link da-example-heading">' + example[
                    'title'] + '</a>')
            make_example_html(example['list'], first_id, example_html, data_dict)
            example_html.append('          </li>')
            continue
        if len(first_id) == 0:
            first_id.append(example['id'])
        example_html.append(
            '            <li class="nav-item"><a tabindex="0" class="nav-link da-example-link" data-example="' +
            example['id'] + '">' + example['title'] + '</a></li>')
        data_dict[example['id']] = example
    example_html.append('          </ul>')


def define_examples():
    if 'encoded_example_html' in pg_ex:
        return
    example_html = []
    example_html.append('        <div class="col-md-2">\n          <h5 class="mb-1">Example blocks</h5>')
    pg_ex['pg_first_id'] = []
    data_dict = {}
    make_example_html(get_examples(), pg_ex['pg_first_id'], example_html, data_dict)
    example_html.append('        </div>')
    example_html.append('        <div class="col-md-4 da-example-source-col"><h5 class="mb-1">' + word(
        'Source') + '<a href="#" tabindex="0" class="dabadge btn btn-success da-example-copy">' + word(
        "Insert") + '</a></h5><div id="da-example-source-before" class="dainvisible"></div><div id="da-example-source"></div><div id="da-example-source-after" class="dainvisible"></div><div><a tabindex="0" class="da-example-hider" id="da-show-full-example">' + word(
        "Show context of example") + '</a><a tabindex="0" class="da-example-hider dainvisible" id="da-hide-full-example">' + word(
        "Hide context of example") + '</a></div></div>')
    example_html.append('        <div class="col-md-6"><h5 class="mb-1">' + word(
        "Preview") + '<a href="#" target="_blank" class="dabadge btn btn-primary da-example-documentation da-example-hidden" id="da-example-documentation-link">' + word(
        "View documentation") + '</a></h5><a href="#" target="_blank" id="da-example-image-link"><img title=' + json.dumps(
        word("Click to try this interview")) + ' class="da-example-screenshot" id="da-example-image"></a></div>')
    pg_ex['encoded_data_dict'] = safeid(json.dumps(data_dict))
    pg_ex['encoded_example_html'] = Markup("\n".join(example_html))


pg_ex = {}


@playground.route('/playground', methods=['GET', 'POST'])
@login_required
@roles_required(['developer', 'admin'])
def playground_page():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    current_project = get_current_project()
    if 'ajax' in request.form and int(request.form['ajax']):
        is_ajax = True
        use_gd = False
        use_od = False
    else:
        is_ajax = False
        use_gd = bool(current_app.config['USE_GOOGLE_DRIVE'] is True and get_gd_folder() is not None)
        use_od = bool(use_gd is False and current_app.config['USE_ONEDRIVE'] is True and get_od_folder() is not None)
        if request.method == 'GET' and needs_to_change_password():
            return redirect(url_for('user.change_password', next=url_for('playground.playground_page', project=current_project)))
    fileform = PlaygroundUploadForm(request.form)
    form = PlaygroundForm(request.form)
    interview = None
    the_file = secure_filename_spaces_ok(request.args.get('file', get_current_file(current_project, 'questions')))
    valid_form = None
    if request.method == 'POST':
        valid_form = form.validate()
    if request.method == 'GET':
        is_new = true_or_false(request.args.get('new', False))
        debug_mode = true_or_false(request.args.get('debug', False))
    else:
        debug_mode = False
        is_new = bool(not valid_form and form.status.data == 'new')
    if is_new:
        the_file = ''
    playground = SavedFile(current_user.id, fix=True, section='playground')
    the_directory = directory_for(playground, current_project)
    if current_project != 'default' and not os.path.isdir(the_directory):
        current_project = set_current_project('default')
        the_directory = directory_for(playground, current_project)
    if request.method == 'POST' and 'uploadfile' in request.files:
        the_files = request.files.getlist('uploadfile')
        if the_files:
            for up_file in the_files:
                try:
                    filename = secure_filename(up_file.filename)
                    extension, mimetype = get_ext_and_mimetype(filename)
                    if extension not in ('yml', 'yaml'):
                        flash(word(
                            "Sorry, only YAML files can be uploaded here.  To upload other types of files, use the Folders."),
                            'error')
                        return redirect(url_for('playground.playground_page', project=current_project))
                    filename = re.sub(r'[^A-Za-z0-9\-\_\. ]+', '_', filename)
                    new_file = filename
                    filename = os.path.join(the_directory, filename)
                    up_file.save(filename)
                    try:
                        with open(filename, 'r', encoding='utf-8') as fp:
                            fp.read()
                    except:
                        os.remove(filename)
                        flash(word(
                            "There was a problem reading the YAML file you uploaded.  Are you sure it is a YAML file?  File was not saved."),
                            'error')
                        return redirect(url_for('playground.playground_page', project=current_project))
                    playground.finalize()
                    r.incr('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':' + new_file)
                    return redirect(
                        url_for('playground.playground_page', project=current_project, file=os.path.basename(filename)))
                except Exception as errMess:
                    flash("Error of type " + str(type(errMess)) + " processing upload: " + str(errMess), "error")
        return redirect(url_for('playground.playground_page', project=current_project))
    if request.method == 'POST' and (form.submit.data or form.run.data or form.delete.data):
        if valid_form and form.playground_name.data:
            the_file = secure_filename_spaces_ok(form.playground_name.data)
            # the_file = re.sub(r'[^A-Za-z0-9\_\-\. ]', '', the_file)
            if the_file != '':
                if not re.search(r'\.ya?ml$', the_file):
                    the_file = re.sub(r'\..*', '', the_file) + '.yml'
                filename = os.path.join(the_directory, the_file)
                if not os.path.isfile(filename):
                    with open(filename, 'a', encoding='utf-8'):
                        os.utime(filename, None)
            else:
                # flash(word('You need to type in a name for the interview'), 'error')
                is_new = True
        else:
            # flash(word('You need to type in a name for the interview'), 'error')
            is_new = True
    # the_file = re.sub(r'[^A-Za-z0-9\_\-\. ]', '', the_file)
    files = sorted(
        [dict(name=f, modtime=os.path.getmtime(os.path.join(the_directory, f))) for f in os.listdir(the_directory) if
         os.path.isfile(os.path.join(the_directory, f)) and re.search(r'^[A-Za-z0-9].*[A-Za-z]$', f)],
        key=lambda x: x['name'])
    file_listing = [x['name'] for x in files]
    assign_opacity(files)
    if valid_form is False:
        content = form.playground_content.data
    else:
        content = ''
    if the_file and not is_new and the_file not in file_listing:
        if request.method == 'GET':
            delete_current_file(current_project, 'questions')
            return redirect(url_for('playground.playground_page', project=current_project))
        the_file = ''
    is_default = False
    if request.method == 'GET' and not the_file and not is_new:
        current_file = get_current_file(current_project, 'questions')
        if current_file in files:
            the_file = current_file
        else:
            delete_current_file(current_project, 'questions')
            if len(files) > 0:
                the_file = sorted(files, key=lambda x: x['modtime'])[-1]['name']
            elif current_project == 'default':
                the_file = 'test.yml'
                is_default = True
                content = default_playground_yaml
            else:
                the_file = ''
                is_default = False
                content = ''
                is_new = True
    if the_file in file_listing:
        set_current_file(current_project, 'questions', the_file)
    active_file = the_file
    current_variable_file = get_variable_file(current_project)
    if current_variable_file is not None:
        if current_variable_file in file_listing:
            active_file = current_variable_file
        else:
            delete_variable_file(current_project)
    if the_file != '':
        filename = os.path.join(the_directory, the_file)
        if (valid_form or is_default) and not os.path.isfile(filename):
            with open(filename, 'w', encoding='utf-8') as fp:
                fp.write(content)
            playground.finalize()
    console_messages = []
    if request.method == 'POST' and the_file != '' and valid_form:
        if form.delete.data:
            filename_to_del = os.path.join(the_directory, form.playground_name.data)
            if os.path.isfile(filename_to_del):
                os.remove(filename_to_del)
                flash(word('File deleted.'), 'info')
                r.delete('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                    current_project) + ':' + the_file)
                if active_file != the_file:
                    r.incr('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                        current_project) + ':' + active_file)
                cloud_trash(use_gd, use_od, 'questions', form.playground_name.data, current_project)
                playground.finalize()
                current_variable_file = get_variable_file(current_project)
                if current_variable_file == the_file or current_variable_file == form.playground_name.data:
                    delete_variable_file(current_project)
                delete_current_file(current_project, 'questions')
                return redirect(url_for('playground.playground_page', project=current_project))
            else:
                flash(word('File not deleted.  There was an error.'), 'error')
        if (form.submit.data or form.run.data):
            if form.original_playground_name.data and form.original_playground_name.data != the_file:
                old_filename = os.path.join(the_directory, form.original_playground_name.data)
                if not is_ajax:
                    flash(word("Changed name of interview"), 'success')
                cloud_trash(use_gd, use_od, 'questions', form.original_playground_name.data, current_project)
                if os.path.isfile(old_filename):
                    os.remove(old_filename)
                    files = sorted([dict(name=f, modtime=os.path.getmtime(os.path.join(the_directory, f))) for f in
                                    os.listdir(the_directory) if
                                    os.path.isfile(os.path.join(the_directory, f)) and re.search(
                                        r'^[A-Za-z0-9].*[A-Za-z]$', f)], key=lambda x: x['name'])
                    file_listing = [x['name'] for x in files]
                    assign_opacity(files)
            the_time = formatted_current_time()
            should_save = True
            the_content = re.sub(r'\r\n', r'\n', form.playground_content.data)
            if os.path.isfile(filename):
                with open(filename, 'r', encoding='utf-8') as fp:
                    orig_content = fp.read()
                    if orig_content == the_content:
                        # logmessage("No need to save")
                        should_save = False
            if should_save:
                with open(filename, 'w', encoding='utf-8') as fp:
                    fp.write(the_content)
            if not form.submit.data and active_file != the_file:
                active_file = the_file
                set_variable_file(current_project, active_file)
            this_interview_string = 'docassemble.playground' + str(current_user.id) + project_name(
                current_project) + ':' + the_file
            active_interview_string = 'docassemble.playground' + str(current_user.id) + project_name(
                current_project) + ':' + active_file
            r.incr('da:interviewsource:' + this_interview_string)
            if the_file != active_file:
                r.incr('da:interviewsource:' + active_interview_string)
            playground.finalize()
            docassemble.base.interview_cache.clear_cache(this_interview_string)
            if active_interview_string != this_interview_string:
                docassemble.base.interview_cache.clear_cache(active_interview_string)
            if not form.submit.data:
                the_url = url_for('index.index', reset=1, i=this_interview_string)
                key = 'da:runplayground:' + str(current_user.id)
                # logmessage("Setting key " + str(key) + " to " + str(the_url))
                pipe = r.pipeline()
                pipe.set(key, the_url)
                pipe.expire(key, 12)
                pipe.execute()
            try:
                interview_source = docassemble.base.parse.interview_source_from_string(active_interview_string)
                interview_source.set_testing(True)
                interview = interview_source.get_interview()
                ensure_ml_file_exists(interview, active_file, current_project)
                the_current_info = current_info(yaml='docassemble.playground' + str(current_user.id) + project_name(
                    current_project) + ':' + active_file, req=request, action=None,
                                                device_id=request.cookies.get('ds', None))
                docassemble.base.functions.this_thread.current_info = the_current_info
                interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
                variables_html, vocab_list, vocab_dict = get_vars_in_use(interview, interview_status,
                                                                         debug_mode=debug_mode,
                                                                         current_project=current_project)
                if form.submit.data:
                    flash_message = flash_as_html(word('Saved at') + ' ' + the_time + '.', 'success', is_ajax=is_ajax)
                else:
                    flash_message = flash_as_html(
                        word('Saved at') + ' ' + the_time + '.  ' + word('Running in other tab.'),
                        message_type='success', is_ajax=is_ajax)
                if interview.issue.get('mandatory_id', False):
                    console_messages.append(
                        word("Note: it is a best practice to tag every mandatory block with an id."))
                if interview.issue.get('id_collision', False):
                    console_messages.append(
                        word("Note: more than one block uses id") + " " + interview.issue['id_collision'])
            except DAError as foo:
                variables_html = None
                flash_message = flash_as_html(word('Saved at') + ' ' + the_time + '.  ' + word('Problem detected.'),
                                              message_type='error', is_ajax=is_ajax)
            if is_ajax:
                return jsonify(variables_html=variables_html, vocab_list=vocab_list, flash_message=flash_message,
                               current_project=current_project, console_messages=console_messages,
                               active_file=active_file,
                               active_interview_url=url_for('index.index', i=active_interview_string))
        else:
            flash(word('Playground not saved.  There was an error.'), 'error')
    interview_path = None
    if valid_form is not False and the_file != '':
        with open(filename, 'r', encoding='utf-8') as fp:
            form.original_playground_name.data = the_file
            form.playground_name.data = the_file
            content = fp.read()
            # if not form.playground_content.data:
            # form.playground_content.data = content
    if active_file != '':
        is_fictitious = False
        interview_path = 'docassemble.playground' + str(current_user.id) + project_name(
            current_project) + ':' + active_file
        if is_default:
            interview_source = docassemble.base.parse.InterviewSourceString(content=content, directory=the_directory,
                                                                            package="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project),
                                                                            path="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project) + ":" + active_file,
                                                                            testing=True)
        else:
            interview_source = docassemble.base.parse.interview_source_from_string(interview_path)
            interview_source.set_testing(True)
    else:
        is_fictitious = True
        if current_project == 'default':
            active_file = 'test.yml'
        else:
            is_new = True
        if form.playground_content.data:
            content = re.sub(r'\r', '', form.playground_content.data)
            interview_source = docassemble.base.parse.InterviewSourceString(content=content, directory=the_directory,
                                                                            package="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project),
                                                                            path="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project) + ":" + active_file,
                                                                            testing=True)
        else:
            interview_source = docassemble.base.parse.InterviewSourceString(content='', directory=the_directory,
                                                                            package="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project),
                                                                            path="docassemble.playground" + str(
                                                                                current_user.id) + project_name(
                                                                                current_project) + ":" + active_file,
                                                                            testing=True)
    interview = interview_source.get_interview()
    if hasattr(interview, 'mandatory_id_issue') and interview.mandatory_id_issue:
        console_messages.append(word("Note: it is a best practice to tag every mandatory block with an id."))
    the_current_info = current_info(
        yaml='docassemble.playground' + str(current_user.id) + project_name(current_project) + ':' + active_file,
        req=request, action=None, device_id=request.cookies.get('ds', None))
    docassemble.base.functions.this_thread.current_info = the_current_info
    interview_status = docassemble.base.parse.InterviewStatus(current_info=the_current_info)
    variables_html, vocab_list, vocab_dict = get_vars_in_use(interview, interview_status, debug_mode=debug_mode,
                                                             current_project=current_project)
    pulldown_files = [x['name'] for x in files]
    define_examples()
    if is_fictitious or is_new or is_default:
        new_active_file = word('(New file)')
        if new_active_file not in pulldown_files:
            pulldown_files.insert(0, new_active_file)
        if is_fictitious:
            active_file = new_active_file
    ajax = """
var exampleData;
var originalFileName = """ + json.dumps(the_file) + """;
var isNew = """ + json.dumps(is_new) + """;
var validForm = """ + json.dumps(valid_form) + """;
var vocab = """ + json.dumps(vocab_list) + """;
var existingFiles = """ + json.dumps(file_listing) + """;
var currentProject = """ + json.dumps(current_project) + """;
var currentFile = """ + json.dumps(the_file) + """;
var attrs_showing = Object();
var daExpireSession = null;
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

function resetExpireSession(){
  if (daExpireSession != null){
    window.clearTimeout(daExpireSession);
  }
  daExpireSession = setTimeout(function(){
    alert(""" + json.dumps(word(
        "Your browser session has expired and you have been signed out.  You will not be able to save your work.  Please log in again.")) + """);
  }, """ + str(999 * int(daconfig.get('session lifetime seconds', 43200))) + """);
}

""" + variables_js() + """

""" + search_js() + """

function activateExample(id, scroll){
  var info = exampleData[id];
  $("#da-example-source").html(info['html']);
  $("#da-example-source-before").html(info['before_html']);
  $("#da-example-source-after").html(info['after_html']);
  $("#da-example-image-link").attr("href", info['interview']);
  $("#da-example-image").attr("src", info['image']);
  if (info['documentation'] != null){
    $("#da-example-documentation-link").attr("href", info['documentation']);
    $("#da-example-documentation-link").removeClass("da-example-hidden");
    //$("#da-example-documentation-link").slideUp();
  }
  else{
    $("#da-example-documentation-link").addClass("da-example-hidden");
    //$("#da-example-documentation-link").slideDown();
  }
  $(".da-example-list").addClass("da-example-hidden");
  $(".da-example-link").removeClass("da-example-active");
  $(".da-example-link").removeClass("active");
  $(".da-example-link").each(function(){
    if ($(this).data("example") == id){
      $(this).addClass("da-example-active");
      $(this).addClass("active");
      $(this).parents(".da-example-list").removeClass("da-example-hidden");
      if (scroll){
        setTimeout(function(){
          //console.log($(this).parents("li").last()[0].offsetTop);
          //console.log($(this).parents("li").last().parent()[0].offsetTop);
          $(".da-example-active").parents("ul").last().scrollTop($(".da-example-active").parents("li").last()[0].offsetTop);
        }, 0);
      }
      //$(this).parents(".da-example-list").slideDown();
    }
  });
  $("#da-hide-full-example").addClass("dainvisible");
  if (info['has_context']){
    $("#da-show-full-example").removeClass("dainvisible");
  }
  else{
    $("#da-show-full-example").addClass("dainvisible");
  }
  $("#da-example-source-before").addClass("dainvisible");
  $("#da-example-source-after").addClass("dainvisible");
}

function daFetchVariableReportCallback(data){
  var translations = """ + json.dumps(
        {'in mako': word("in mako"), 'mentioned in': word("mentioned in"), 'defined by': word("defined by")}) + """;
  var modal = $("#daVariablesReport .modal-body");
  if (modal.length == 0){
    console.log("No modal body on page");
    return;
  }
  if (!data.success){
    $(modal).html('<p>""" + word("Failed to load report") + """</p>');
    return;
  }
  var yaml_file = data.yaml_file;
  console.log(yaml_file)
  modal.empty();
  var accordion = $('<div>');
  accordion.addClass("accordion");
  accordion.attr("id", "varsreport");
  var n = data.items.length;
  for (var i = 0; i < n; ++i){
    var item = data.items[i];
    if (item.questions.length){
      var accordionItem = $('<div>');
      accordionItem.addClass("accordion-item");
      var accordionItemHeader = $('<h2>');
      accordionItemHeader.addClass("accordion-header");
      accordionItemHeader.attr("id", "accordionItemheader" + i);
      accordionItemHeader.html('<button class="accordion-button" type="button" data-bs-toggle="collapse" data-bs-target="#collapse' + i + '" aria-expanded="false" aria-controls="collapse' + i + '">' + item.name + '</button>');
      accordionItem.append(accordionItemHeader);
      var collapse = $("<div>");
      collapse.attr("id", "collapse" + i);
      collapse.attr("aria-labelledby", "accordionItemheader" + i);
      collapse.data("parent", "#varsreport");
      collapse.addClass("accordion-collapse");
      collapse.addClass("collapse");
      var accordionItemBody = $("<div>");
      accordionItemBody.addClass("accordion-body");
      var m = item.questions.length;
      for (var j = 0; j < m; j++){
        var h5 = $("<h5>");
        h5.html(item.questions[j].usage.map(x => translations[x]).join(','));
        var pre = $("<pre>");
        pre.html(item.questions[j].source_code);
        accordionItemBody.append(h5);
        accordionItemBody.append(pre);
        if (item.questions[j].yaml_file != yaml_file){
          var p = $("<p>");
          p.html(""" + json.dumps(word("from")) + """ + ' ' + item.questions[j].yaml_file);
          accordionItemBody.append(p);
        }
      }
      collapse.append(accordionItemBody);
      accordionItem.append(collapse);
      accordion.append(accordionItem);
    }
  }
  modal.append(accordion);
}

function daFetchVariableReport(){
  url = """ + json.dumps(url_for('admin.variables_report', project=current_project)) + """ + "&file=" + currentFile;
  $("#daVariablesReport .modal-body").html('<p>""" + word("Loading . . .") + """</p>');
  $.ajax({
    type: "GET",
    url: url,
    success: daFetchVariableReportCallback,
    xhrFields: {
      withCredentials: true
    },
    error: function(xhr, status, error){
      $("#daVariablesReport .modal-body").html('<p>""" + word("Failed to load report") + """</p>');
    }
  });
}

function saveCallback(data){
  if (data.action && data.action == 'reload'){
    location.reload(true);
  }
  if ($("#daflash").length){
    $("#daflash").html(data.flash_message);
  }
  else{
    $("#damain").prepend(daSprintf(daNotificationContainer, data.flash_message));
  }
  if (data.vocab_list != null){
    vocab = data.vocab_list;
  }
  if (data.current_project != null){
    currentProject = data.current_project;
  }
  history.replaceState({}, "", """ + json.dumps(url_for('playground.playground_page')) + """ + encodeURI('?project=' + currentProject + '&file=' + currentFile));
  $("#daVariables").val(data.active_file);
  $("#share-link").attr('href', data.active_interview_url);
  if (data.variables_html != null){
    $("#daplaygroundtable").html(data.variables_html);
    activateVariables();
    $("#form").trigger("reinitialize.areYouSure");
    var daPopoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var daPopoverList = daPopoverTriggerList.map(function (daPopoverTriggerEl) {
      return new bootstrap.Popover(daPopoverTriggerEl, {trigger: "focus", html: true});
    });
  }
  daConsoleMessages = data.console_messages;
  daShowConsoleMessages();
}

function daShowConsoleMessages(){
  for (i=0; i < daConsoleMessages.length; ++i){
    console.log(daConsoleMessages[i]);
  }
}

function disableButtonsUntilCallback(){
  $("button.dasubmitbutton").prop('disabled', true);
  $("a.dasubmitbutton").addClass('dadisabled');
}

function enableButtons(){
  $(".dasubmitbutton").prop('disabled', false);
  $("a.dasubmitbutton").removeClass('dadisabled');
}

$( document ).ready(function() {
  variablesReady();
  searchReady();
  resetExpireSession();
  $("#playground_name").on('change', function(){
    var newFileName = $(this).val();
    if ((!isNew) && newFileName == currentFile){
      return;
    }
    for (var i = 0; i < existingFiles.length; i++){
      if (newFileName == existingFiles[i] || newFileName + '.yml' == existingFiles[i]){
        alert(""" + json.dumps(
        word("Warning: a file by that name already exists.  If you save, you will overwrite it.")) + """);
        return;
      }
    }
    return;
  });
  $("#daRun").click(function(event){
    if (originalFileName != $("#playground_name").val() || $("#playground_name").val() == ''){
      $("#form button[name='submit']").click();
      event.preventDefault();
      return false;
    }
    daCodeMirror.save();
    disableButtonsUntilCallback();
    $.ajax({
      type: "POST",
      url: """ + '"' + url_for('playground.playground_page', project=current_project) + '"' + """,
      data: $("#form").serialize() + '&run=Save+and+Run&ajax=1',
      success: function(data){
        if (data.action && data.action == 'reload'){
          location.reload(true);
        }
        enableButtons();
        resetExpireSession();
        saveCallback(data);
      },
      dataType: 'json'
    });
    //event.preventDefault();
    return true;
  });
  var thisWindow = window;
  $("#daRunSyncGD").click(function(event){
    daCodeMirror.save();
    $("#form").trigger("checkform.areYouSure");
    if ($('#form').hasClass('dirty') && !confirm(""" + json.dumps(
        word("There are unsaved changes.  Are you sure you wish to leave this page?")) + """)){
      event.preventDefault();
      return false;
    }
    if ($("#playground_name").val() == ''){
      $("#form button[name='submit']").click();
      event.preventDefault();
      return false;
    }
    thisWindow.location.replace('""" + url_for('google_drive.sync_with_google_drive', project=current_project,
                                               auto_next=url_for('playground.playground_page_run', file=the_file,
                                                                 project=current_project)) + """');
    return true;
  });
  $("#daRunSyncOD").click(function(event){
    daCodeMirror.save();
    $("#form").trigger("checkform.areYouSure");
    if ($('#form').hasClass('dirty') && !confirm(""" + json.dumps(
        word("There are unsaved changes.  Are you sure you wish to leave this page?")) + """)){
      event.preventDefault();
      return false;
    }
    if ($("#playground_name").val() == ''){
      $("#form button[name='submit']").click();
      event.preventDefault();
      return false;
    }
    thisWindow.location.replace('""" + url_for('one_drive.sync_with_onedrive', project=current_project,
                                               auto_next=url_for('playground.playground_page_run', file=the_file,
                                                                 project=current_project)) + """');
  });
  $("#form button[name='submit']").click(function(event){
    daCodeMirror.save();
    if (validForm == false || isNew == true || originalFileName != $("#playground_name").val() || $("#playground_name").val().trim() == ""){
      return true;
    }
    disableButtonsUntilCallback();
    $.ajax({
      type: "POST",
      url: """ + '"' + url_for('playground.playground_page', project=current_project) + '"' + """,
      data: $("#form").serialize() + '&submit=Save&ajax=1',
      success: function(data){
        if (data.action && data.action == 'reload'){
          location.reload(true);
        }
        enableButtons();
        resetExpireSession();
        saveCallback(data);
        setTimeout(function(){
          $("#daflash .alert-success").hide(300, function(){
            $(self).remove();
          });
        }, 3000);
      },
      dataType: 'json'
    });
    event.preventDefault();
    return false;
  });

  $(".da-example-link").on("click", function(){
    var id = $(this).data("example");
    activateExample(id, false);
  });

  $(".da-example-copy").on("click", function(event){
    if (daCodeMirror.somethingSelected()){
      daCodeMirror.replaceSelection("");
    }
    var id = $(".da-example-active").data("example");
    var curPos = daCodeMirror.getCursor();
    var notFound = 1;
    var insertLine = daCodeMirror.lastLine();
    daCodeMirror.eachLine(curPos.line, insertLine, function(line){
      if (notFound){
        if (line.text.substring(0, 3) == "---" || line.text.substring(0, 3) == "..."){
          insertLine = daCodeMirror.getLineNumber(line)
          //console.log("Found break at line number " + insertLine)
          notFound = 0;
        }
      }
    });
    if (notFound){
      daCodeMirror.setSelection({'line': insertLine, 'ch': null});
      daCodeMirror.replaceSelection("\\n---\\n" + exampleData[id]['source'] + "\\n", "around");
    }
    else{
      daCodeMirror.setSelection({'line': insertLine, 'ch': 0});
      daCodeMirror.replaceSelection("---\\n" + exampleData[id]['source'] + "\\n", "around");
    }
    daCodeMirror.focus();
    event.preventDefault();
    return false;
  });

  $(".da-example-heading").on("click", function(){
    var list = $(this).parent().children("ul").first();
    if (list != null){
      if (!list.hasClass("da-example-hidden")){
        return;
      }
      $(".da-example-list").addClass("da-example-hidden");
      //$(".da-example-list").slideUp();
      var new_link = $(this).parent().find("a.da-example-link").first();
      if (new_link.length){
        var id = new_link.data("example");
        activateExample(id, true);
      }
    }
  });

  activatePopovers();

  $("#da-show-full-example").on("click", function(){
    var id = $(".da-example-active").data("example");
    var info = exampleData[id];
    $(this).addClass("dainvisible");
    $("#da-hide-full-example").removeClass("dainvisible");
    $("#da-example-source-before").removeClass("dainvisible");
    $("#da-example-source-after").removeClass("dainvisible");
  });

  $("#da-hide-full-example").on("click", function(){
    var id = $(".da-example-active").data("example");
    var info = exampleData[id];
    $(this).addClass("dainvisible");
    $("#da-show-full-example").removeClass("dainvisible");
    $("#da-example-source-before").addClass("dainvisible");
    $("#da-example-source-after").addClass("dainvisible");
  });
  if ($("#playground_name").val().length > 0){
    daCodeMirror.focus();
  }
  else{
    $("#playground_name").focus()
  }
  activateVariables();
  updateRunLink();
  origPosition = daCodeMirror.getCursor();
  daShowConsoleMessages();
  if (currentFile != ''){
    history.replaceState({}, "", """ + json.dumps(url_for('playground.playground_page')) + """ + encodeURI('?project=' + currentProject + '&file=' + currentFile));
  }
});
"""
    any_files = len(files) > 0
    cm_setup = """
    <script>
      var word_re = /[\w$]+/
      $( document ).ready(function(){
        CodeMirror.registerHelper("hint", "yaml", function(editor, options){
          var cur = editor.getCursor(), curLine = editor.getLine(cur.line);
          var end = cur.ch, start = end;
          while (start && word_re.test(curLine.charAt(start - 1))) --start;
          var curWord = start != end && curLine.slice(start, end);
          var list = [];
          if (curWord){
            var n = vocab.length;
            for (var i = 0; i < n; ++i){
              if (vocab[i].indexOf(curWord) == 0){
                list.push(vocab[i]);
              }
            }
          }
          return {list: list, from: CodeMirror.Pos(cur.line, start), to: CodeMirror.Pos(cur.line, end)};
        });""" + upload_js() + """
      });
    </script>"""
    if keymap:
        kbOpt = 'keyMap: "' + keymap + '", cursorBlinkRate: 0, '
        kbLoad = '<script src="' + url_for('static', filename="codemirror/keymap/" + keymap + ".js",
                                           v=da_version) + '"></script>\n    '
    else:
        kbOpt = ''
        kbLoad = ''
    page_title = word("Playground")
    if current_project != 'default':
        page_title += " / " + current_project
    response = make_response(render_template('pages/playground.html', projects=get_list_of_projects(current_user.id),
                                             current_project=current_project, version_warning=None,
                                             bodyclass='daadminbody', use_gd=use_gd, use_od=use_od,
                                             userid=current_user.id, page_title=Markup(page_title),
                                             tab_title=word("Playground"), extra_css=Markup(
            '\n    <link href="' + url_for('static', filename='app/playgroundbundle.css',
                                           v=da_version) + '" rel="stylesheet">'), extra_js=Markup(
            '\n    <script src="' + url_for('static', filename="app/playgroundbundle.js",
                                            v=da_version) + '"></script>\n    ' + kbLoad + cm_setup + '<script>\n      var daConsoleMessages = ' + json.dumps(
                console_messages) + ';\n      $("#daDelete").click(function(event){if (originalFileName != $("#playground_name").val() || $("#playground_name").val() == \'\'){ $("#form button[name=\'submit\']").click(); event.preventDefault(); return false; } if(!confirm("' + word(
                "Are you sure that you want to delete this playground file?") + '")){event.preventDefault();}});\n      daTextArea = document.getElementById("playground_content");\n      var daCodeMirror = CodeMirror.fromTextArea(daTextArea, {specialChars: /[\\u00a0\\u0000-\\u001f\\u007f-\\u009f\\u00ad\\u061c\\u200b-\\u200f\\u2028\\u2029\\ufeff]/, mode: "' + (
                'yamlmixed' if daconfig.get(
                    'test yamlmixed mode') else 'yamlmixed') + '", ' + kbOpt + 'tabSize: 2, tabindex: 70, autofocus: false, lineNumbers: true, matchBrackets: true, lineWrapping: ' + (
                'true' if daconfig.get('wrap lines in playground',
                                       True) else 'false') + '});\n      $(window).bind("beforeunload", function(){daCodeMirror.save(); $("#form").trigger("checkform.areYouSure");});\n      $("#form").areYouSure(' + json.dumps(
                {'message': word(
                    "There are unsaved changes.  Are you sure you wish to leave this page?")}) + ');\n      $("#form").bind("submit", function(){daCodeMirror.save(); $("#form").trigger("reinitialize.areYouSure"); return true;});\n      daCodeMirror.setSize(null, null);\n      daCodeMirror.setOption("extraKeys", { Tab: function(cm) { var spaces = Array(cm.getOption("indentUnit") + 1).join(" "); cm.replaceSelection(spaces); }, "Ctrl-Space": "autocomplete", "F11": function(cm) { cm.setOption("fullScreen", !cm.getOption("fullScreen")); }, "Esc": function(cm) { if (cm.getOption("fullScreen")) cm.setOption("fullScreen", false); }});\n      daCodeMirror.setOption("coverGutterNextToScrollbar", true);\n' + indent_by(
                ajax, 6) + '\n      exampleData = JSON.parse(atob("' + pg_ex[
                'encoded_data_dict'] + '"));\n      activateExample("' + str(pg_ex['pg_first_id'][
                                                                                 0]) + '", false);\n    $("#my-form").trigger("reinitialize.areYouSure");\n      $("#daVariablesReport").on("shown.bs.modal", function () { daFetchVariableReport(); })\n    </script>'),
                                             form=form, fileform=fileform,
                                             files=sorted(files, key=lambda y: y['name'].lower()), any_files=any_files,
                                             pulldown_files=sorted(pulldown_files, key=lambda y: y.lower()),
                                             current_file=the_file, active_file=active_file, content=content,
                                             variables_html=Markup(variables_html),
                                             example_html=pg_ex['encoded_example_html'], interview_path=interview_path,
                                             is_new=str(is_new), valid_form=str(valid_form)), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@playground.route('/playgroundbundle.css', methods=['GET'])
def playground_css_bundle():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['codemirror', 'lib', 'codemirror.css'], ['codemirror', 'addon', 'search', 'matchesonscrollbar.css'],
                  ['codemirror', 'addon', 'display', 'fullscreen.css'],
                  ['codemirror', 'addon', 'scroll', 'simplescrollbars.css'],
                  ['codemirror', 'addon', 'hint', 'show-hint.css'], ['app', 'pygments.min.css'],
                  ['bootstrap-fileinput', 'css', 'fileinput.min.css']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    return Response(output, mimetype='text/css')


@playground.route('/playgroundbundle.js', methods=['GET'])
def playground_js_bundle():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['areyousure', 'jquery.are-you-sure.js'], ['codemirror', 'lib', 'codemirror.js'],
                  ['codemirror', 'addon', 'search', 'searchcursor.js'],
                  ['codemirror', 'addon', 'scroll', 'annotatescrollbar.js'],
                  ['codemirror', 'addon', 'search', 'matchesonscrollbar.js'],
                  ['codemirror', 'addon', 'display', 'fullscreen.js'],
                  ['codemirror', 'addon', 'edit', 'matchbrackets.js'], ['codemirror', 'addon', 'hint', 'show-hint.js'],
                  ['codemirror', 'mode', 'yaml', 'yaml.js'], ['codemirror', 'mode', 'python', 'python.js'],
                  ['yamlmixed', 'yamlmixed.js'], ['codemirror', 'mode', 'markdown', 'markdown.js'],
                  ['bootstrap-fileinput', 'js', 'plugins', 'piexif.min.js'],
                  ['bootstrap-fileinput', 'js', 'fileinput.min.js'],
                  ['bootstrap-fileinput', 'themes', 'fas', 'theme.min.js']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    return Response(output, mimetype='application/javascript')


@playground.route('/api/playground_pull', methods=['GET', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_playground_pull():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    do_restart = true_or_false(post_data.get('restart', True))
    current_project = post_data.get('project', 'default')
    try:
        if current_user.has_role_or_permission('admin', permissions=['playground_control']):
            user_id = int(post_data.get('user_id', current_user.id))
        else:
            if 'user_id' in post_data:
                assert int(post_data['user_id']) == current_user.id
            user_id = current_user.id
    except:
        return jsonify_with_status("Invalid user_id.", 400)
    if current_project != 'default' and current_project not in get_list_of_projects(user_id):
        return jsonify_with_status("Invalid project.", 400)
    docassemble.base.functions.this_thread.current_info['user'] = dict(is_anonymous=False, theid=user_id)
    if current_app.config['USE_GITHUB']:
        github_auth = r.get('da:using_github:userid:' + str(current_user.id))
        can_publish_to_github = bool(github_auth is not None)
    else:
        can_publish_to_github = None
    github_url = None
    branch = None
    pypi_package = None
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
    elif 'pip' in post_data:
        m = re.match(r'([^>=<]+)([>=<]+.+)', post_data['pip'])
        if m:
            pypi_package = m.group(1)
            limitation = m.group(2)
        else:
            pypi_package = post_data['pip']
            limitation = None
        packagename = re.sub(r'[^A-Za-z0-9\_\-\.]', '', pypi_package)
    else:
        return jsonify_with_status("Either github_url or pip is required.", 400)
    area = {}
    area_sec = dict(templates='playgroundtemplate', static='playgroundstatic', sources='playgroundsources',
                    questions='playground')
    for sec in ('playground', 'playgroundpackages', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources',
                'playgroundmodules'):
        area[sec] = SavedFile(user_id, fix=True, section=sec)
    result = do_playground_pull(area, current_project, github_url=github_url, branch=branch, pypi_package=pypi_package,
                                can_publish_to_github=can_publish_to_github, github_email=current_user.email)
    if result['action'] in ('error', 'fail'):
        return jsonify_with_status("Pull process encountered an error: " + result['message'], 400)
    if result['action'] == 'finished':
        if result['need_to_restart'] and do_restart:
            return_val = jsonify_restart_task()
            restart_all()
            return return_val
    return ('', 204)


def get_list_of_projects(user_id):
    playground = SavedFile(user_id, fix=False, section='playground')
    return playground.list_of_dirs()


@playground.route('/api/playground_install', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_playground_install():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    do_restart = true_or_false(post_data.get('restart', True))
    current_project = post_data.get('project', 'default')
    try:
        if current_user.has_role_or_permission('admin', permissions=['playground_control']):
            user_id = int(post_data.get('user_id', current_user.id))
        else:
            if 'user_id' in post_data:
                assert int(post_data['user_id']) == current_user.id
            user_id = current_user.id
    except:
        return jsonify_with_status("Invalid user_id.", 400)
    if current_project != 'default' and current_project not in get_list_of_projects(user_id):
        return jsonify_with_status("Invalid project.", 400)
    docassemble.base.functions.this_thread.current_info['user'] = dict(is_anonymous=False, theid=user_id)
    found = False
    expected_name = 'unknown'
    need_to_restart = False
    area = {}
    area_sec = dict(templates='playgroundtemplate', static='playgroundstatic', sources='playgroundsources',
                    questions='playground')
    for sec in ('playground', 'playgroundpackages', 'playgroundtemplate', 'playgroundstatic', 'playgroundsources',
                'playgroundmodules'):
        area[sec] = SavedFile(user_id, fix=True, section=sec)
    try:
        for filekey in request.files:
            the_files = request.files.getlist(filekey)
            if not the_files:
                continue
            for up_file in the_files:
                found = True
                zippath = tempfile.NamedTemporaryFile(mode="wb", prefix='datemp', suffix=".zip", delete=False)
                up_file.save(zippath)
                up_file.close()
                zippath.close()
                with zipfile.ZipFile(zippath.name, mode='r') as zf:
                    readme_text = ''
                    setup_py = ''
                    extracted = {}
                    data_files = dict(templates=[], static=[], sources=[], interviews=[], modules=[], questions=[])
                    has_docassemble_dir = set()
                    has_setup_file = set()
                    for zinfo in zf.infolist():
                        if zinfo.is_dir():
                            if zinfo.filename.endswith('/docassemble/'):
                                has_docassemble_dir.add(re.sub(r'/docassemble/$', '', zinfo.filename))
                            if zinfo.filename == 'docassemble/':
                                has_docassemble_dir.add('')
                        elif zinfo.filename.endswith('/setup.py'):
                            (directory, filename) = os.path.split(zinfo.filename)
                            has_setup_file.add(directory)
                        elif zinfo.filename == 'setup.py':
                            has_setup_file.add('')
                    root_dir = None
                    for directory in has_docassemble_dir.union(has_setup_file):
                        if root_dir is None or len(directory) < len(root_dir):
                            root_dir = directory
                    if root_dir is None:
                        return jsonify_with_status("Not a docassemble package.", 400)
                    for zinfo in zf.infolist():
                        if zinfo.filename.endswith('/'):
                            continue
                        (directory, filename) = os.path.split(zinfo.filename)
                        if filename.startswith('#') or filename.endswith('~'):
                            continue
                        dirparts = splitall(directory)
                        if '.git' in dirparts:
                            continue
                        levels = re.findall(r'/', directory)
                        time_tuple = zinfo.date_time
                        the_time = time.mktime(datetime.datetime(*time_tuple).timetuple())
                        for sec in ('templates', 'static', 'sources', 'questions'):
                            if directory.endswith('data/' + sec) and filename != 'README.md':
                                data_files[sec].append(filename)
                                target_filename = os.path.join(directory_for(area[area_sec[sec]], current_project),
                                                               filename)
                                with zf.open(zinfo) as source_fp, open(target_filename, 'wb') as target_fp:
                                    shutil.copyfileobj(source_fp, target_fp)
                                os.utime(target_filename, (the_time, the_time))
                        if filename == 'README.md' and directory == root_dir:
                            with zf.open(zinfo) as f:
                                the_file_obj = TextIOWrapper(f, encoding='utf8')
                                readme_text = the_file_obj.read()
                        if filename == 'setup.py' and directory == root_dir:
                            with zf.open(zinfo) as f:
                                the_file_obj = TextIOWrapper(f, encoding='utf8')
                                setup_py = the_file_obj.read()
                        elif len(levels) >= 2 and filename.endswith(
                                '.py') and filename != '__init__.py' and 'tests' not in dirparts and 'data' not in dirparts:
                            need_to_restart = True
                            data_files['modules'].append(filename)
                            target_filename = os.path.join(directory_for(area['playgroundmodules'], current_project),
                                                           filename)
                            with zf.open(zinfo) as source_fp, open(target_filename, 'wb') as target_fp:
                                shutil.copyfileobj(source_fp, target_fp)
                                os.utime(target_filename, (the_time, the_time))
                    setup_py = re.sub(r'.*setup\(', '', setup_py, flags=re.DOTALL)
                    for line in setup_py.splitlines():
                        m = re.search(r"^ *([a-z_]+) *= *\(?'(.*)'", line)
                        if m:
                            extracted[m.group(1)] = m.group(2)
                        m = re.search(r'^ *([a-z_]+) *= *\(?"(.*)"', line)
                        if m:
                            extracted[m.group(1)] = m.group(2)
                        m = re.search(r'^ *([a-z_]+) *= *\[(.*)\]', line)
                        if m:
                            the_list = []
                            for item in re.split(r', *', m.group(2)):
                                inner_item = re.sub(r"'$", '', item)
                                inner_item = re.sub(r"^'", '', inner_item)
                                inner_item = re.sub(r'"+$', '', inner_item)
                                inner_item = re.sub(r'^"+', '', inner_item)
                                the_list.append(inner_item)
                            extracted[m.group(1)] = the_list
                    info_dict = dict(readme=readme_text, interview_files=data_files['questions'],
                                     sources_files=data_files['sources'], static_files=data_files['static'],
                                     module_files=data_files['modules'], template_files=data_files['templates'],
                                     dependencies=[z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y),
                                                                  extracted.get('install_requires', []))],
                                     description=extracted.get('description', ''),
                                     author_name=extracted.get('author', ''),
                                     author_email=extracted.get('author_email', ''),
                                     license=extracted.get('license', ''), url=extracted.get('url', ''),
                                     version=extracted.get('version', ''))

                    info_dict['dependencies'] = [x for x in [z for z in map(lambda y: re.sub(r'[\>\<\=].*', '', y),
                                                                            info_dict['dependencies'])] if
                                                 x not in ('docassemble', 'docassemble.base', 'docassemble.webapp')]
                    package_name = re.sub(r'^docassemble\.', '', extracted.get('name', expected_name))
                    with open(os.path.join(directory_for(area['playgroundpackages'], current_project),
                                           'docassemble.' + package_name), 'w', encoding='utf-8') as fp:
                        the_yaml = yaml.safe_dump(info_dict, default_flow_style=False, default_style='|')
                        fp.write(str(the_yaml))
                    for key in r.keys('da:interviewsource:docassemble.playground' + str(current_user.id) + project_name(
                            current_project) + ':*'):
                        r.incr(key.decode())
                    for sec in area:
                        area[sec].finalize()
                    the_file = package_name
                zippath.close()
    except Exception as err:
        logmessage("api_playground_install: " + err.__class__.__name__ + ": " + str(err))
        return jsonify_with_status("Error installing packages.", 400)
    if not found:
        return jsonify_with_status("No package found.", 400)
    for key in r.keys(
            'da:interviewsource:docassemble.playground' + str(user_id) + project_name(current_project) + ':*'):
        r.incr(key.decode())
    if do_restart and need_to_restart:
        return_val = jsonify_restart_task()
        restart_all()
        return return_val
    return ('', 204)


@playground.route('/api/playground/project', methods=['GET', 'POST', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'HEAD'], automatic_options=True)
def api_playground_projects():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    if request.method in ('GET', 'DELETE'):
        try:
            if current_user.has_role_or_permission('admin', permissions=['playground_control']):
                user_id = int(request.args.get('user_id', current_user.id))
            else:
                if 'user_id' in request.args:
                    assert int(request.args['user_id']) == current_user.id
                user_id = current_user.id
        except:
            return jsonify_with_status("Invalid user_id.", 400)
    if request.method == 'GET':
        return jsonify(get_list_of_projects(user_id))
    if request.method == 'DELETE':
        if 'project' not in request.args:
            return jsonify_with_status("Project not provided.", 400)
        project = request.args['project']
        if project not in get_list_of_projects(user_id) or project == 'default':
            return jsonify_with_status("Invalid project.", 400)
        delete_project(user_id, project)
        return ('', 204)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        try:
            if current_user.has_role_or_permission('admin', permissions=['playground_control']):
                user_id = int(post_data.get('user_id', current_user.id))
            else:
                if 'user_id' in post_data:
                    assert int(post_data['user_id']) == current_user.id
                user_id = current_user.id
        except:
            return jsonify_with_status("Invalid user_id.", 400)
        if 'project' not in post_data:
            return jsonify_with_status("Project not provided.", 400)
        project = post_data['project']
        if re.search('^[0-9]', project) or re.search('[^A-Za-z0-9]', project):
            return jsonify_with_status("Invalid project name.", 400)
        if project in get_list_of_projects(user_id) or project == 'default':
            return jsonify_with_status("Invalid project.", 400)
        create_project(user_id, project)
        return ('', 204)


@playground.route('/api/playground', methods=['GET', 'POST', 'DELETE'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'HEAD'], automatic_options=True)
def api_playground():
    if not api_verify(request, roles=['admin', 'developer'], permissions=['playground_control']):
        return jsonify_with_status("Access denied.", 403)
    if request.method in ('GET', 'DELETE'):
        folder = request.args.get('folder', 'static')
        project = request.args.get('project', 'default')
        try:
            if current_user.has_role_or_permission('admin', permissions=['playground_control']):
                user_id = int(request.args.get('user_id', current_user.id))
            else:
                if 'user_id' in request.args:
                    assert int(request.args['user_id']) == current_user.id
                user_id = current_user.id
        except:
            return jsonify_with_status("Invalid user_id.", 400)
    elif request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        folder = post_data.get('folder', 'static')
        project = post_data.get('project', 'default')
        do_restart = true_or_false(post_data.get('restart', True))
        try:
            if current_user.has_role_or_permission('admin', permissions=['playground_control']):
                user_id = int(post_data.get('user_id', current_user.id))
            else:
                if 'user_id' in post_data:
                    assert int(post_data['user_id']) == current_user.id
                user_id = current_user.id
        except:
            return jsonify_with_status("Invalid user_id.", 400)
    if request.method == 'DELETE':
        do_restart = true_or_false(request.args.get('restart', True))
        if 'filename' not in request.args:
            return jsonify_with_status("Missing filename.", 400)
    if folder not in ('questions', 'sources', 'static', 'templates', 'modules'):
        return jsonify_with_status("Invalid folder.", 400)
    if project != 'default' and project not in get_list_of_projects(user_id):
        return jsonify_with_status("Invalid project.", 400)
    if folder == 'questions':
        section = ''
    elif folder == 'templates':
        section = 'template'
    else:
        section = folder
    docassemble.base.functions.this_thread.current_info['user'] = dict(is_anonymous=False, theid=user_id)
    pg_section = PlaygroundSection(section=section, project=project)
    if request.method == 'GET':
        if 'filename' not in request.args:
            return jsonify(pg_section.file_list)
        the_filename = secure_filename_spaces_ok(request.args['filename'])
        if not pg_section.file_exists(the_filename):
            return jsonify_with_status("File not found", 404)
        response_to_send = send_file(pg_section.get_file(the_filename), mimetype=pg_section.get_mimetype(the_filename))
        response_to_send.headers[
            'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response_to_send
    if request.method == 'DELETE':
        pg_section.delete_file(secure_filename_spaces_ok(request.args['filename']))
        if section == 'modules' and do_restart:
            return_val = jsonify_restart_task()
            restart_all()
            return return_val
        return ('', 204)
    if request.method == 'POST':
        found = False
        try:
            for filekey in request.files:
                the_files = request.files.getlist(filekey)
                if the_files:
                    for the_file in the_files:
                        filename = werkzeug.utils.secure_filename(the_file.filename)
                        temp_file = tempfile.NamedTemporaryFile(prefix="datemp", delete=False)
                        the_file.save(temp_file.name)
                        pg_section.copy_from(temp_file.name, filename=filename)
                        found = True
        except:
            return jsonify_with_status("Error saving file(s).", 400)
        if not found:
            return jsonify_with_status("No file found.", 400)
        for key in r.keys('da:interviewsource:docassemble.playground' + str(user_id) + project_name(project) + ':*'):
            r.incr(key.decode())
        if section == 'modules' and do_restart:
            return_val = jsonify_restart_task()
            restart_all()
            return return_val
        return ('', 204)
    return ('', 204)
