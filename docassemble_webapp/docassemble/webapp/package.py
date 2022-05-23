import copy
import copy
import importlib
import json
import os
import re
import sys
import zipfile
from io import TextIOWrapper
from urllib.parse import urlencode

import docassemble.base.DA
import docassemble.base.astparser
import docassemble.base.core
import docassemble.base.functions
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
import httplib2
import requests
from docassemble.base.config import daconfig
from docassemble.base.functions import word
from docassemble.base.logger import logmessage
from docassemble.base.util import DAFile, DAFileCollection, DAFileList, DAStaticFile
from docassemble.webapp.authentication import login_as_admin
from docassemble.webapp.backend import can_access_file_number, get_session_uids, url_for, url_if_exists
from docassemble.webapp.config_server import COOKIELESS_SESSIONS, FULL_PACKAGE_DIRECTORY, GITHUB_BRANCH, \
    PACKAGE_PROTECTION
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.files import SavedFile
from docassemble.webapp.info import system_packages
from docassemble.webapp.packages.models import Package, PackageAuth
from docassemble.webapp.util import RedisCredStorage, splitall
from flask import current_app, flash
from flask_login import current_user
from sqlalchemy import and_, or_, select, update


class Object:
    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)

    pass


def url_sanitize(url):
    return re.sub(r'\s', ' ', url)


def user_can_edit_package(pkgname=None, giturl=None):
    if current_user.has_role('admin'):
        return True
    if not PACKAGE_PROTECTION:
        if pkgname in ('docassemble.base', 'docassemble.demo', 'docassemble.webapp'):
            return False
        return True
    if pkgname is not None:
        pkgname = pkgname.strip()
        if pkgname == '' or re.search(r'\s', pkgname):
            return False
        results = db.session.execute(
            select(Package.id, PackageAuth.user_id, PackageAuth.authtype).outerjoin(PackageAuth,
                                                                                    Package.id == PackageAuth.package_id).where(
                and_(Package.name == pkgname, Package.active == True))).all()
        the_count = 0
        for result in results:
            the_count += 1
        if the_count == 0:
            return True
        for d in results:
            if d.user_id == current_user.id:
                return True
    if giturl is not None:
        giturl = giturl.strip()
        if giturl == '' or re.search(r'\s', giturl):
            return False
        results = db.session.execute(
            select(Package.id, PackageAuth.user_id, PackageAuth.authtype).outerjoin(PackageAuth,
                                                                                    Package.id == PackageAuth.package_id).where(
                and_(or_(Package.giturl == giturl + '/', Package.giturl == giturl), Package.active == True))).all()
        the_count = 0
        for result in results:
            the_count += 1
        if the_count == 0:
            return True
        for d in results:
            if d.user_id == current_user.id:
                return True
    return False


def uninstall_package(packagename):
    # logmessage("server uninstall_package: " + packagename)
    existing_package = db.session.execute(
        select(Package).filter_by(name=packagename, active=True).order_by(Package.id.desc())).first()
    if existing_package is None:
        flash(word("Package did not exist"), 'error')
        return
    db.session.execute(update(Package).where(Package.name == packagename, Package.active == True).values(active=False))
    db.session.commit()


def import_necessary(url, url_root):
    login_as_admin(url, url_root)
    modules_to_import = daconfig.get('preloaded modules', None)
    if isinstance(modules_to_import, list):
        for module_name in daconfig['preloaded modules']:
            try:
                importlib.import_module(module_name)
            except:
                pass

    start_dir = len(FULL_PACKAGE_DIRECTORY.split(os.sep))
    avoid_dirs = [os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble', 'base'),
                  os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble', 'demo'),
                  os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble', 'webapp')]
    modules = ['docassemble.base.legal']
    for root, dirs, files in os.walk(os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble')):
        ok = True
        for avoid in avoid_dirs:
            if root.startswith(avoid):
                ok = False
                break
        if not ok:
            continue
        for the_file in files:
            if not the_file.endswith('.py'):
                continue
            thefilename = os.path.join(root, the_file)
            with open(thefilename, 'r', encoding='utf-8') as fp:
                for cnt, line in enumerate(fp):
                    if line.startswith('# do not pre-load'):
                        break
                    if line.startswith('class') or line.startswith(
                            '# pre-load') or 'docassemble.base.util.update' in line:
                        parts = thefilename.split(os.sep)[start_dir:]
                        parts[-1] = parts[-1][0:-3]
                        modules.append(('.'.join(parts)))
                        break
    for module_name in modules:
        current_package = re.sub(r'\.[^\.]+$', '', module_name)
        docassemble.base.functions.this_thread.current_package = current_package
        docassemble.base.functions.this_thread.current_info.update(
            dict(yaml_filename=current_package + ':data/questions/test.yml'))
        try:
            importlib.import_module(module_name)
        except Exception as err:
            sys.stderr.write(
                "Import of " + module_name + " failed.  " + err.__class__.__name__ + ": " + str(err) + "\n")
    current_app.login_manager._update_request_context_with_user()


def remove_question_package(args):
    if '_question' in args:
        del args['_question']
    if '_package' in args:
        del args['_package']


def get_package_info(exclude_core=False):
    is_admin = current_user.has_role('admin')
    package_list = []
    package_auth = {}
    seen = {}
    for auth in db.session.execute(select(PackageAuth)).scalars():
        if auth.package_id not in package_auth:
            package_auth[auth.package_id] = {}
        package_auth[auth.package_id][auth.user_id] = auth.authtype
    for package in db.session.execute(
            select(Package).filter_by(active=True).order_by(Package.name, Package.id.desc())).scalars():
        if package.name in seen:
            continue
        seen[package.name] = 1
        if package.type is not None:
            can_update = not bool(package.type == 'zip')
            can_uninstall = bool(
                is_admin or (package.id in package_auth and current_user.id in package_auth[package.id]))
            if package.name in system_packages:
                can_uninstall = False
                can_update = False
            if package.name == 'docassemble.webapp':
                can_uninstall = False
                can_update = is_admin
            package_list.append(Object(package=package, can_update=can_update, can_uninstall=can_uninstall))
    return package_list, package_auth


def install_git_package(packagename, giturl, branch):
    # logmessage("install_git_package: " + packagename + " " + str(giturl))
    giturl = str(giturl).rstrip('/')
    if branch is None or str(branch).lower().strip() in ('none', ''):
        branch = GITHUB_BRANCH
    if db.session.execute(select(Package).filter_by(name=packagename)).first() is None and db.session.execute(
            select(Package).where(
                    or_(Package.giturl == giturl, Package.giturl == giturl + '/')).with_for_update()).scalar() is None:
        package_auth = PackageAuth(user_id=current_user.id)
        package_entry = Package(name=packagename, giturl=giturl, package_auth=package_auth, version=1, active=True,
                                type='git', upload=None, limitation=None, gitbranch=branch)
        db.session.add(package_auth)
        db.session.add(package_entry)
    else:
        existing_package = db.session.execute(
            select(Package).filter_by(name=packagename).order_by(Package.id.desc()).with_for_update()).scalar()
        if existing_package is None:
            existing_package = db.session.execute(
                select(Package).where(or_(Package.giturl == giturl, Package.giturl == giturl + '/')).order_by(
                    Package.id.desc()).with_for_update()).scalar()
        if existing_package is not None:
            if existing_package.type == 'zip' and existing_package.upload is not None:
                SavedFile(existing_package.upload).delete()
            existing_package.package_auth.user_id = current_user.id
            existing_package.package_auth.authtype = 'owner'
            existing_package.name = packagename
            existing_package.giturl = giturl
            existing_package.upload = None
            existing_package.version += 1
            existing_package.limitation = None
            existing_package.active = True
            if branch:
                existing_package.gitbranch = branch
            existing_package.type = 'git'
        else:
            logmessage("install_git_package: package " + str(giturl) + " appeared to exist but could not be found")
    db.session.commit()


def install_pip_package(packagename, limitation):
    existing_package = db.session.execute(
        select(Package).filter_by(name=packagename).order_by(Package.id.desc()).with_for_update()).scalar()
    if existing_package is None:
        package_auth = PackageAuth(user_id=current_user.id)
        package_entry = Package(name=packagename, package_auth=package_auth, limitation=limitation, version=1,
                                active=True, type='pip')
        db.session.add(package_auth)
        db.session.add(package_entry)
    else:
        if existing_package.type == 'zip' and existing_package.upload is not None:
            SavedFile(existing_package.upload).delete()
        existing_package.package_auth.user_id = current_user.id
        existing_package.package_auth.authtype = 'owner'
        existing_package.version += 1
        existing_package.type = 'pip'
        existing_package.limitation = limitation
        existing_package.giturl = None
        existing_package.gitbranch = None
        existing_package.upload = None
        existing_package.active = True
    db.session.commit()


def install_zip_package(packagename, file_number):
    existing_package = db.session.execute(
        select(Package).filter_by(name=packagename).order_by(Package.id.desc()).with_for_update()).scalar()
    if existing_package is None:
        package_auth = PackageAuth(user_id=current_user.id)
        package_entry = Package(name=packagename, package_auth=package_auth, upload=file_number, active=True,
                                type='zip', version=1)
        db.session.add(package_auth)
        db.session.add(package_entry)
    else:
        if existing_package.type == 'zip' and existing_package.upload is not None and existing_package.upload != file_number:
            SavedFile(existing_package.upload).delete()
        existing_package.package_auth.user_id = current_user.id
        existing_package.package_auth.authtype = 'owner'
        existing_package.upload = file_number
        existing_package.active = True
        existing_package.limitation = None
        existing_package.giturl = None
        existing_package.gitbranch = None
        existing_package.type = 'zip'
        existing_package.version += 1
    db.session.commit()


def get_repo_info(giturl):
    repo_name = re.sub(r'/*$', '', giturl)
    m = re.search(r'//(.+):x-oauth-basic@github.com', repo_name)
    if m:
        access_token = m.group(1)
    else:
        access_token = None
    repo_name = re.sub(r'^http.*github.com/', '', repo_name)
    repo_name = re.sub(r'.*@github.com:', '', repo_name)
    repo_name = re.sub(r'.git$', '', repo_name)
    if current_app.config['USE_GITHUB']:
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
    the_url = "https://api.github.com/repos/" + repo_name
    if access_token:
        resp, content = http.request(the_url, "GET", headers=dict(Authorization="token " + access_token))
    else:
        resp, content = http.request(the_url, "GET")
    if int(resp['status']) == 200:
        return json.loads(content.decode())
    raise Exception(the_url + " fetch failed on first try; got " + str(resp['status']))


def get_master_branch(giturl):
    try:
        return get_repo_info(giturl).get('default_branch', GITHUB_BRANCH)
    except:
        return GITHUB_BRANCH


def get_package_name_from_zip(zippath):
    with zipfile.ZipFile(zippath, mode='r') as zf:
        min_level = 999999
        setup_py = None
        for zinfo in zf.infolist():
            parts = splitall(zinfo.filename)
            if parts[-1] == 'setup.py':
                if len(parts) < min_level:
                    setup_py = zinfo
                    min_level = len(parts)
        if setup_py is None:
            raise Exception("Not a Python package zip file")
        with zf.open(setup_py) as f:
            the_file = TextIOWrapper(f, encoding='utf8')
            contents = the_file.read()
    extracted = {}
    for line in contents.splitlines():
        m = re.search(r"^NAME *= *\(?'(.*)'", line)
        if m:
            extracted['name'] = m.group(1)
        m = re.search(r'^NAME *= *\(?"(.*)"', line)
        if m:
            extracted['name'] = m.group(1)
        m = re.search(r'^NAME *= *\[(.*)\]', line)
        if m:
            extracted['name'] = m.group(1)
    if 'name' in extracted:
        return extracted['name']
    contents = re.sub(r'.*setup\(', '', contents, flags=re.DOTALL)
    extracted = {}
    for line in contents.splitlines():
        m = re.search(r"^ *([a-z_]+) *= *\(?'(.*)'", line)
        if m:
            extracted[m.group(1)] = m.group(2)
        m = re.search(r'^ *([a-z_]+) *= *\(?"(.*)"', line)
        if m:
            extracted[m.group(1)] = m.group(2)
        m = re.search(r'^ *([a-z_]+) *= *\[(.*)\]', line)
        if m:
            extracted[m.group(1)] = m.group(2)
    if 'name' not in extracted:
        raise Exception("Could not find name of Python package")
    return extracted['name']


def pypi_status(packagename, limitation=None):
    result = {}
    pypi_url = daconfig.get('pypi url', 'https://pypi.python.org/pypi')
    try:
        response = requests.get(url_sanitize(pypi_url + '/' + str(packagename) + '/json'))
        assert response.status_code == 200
    except AssertionError:
        if response.status_code == 404:
            result['error'] = False
            result['exists'] = False
        else:
            result['error'] = response.status_code
    except:
        result['error'] = 'unknown'
    else:
        try:
            result['info'] = response.json()
        except:
            result['error'] = 'json'
        else:
            result['error'] = False
            result['exists'] = True
    return result


def get_url_from_file_reference(file_reference, **kwargs):
    if 'jsembed' in docassemble.base.functions.this_thread.misc or COOKIELESS_SESSIONS:
        kwargs['_external'] = True
    privileged = kwargs.get('privileged', False)
    if isinstance(file_reference, DAFileList) and len(file_reference.elements) > 0:
        file_reference = file_reference.elements[0]
    elif isinstance(file_reference, DAFileCollection):
        file_reference = file_reference._first_file()
    elif isinstance(file_reference, DAStaticFile):
        return file_reference.url_for(**kwargs)
    if isinstance(file_reference, DAFile) and hasattr(file_reference, 'number'):
        file_number = file_reference.number
        if privileged or can_access_file_number(file_number, uids=get_session_uids()):
            url_properties = {}
            if hasattr(file_reference, 'filename') and len(
                    file_reference.filename) and file_reference.has_specific_filename:
                url_properties['display_filename'] = file_reference.filename
            if hasattr(file_reference, 'extension'):
                url_properties['ext'] = file_reference.extension
            for key, val in kwargs.items():
                url_properties[key] = val
            the_file = SavedFile(file_number)
            if kwargs.get('temporary', False):
                return the_file.temp_url_for(**url_properties)
            return the_file.url_for(**url_properties)
    file_reference = str(file_reference)
    if re.search(r'^https?://', file_reference) or re.search(r'^mailto:', file_reference) or file_reference.startswith(
            '/') or file_reference.startswith('?'):
        if '?' not in file_reference:
            args = {}
            for key, val in kwargs.items():
                if key in ('_package', '_question', '_external'):
                    continue
                args[key] = val
            if len(args) > 0:
                if file_reference.startswith('mailto:') and 'body' in args:
                    args['body'] = re.sub(r'(?<!\r)\n', '\r\n', args['body'], re.MULTILINE)
                return file_reference + '?' + urlencode(args, quote_via=safe_quote_func)
        return file_reference
    kwargs_with_i = copy.copy(kwargs)
    if 'i' not in kwargs_with_i:
        yaml_filename = docassemble.base.functions.this_thread.current_info.get('yaml_filename', None)
        if yaml_filename is not None:
            kwargs_with_i['i'] = yaml_filename
    if file_reference in ('login', 'signin'):
        remove_question_package(kwargs)
        return url_for('user.login', **kwargs)
    if file_reference == 'profile':
        remove_question_package(kwargs)
        return url_for('user_profile_page', **kwargs)
    if file_reference == 'change_password':
        remove_question_package(kwargs)
        return url_for('user.change_password', **kwargs)
    if file_reference == 'register':
        remove_question_package(kwargs)
        return url_for('user.register', **kwargs)
    if file_reference == 'config':
        remove_question_package(kwargs)
        return url_for('config_page', **kwargs)
    if file_reference == 'leave':
        remove_question_package(kwargs)
        return url_for('leave', **kwargs)
    if file_reference == 'logout':
        remove_question_package(kwargs)
        return url_for('user.logout', **kwargs)
    if file_reference == 'restart':
        remove_question_package(kwargs_with_i)
        return url_for('restart_session', **kwargs_with_i)
    if file_reference == 'new_session':
        remove_question_package(kwargs_with_i)
        return url_for('new_session', **kwargs_with_i)
    if file_reference == 'help':
        return 'javascript:daShowHelpTab()'
    if file_reference == 'interview':
        remove_question_package(kwargs)
        return url_for('index', **kwargs)
    if file_reference == 'flex_interview':
        remove_question_package(kwargs)
        how_called = docassemble.base.functions.this_thread.misc.get('call', None)
        if how_called is None:
            return url_for('index', **kwargs)
        try:
            if int(kwargs.get('new_session')):
                is_new = True
                del kwargs['new_session']
            else:
                is_new = False
        except:
            is_new = False
        if how_called[0] in ('start', 'run'):
            del kwargs['i']
            kwargs['package'] = how_called[1]
            kwargs['filename'] = how_called[2]
            if is_new:
                return url_for('redirect_to_interview_in_package', **kwargs)
            return url_for('run_interview_in_package', **kwargs)
        if how_called[0] in ('start_dispatch', 'run_dispatch'):
            del kwargs['i']
            kwargs['dispatch'] = how_called[1]
            if is_new:
                return url_for('redirect_to_interview', **kwargs)
            return url_for('run_interview', **kwargs)
        if how_called[0] in ('start_directory', 'run_directory'):
            del kwargs['i']
            kwargs['package'] = how_called[1]
            kwargs['directory'] = how_called[2]
            kwargs['filename'] = how_called[3]
            if is_new:
                return url_for('redirect_to_interview_in_package_directory', **kwargs)
            return url_for('run_interview_in_package_directory', **kwargs)
        if is_new:
            kwargs['new_session'] = 1
        return url_for('index', **kwargs)
    if file_reference == 'interviews':
        remove_question_package(kwargs)
        return url_for('interview_list', **kwargs)
    if file_reference == 'exit':
        remove_question_package(kwargs_with_i)
        return url_for('exit_endpoint', **kwargs_with_i)
    if file_reference == 'exit_logout':
        remove_question_package(kwargs_with_i)
        return url_for('exit_logout', **kwargs_with_i)
    if file_reference == 'dispatch':
        remove_question_package(kwargs)
        return url_for('interview_start', **kwargs)
    if file_reference == 'manage':
        remove_question_package(kwargs)
        return url_for('manage_account', **kwargs)
    if file_reference == 'interview_list':
        remove_question_package(kwargs)
        return url_for('interview_list', **kwargs)
    if file_reference == 'playground':
        remove_question_package(kwargs)
        return url_for('playground_page', **kwargs)
    if file_reference == 'playgroundtemplate':
        kwargs['section'] = 'template'
        remove_question_package(kwargs)
        return url_for('playground_files', **kwargs)
    if file_reference == 'playgroundstatic':
        kwargs['section'] = 'static'
        remove_question_package(kwargs)
        return url_for('playground_files', **kwargs)
    if file_reference == 'playgroundsources':
        kwargs['section'] = 'sources'
        remove_question_package(kwargs)
        return url_for('playground_files', **kwargs)
    if file_reference == 'playgroundmodules':
        kwargs['section'] = 'modules'
        remove_question_package(kwargs)
        return url_for('playground_files', **kwargs)
    if file_reference == 'playgroundpackages':
        remove_question_package(kwargs)
        return url_for('playground_packages', **kwargs)
    if file_reference == 'playgroundfiles':
        remove_question_package(kwargs)
        return url_for('playground_files', **kwargs)
    if file_reference == 'create_playground_package':
        remove_question_package(kwargs)
        return url_for('create_playground_package', **kwargs)
    if file_reference == 'configuration':
        remove_question_package(kwargs)
        return url_for('config_page', **kwargs)
    if file_reference == 'root':
        remove_question_package(kwargs)
        return url_for('rootindex', **kwargs)
    if file_reference == 'run':
        remove_question_package(kwargs)
        return url_for('run_interview_in_package', **kwargs)
    if file_reference == 'run_dispatch':
        remove_question_package(kwargs)
        return url_for('run_interview', **kwargs)
    if file_reference == 'run_new':
        remove_question_package(kwargs)
        return url_for('redirect_to_interview_in_package', **kwargs)
    if file_reference == 'run_new_dispatch':
        remove_question_package(kwargs)
        return url_for('redirect_to_interview', **kwargs)
    if re.search('^[0-9]+$', file_reference):
        remove_question_package(kwargs)
        file_number = file_reference
        if kwargs.get('temporary', False):
            url = SavedFile(file_number).temp_url_for(**kwargs)
        elif can_access_file_number(file_number, uids=get_session_uids()):
            url = SavedFile(file_number).url_for(**kwargs)
        else:
            logmessage("Problem accessing " + str(file_number))
            url = 'about:blank'
    else:
        question = kwargs.get('_question', None)
        package_arg = kwargs.get('_package', None)
        if 'ext' in kwargs and kwargs['ext'] is not None:
            extn = kwargs['ext']
            extn = re.sub(r'^\.', '', extn)
            extn = '.' + extn
        else:
            extn = ''
        parts = file_reference.split(':')
        if len(parts) < 2:
            file_reference = re.sub(r'^data/static/', '', file_reference)
            the_package = None
            if question is not None and question.from_source is not None and hasattr(question.from_source, 'package'):
                the_package = question.from_source.package
            if the_package is None and package_arg is not None:
                the_package = package_arg
            if the_package is None:
                the_package = 'docassemble.base'
            parts = [the_package, file_reference]
        parts[1] = re.sub(r'^data/[^/]+/', '', parts[1])
        url = url_if_exists(parts[0] + ':data/static/' + parts[1] + extn, **kwargs)
    return url
