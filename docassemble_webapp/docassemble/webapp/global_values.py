import docassemble.base.config
from docassemble.webapp.api_key import encrypt_api_key
from docassemble.webapp.config_server import FULL_PACKAGE_DIRECTORY, init_py_file, page_parts

if not docassemble.base.config.loaded:
    docassemble.base.config.load()

from docassemble.base.config import hostname
from docassemble.base.functions import word
import docassemble.webapp.machinelearning
import docassemble.base.util
import re
import os
import sys
import shutil
import stat
from docassemble.webapp.files import SavedFile
from docassemble.webapp.db_object import db
from sqlalchemy import and_, or_, select
from docassemble.webapp.users.models import Role, UserModel, UserRoles
import docassemble.base.interview_cache
from docassemble.base.config import daconfig
from docassemble.webapp.app_object import app
from docassemble.webapp.lock import obtain_lock, release_lock
from docassemble.webapp.package import get_url_from_file_reference, import_necessary
from docassemble.webapp.daredis import r
from flask_login import current_user
import json

global_css = ''

global_js = ''


class AdminInterview:
    def can_use(self):
        if self.require_login and current_user.is_anonymous:
            return False
        if self.roles is None:
            return True
        if current_user.is_anonymous:
            if 'anonymous' in self.roles:
                return True
            return False
        if current_user.has_roles(self.roles):
            return True
        return False

    def get_title(self, language):
        if isinstance(self.title, str):
            return word(self.title, language=language)
        return self.title.get(language, word(self.title, language=language))


def set_admin_interviews():
    admin_interviews = []
    if 'administrative interviews' in daconfig:
        if isinstance(daconfig['administrative interviews'], list):
            for item in daconfig['administrative interviews']:
                if isinstance(item, dict):
                    if 'interview' in item and isinstance(item['interview'], str):
                        try:
                            interview = docassemble.base.interview_cache.get_interview(item['interview'])
                        except:
                            sys.stderr.write(
                                "interview " + item['interview'] + " in administrative interviews did not exist" + "\n")
                            continue
                        if 'title' in item:
                            the_title = item['title']
                        else:
                            the_title = interview.consolidated_metadata.get('short title',
                                                                            interview.consolidated_metadata.get('title',
                                                                                                                None))
                            if the_title is None:
                                sys.stderr.write(
                                    "interview in administrative interviews needs to be given a title" + "\n")
                                continue
                        admin_interview = AdminInterview()
                        admin_interview.interview = item['interview']
                        if isinstance(the_title, (str, dict)):
                            if isinstance(the_title, dict):
                                fault = False
                                for key, val in the_title.items():
                                    if not (isinstance(key, str) and isinstance(val, str)):
                                        fault = True
                                        break
                                if fault:
                                    sys.stderr.write(
                                        "title of administrative interviews item must be a string or a dictionary with keys and values that are strings" + "\n")
                                    continue
                            admin_interview.title = the_title
                        else:
                            sys.stderr.write(
                                "title of administrative interviews item must be a string or a dictionary" + "\n")
                            continue
                        if 'required privileges' not in item:
                            roles = set()
                            for metadata in interview.metadata:
                                if 'required privileges for listing' in metadata:
                                    roles = set()
                                    privs = metadata['required privileges for listing']
                                    if isinstance(privs, list):
                                        for priv in privs:
                                            if isinstance(priv, str):
                                                roles.add(priv)
                                    elif isinstance(privs, str):
                                        roles.add(privs)
                                elif 'required privileges' in metadata:
                                    roles = set()
                                    privs = metadata['required privileges']
                                    if isinstance(privs, list):
                                        for priv in privs:
                                            if isinstance(priv, str):
                                                roles.add(priv)
                                    elif isinstance(privs, str):
                                        roles.add(privs)
                            if len(roles) > 0:
                                item['required privileges'] = list(roles)
                        if 'required privileges' in item:
                            fault = False
                            if isinstance(item['required privileges'], list):
                                for rolename in item['required privileges']:
                                    if not isinstance(rolename, str):
                                        fault = True
                                        break
                            else:
                                fault = True
                            if fault:
                                sys.stderr.write(
                                    "required privileges in administrative interviews item must be a list of strings" + "\n")
                                admin_interview.roles = None
                            else:
                                admin_interview.roles = item['required privileges']
                        else:
                            admin_interview.roles = None
                        admin_interview.require_login = False
                        for metadata in interview.metadata:
                            if 'require login' in metadata:
                                admin_interview.require_login = bool(metadata['require login'])
                        admin_interviews.append(admin_interview)
                    else:
                        sys.stderr.write("item in administrative interviews must contain a valid interview name" + "\n")
                else:
                    sys.stderr.write("item in administrative interviews is not a dict" + "\n")
        else:
            sys.stderr.write("administrative interviews is not a list" + "\n")
    return admin_interviews


def test_favicon_file(filename, alt=None):
    the_dir = docassemble.base.functions.package_data_filename(
        daconfig.get('favicon', 'docassemble.webapp:data/static/favicon'))
    if the_dir is None or not os.path.isdir(the_dir):
        return False
    the_file = os.path.join(the_dir, filename)
    if not os.path.isfile(the_file):
        if alt is not None:
            the_file = os.path.join(the_dir, alt)
        if not os.path.isfile(the_file):
            return False
    return True


def copy_playground_modules():
    root_dir = os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble')
    for d in os.listdir(root_dir):
        if re.search(r'^playground[0-9]', d) and os.path.isdir(os.path.join(root_dir, d)):
            try:
                shutil.rmtree(os.path.join(root_dir, d))
            except:
                sys.stderr.write("copy_playground_modules: error deleting " + os.path.join(root_dir, d) + "\n")
    devs = set()
    for user in db.session.execute(select(UserModel.id).join(UserRoles, UserModel.id == UserRoles.user_id).join(Role,
                                                                                                                UserRoles.role_id == Role.id).where(
        and_(UserModel.active == True, or_(Role.name == 'admin', Role.name == 'developer')))):
        devs.add(user.id)
    for user_id in devs:
        mod_dir = SavedFile(user_id, fix=True, section='playgroundmodules')
        local_dirs = [
            (os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble', 'playground' + str(user_id)), mod_dir.directory)]
        for dirname in mod_dir.list_of_dirs():
            local_dirs.append((os.path.join(FULL_PACKAGE_DIRECTORY, 'docassemble',
                                            'playground' + str(user_id) + dirname),
                               os.path.join(mod_dir.directory, dirname)))
        for local_dir, mod_directory in local_dirs:
            if os.path.isdir(local_dir):
                try:
                    shutil.rmtree(local_dir)
                except:
                    sys.stderr.write("copy_playground_modules: error deleting " + local_dir + " before replacing it\n")
            os.makedirs(local_dir, exist_ok=True)
            for f in [f for f in os.listdir(mod_directory) if re.search(r'^[A-Za-z].*\.py$', f)]:
                shutil.copyfile(os.path.join(mod_directory, f), os.path.join(local_dir, f))
            with open(os.path.join(local_dir, '__init__.py'), 'w', encoding='utf-8') as the_file:
                the_file.write(init_py_file)


def write_pypirc():
    pypirc_file = daconfig.get('pypirc path', '/var/www/.pypirc')
    pypi_url = daconfig.get('pypi url', 'https://upload.pypi.org/legacy/')
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
    if existing_content != content:
        with open(pypirc_file, 'w', encoding='utf-8') as fp:
            fp.write(content)
        os.chmod(pypirc_file, stat.S_IRUSR | stat.S_IWUSR)


def fix_api_key(match):
    return 'da:apikey:userid:' + match.group(1) + ':key:' + encrypt_api_key(match.group(2), app.secret_key) + ':info'


def fix_api_keys():
    to_delete = []
    for rkey in r.keys('da:api:userid:*:key:*:info'):
        try:
            rkey = rkey.decode()
        except:
            continue
        try:
            info = json.loads(r.get(rkey).decode())
            assert isinstance(info, dict)
        except:
            to_delete.append(rkey)
            continue
        info['last_four'] = re.sub(r'da:api:userid:.*:key:.*(....):info', r'\1', rkey)
        new_rkey = re.sub(r'da:api:userid:(.*):key:(.*):info', fix_api_key, rkey)
        r.set(new_rkey, json.dumps(info))
        to_delete.append(rkey)
    for rkey in to_delete:
        r.delete(rkey)


def initialize():
    global global_css
    global global_js
    with app.app_context():
        url_root = daconfig.get('url root', 'http://localhost') + daconfig.get('root', '/')
        url = url_root + 'interview'
        with app.test_request_context(base_url=url_root, path=url):
            app.config['USE_FAVICON'] = test_favicon_file('favicon.ico')
            app.config['USE_APPLE_TOUCH_ICON'] = test_favicon_file('apple-touch-icon.png')
            app.config['USE_FAVICON_MD'] = test_favicon_file('favicon-32x32.png')
            app.config['USE_FAVICON_SM'] = test_favicon_file('favicon-16x16.png')
            app.config['USE_SITE_WEBMANIFEST'] = test_favicon_file('site.webmanifest', alt='manifest.json')
            app.config['USE_SAFARI_PINNED_TAB'] = test_favicon_file('safari-pinned-tab.svg')
            if 'bootstrap theme' in daconfig and daconfig['bootstrap theme']:
                try:
                    app.config['BOOTSTRAP_THEME'] = get_url_from_file_reference(daconfig['bootstrap theme'])
                    assert isinstance(app.config['BOOTSTRAP_THEME'], str)
                except:
                    app.config['BOOTSTRAP_THEME'] = None
                    sys.stderr.write("error loading bootstrap theme\n")
            else:
                app.config['BOOTSTRAP_THEME'] = None
            if 'global css' in daconfig:
                for fileref in daconfig['global css']:
                    try:
                        global_css_url = get_url_from_file_reference(fileref)
                        assert isinstance(global_css_url, str)
                        global_css += "\n" + '    <link href="' + global_css_url + '" rel="stylesheet">'
                    except:
                        sys.stderr.write("error loading global css: " + repr(fileref) + "\n")
            if 'global javascript' in daconfig:
                for fileref in daconfig['global javascript']:
                    try:
                        global_js_url = get_url_from_file_reference(fileref)
                        assert isinstance(global_js_url, str)
                        global_js += "\n" + '    <script src="' + global_js_url + '"></script>'
                    except:
                        sys.stderr.write("error loading global js: " + repr(fileref) + "\n")
            if 'raw global css' in daconfig and daconfig['raw global css']:
                global_css += "\n" + str(daconfig['raw global css'])
            if 'raw global javascript' in daconfig and daconfig['raw global javascript']:
                global_js += "\n" + str(daconfig['raw global javascript'])
            app.config['GLOBAL_CSS'] = global_css
            app.config['GLOBAL_JS'] = global_js
            app.config['PARTS'] = page_parts
            app.config['ADMIN_INTERVIEWS'] = set_admin_interviews()
            app.config['ENABLE_PLAYGROUND'] = daconfig.get('enable playground', True)
            app.config['ALLOW_UPDATES'] = daconfig.get('allow updates', True)
            try:
                if 'image' in daconfig['social'] and isinstance(daconfig['social']['image'], str):
                    daconfig['social']['image'] = get_url_from_file_reference(daconfig['social']['image'],
                                                                              _external=True)
                    if daconfig['social']['image'] is None:
                        del daconfig['social']['image']
                for key, subkey in (('og', 'image'), ('twitter', 'image')):
                    if key in daconfig['social'] and isinstance(daconfig['social'][key], dict) and subkey in \
                            daconfig['social'][key] and isinstance(daconfig['social'][key][subkey], str):
                        daconfig['social'][key][subkey] = get_url_from_file_reference(daconfig['social'][key][subkey],
                                                                                      _external=True)
                        if daconfig['social'][key][subkey] is None:
                            del daconfig['social'][key][subkey]
            except:
                sys.stderr.write("Error converting social image references")
            interviews_to_load = daconfig.get('preloaded interviews', None)
            if isinstance(interviews_to_load, list):
                for yaml_filename in daconfig['preloaded interviews']:
                    try:
                        docassemble.base.interview_cache.get_interview(yaml_filename)
                    except:
                        pass
            if app.config['ENABLE_PLAYGROUND']:
                obtain_lock('init' + hostname, 'init')
                try:
                    copy_playground_modules()
                except Exception as err:
                    sys.stderr.write(
                        "There was an error copying the playground modules: " + err.__class__.__name__ + "\n")
                write_pypirc()
                release_lock('init' + hostname, 'init')
            try:
                macro_path = daconfig.get('libreoffice macro file',
                                          '/var/www/.config/libreoffice/4/user/basic/Standard/Module1.xba')
                if os.path.isfile(macro_path) and os.path.getsize(macro_path) != 7167:
                    os.remove(macro_path)
            except Exception as err:
                sys.stderr.write("Error was " + err.__class__.__name__ + ' ' + str(err) + "\n")
            fix_api_keys()
            import_necessary(url, url_root)
