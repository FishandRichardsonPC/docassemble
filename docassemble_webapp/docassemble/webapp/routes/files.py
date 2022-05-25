import datetime
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

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
import pkg_resources
import werkzeug.exceptions
import werkzeug.utils
from dateutil import tz
from docassemble.base.config import daconfig, in_celery
from docassemble.base.functions import ReturnValue, get_default_timezone, word
from docassemble.base.logger import logmessage
from docassemble.base.util import DAFile
from docassemble.webapp.backend import can_access_file_number, cloud, decrypt_phrase, file_set_attributes, \
    generate_csrf, get_info_from_file_number, get_new_file_number, get_session, get_session_uids, unpack_phrase, url_for
from docassemble.webapp.config_server import START_TIME, VOICERSS_ENABLED, audio_mimetype_table, html_index_path, \
    version_warning, voicerss_config
from docassemble.webapp.core.models import SpeakList
from docassemble.webapp.daredis import r
from docassemble.webapp.db_object import db
from docassemble.webapp.develop import CreatePackageForm
from docassemble.webapp.files import SavedFile, get_ext_and_mimetype
from docassemble.webapp.packages.models import Package, PackageAuth
from docassemble.webapp.setup import da_version
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.util import name_of_user, secure_filename_spaces_ok, summarize_results
from flask import Blueprint

if not in_celery:
    import docassemble.webapp.worker

from docassemble_flask_user import login_required, roles_required
from flask import make_response, abort, render_template, request, session, send_file, redirect, \
    current_app, flash, Markup, jsonify, Response
from flask_login import current_user
from backports import zoneinfo
from sqlalchemy import and_, select
import werkzeug.exceptions
import werkzeug.utils

files = Blueprint('files', __name__)


def favicon_file(filename, alt=None):
    the_dir = docassemble.base.functions.package_data_filename(
        daconfig.get('favicon', 'docassemble.webapp:data/static/favicon'))
    if the_dir is None or not os.path.isdir(the_dir):
        logmessage("favicon_file: could not find favicon directory")
        return ('File not found', 404)
    the_file = os.path.join(the_dir, filename)
    if not os.path.isfile(the_file):
        if alt is not None:
            the_file = os.path.join(the_dir, alt)
        if not os.path.isfile(the_file):
            return ('File not found', 404)
    if filename == 'site.webmanifest':
        mimetype = 'application/manifest+json'
    else:
        extension, mimetype = get_ext_and_mimetype(the_file)
    response = send_file(the_file, mimetype=mimetype, download_name=filename)
    return response


@files.route("/favicon.ico", methods=['GET'])
def favicon():
    return favicon_file('favicon.ico')


@files.route("/apple-touch-icon.png", methods=['GET'])
def apple_touch_icon():
    return favicon_file('apple-touch-icon.png')


@files.route("/favicon-32x32.png", methods=['GET'])
def favicon_md():
    return favicon_file('favicon-32x32.png')


@files.route("/favicon-16x16.png", methods=['GET'])
def favicon_sm():
    return favicon_file('favicon-16x16.png')


@files.route("/site.webmanifest", methods=['GET'])
def favicon_site_webmanifest():
    return favicon_file('site.webmanifest', alt='manifest.json')


@files.route("/manifest.json", methods=['GET'])
def favicon_manifest_json():
    return favicon_file('manifest.json', alt='site.webmanifest')


@files.route("/safari-pinned-tab.svg", methods=['GET'])
def favicon_safari_pinned_tab():
    return favicon_file('safari-pinned-tab.svg')


@files.route("/android-chrome-192x192.png", methods=['GET'])
def favicon_android_md():
    return favicon_file('android-chrome-192x192.png')


@files.route("/android-chrome-512x512.png", methods=['GET'])
def favicon_android_lg():
    return favicon_file('android-chrome-512x512.png')


@files.route("/mstile-150x150.png", methods=['GET'])
def favicon_mstile():
    return favicon_file('mstile-150x150.png')


@files.route("/browserconfig.xml", methods=['GET'])
def favicon_browserconfig():
    return favicon_file('browserconfig.xml')


@files.route("/robots.txt", methods=['GET'])
def robots():
    if 'robots' not in daconfig and daconfig.get('allow robots', False):
        response = make_response("User-agent: *\nDisallow:", 200)
        response.mimetype = "text/plain"
        return response
    the_file = docassemble.base.functions.package_data_filename(
        daconfig.get('robots', 'docassemble.webapp:data/static/robots.txt'))
    if the_file is None:
        return ('File not found', 404)
    if not os.path.isfile(the_file):
        return ('File not found', 404)
    response = send_file(the_file, mimetype='text/plain', download_name='robots.txt')
    return response


@files.route(html_index_path, methods=['GET'])
def html_index():
    resp = current_app.send_static_file('index.html')
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return resp


@files.route('/bundle.css', methods=['GET'])
def css_bundle():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['bootstrap-fileinput', 'css', 'fileinput.min.css'],
                  ['labelauty', 'source', 'jquery-labelauty.min.css'],
                  ['bootstrap-combobox', 'css', 'bootstrap-combobox.min.css'],
                  ['bootstrap-slider', 'dist', 'css', 'bootstrap-slider.min.css'], ['app', 'app.min.css']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    return Response(output, mimetype='text/css')


@files.route('/bundle.js', methods=['GET'])
def js_bundle():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['app', 'jquery.min.js'], ['app', 'jquery.validate.min.js'], ['app', 'additional-methods.min.js'],
                  ['app', 'jquery.visible.min.js'], ['bootstrap', 'js', 'bootstrap.bundle.min.js'],
                  ['bootstrap-slider', 'dist', 'bootstrap-slider.min.js'],
                  ['bootstrap-fileinput', 'js', 'plugins', 'piexif.min.js'],
                  ['bootstrap-fileinput', 'js', 'fileinput.min.js'],
                  ['bootstrap-fileinput', 'themes', 'fas', 'theme.min.js'], ['app', 'app.min.js'],
                  ['app', 'socket.io.min.js'], ['labelauty', 'source', 'jquery-labelauty.min.js'],
                  ['bootstrap-combobox', 'js', 'bootstrap-combobox.min.js']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    return Response(output, mimetype='application/javascript')


@files.route('/adminbundle.js', methods=['GET'])
def js_admin_bundle():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['app', 'jquery.min.js'], ['bootstrap', 'js', 'bootstrap.bundle.min.js']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    return Response(output, mimetype='application/javascript')


@files.route('/bundlewrapjquery.js', methods=['GET'])
def js_bundle_wrap():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = '(function($) {'
    for parts in [['app', 'jquery.validate.min.js'], ['app', 'additional-methods.min.js'], ['app', 'jquery.visible.js'],
                  ['bootstrap', 'js', 'bootstrap.bundle.min.js'],
                  ['bootstrap-slider', 'dist', 'bootstrap-slider.min.js'],
                  ['bootstrap-fileinput', 'js', 'plugins', 'piexif.min.js'],
                  ['bootstrap-fileinput', 'js', 'fileinput.min.js'],
                  ['bootstrap-fileinput', 'themes', 'fas', 'theme.min.js'], ['app', 'app.min.js'],
                  ['app', 'socket.io.min.js'], ['labelauty', 'source', 'jquery-labelauty.min.js'],
                  ['bootstrap-combobox', 'js', 'bootstrap-combobox.min.js']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    output += '})(jQuery);'
    return Response(output, mimetype='application/javascript')


@files.route('/bundlenojquery.js', methods=['GET'])
def js_bundle_no_query():
    base_path = pkg_resources.resource_filename(pkg_resources.Requirement.parse('docassemble.webapp'),
                                                os.path.join('docassemble', 'webapp', 'static'))
    output = ''
    for parts in [['app', 'jquery.validate.min.js'], ['app', 'additional-methods.min.js'],
                  ['app', 'jquery.visible.min.js'], ['bootstrap', 'js', 'bootstrap.bundle.min.js'],
                  ['bootstrap-slider', 'dist', 'bootstrap-slider.min.js'],
                  ['bootstrap-fileinput', 'js', 'plugins', 'piexif.min.js'],
                  ['bootstrap-fileinput', 'js', 'fileinput.min.js'],
                  ['bootstrap-fileinput', 'themes', 'fas', 'theme.min.js'], ['app', 'app.min.js'],
                  ['app', 'socket.io.min.js'], ['labelauty', 'source', 'jquery-labelauty.min.js'],
                  ['bootstrap-combobox', 'js', 'bootstrap-combobox.min.js']]:
        with open(os.path.join(base_path, *parts), encoding='utf-8') as fp:
            output += fp.read()
        output += "\n"
    output += ''
    return Response(output, mimetype='application/javascript')


@files.route('/storedfile/<uid>/<number>/<filename>.<extension>', methods=['GET'])
def serve_stored_file(uid, number, filename, extension):
    return do_serve_stored_file(uid, number, filename, extension)


@files.route('/storedfiledownload/<uid>/<number>/<filename>.<extension>', methods=['GET'])
def serve_stored_file_download(uid, number, filename, extension):
    return do_serve_stored_file(uid, number, filename, extension, download=True)


def do_serve_stored_file(uid, number, filename, extension, download=False):
    number = re.sub(r'[^0-9]', '', str(number))
    if not can_access_file_number(number, uids=[uid]):
        return ('File not found', 404)
    try:
        file_info = get_info_from_file_number(number, privileged=True, uids=get_session_uids())
    except:
        return ('File not found', 404)
    if 'path' not in file_info:
        return ('File not found', 404)
    else:
        if not os.path.isfile(file_info['path']):
            return ('File not found', 404)
        response = send_file(file_info['path'], mimetype=file_info['mimetype'],
                             download_name=filename + '.' + extension)
        if download:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename + '.' + extension)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response


@files.route('/tempfile/<code>/<filename>.<extension>', methods=['GET'])
def serve_temporary_file(code, filename, extension):
    return do_serve_temporary_file(code, filename, extension)


@files.route('/tempfiledownload/<code>/<filename>.<extension>', methods=['GET'])
def serve_temporary_file_download(code, filename, extension):
    return do_serve_temporary_file(code, filename, extension, download=True)


def do_serve_temporary_file(code, filename, extension, download=False):
    file_info = r.get('da:tempfile:' + str(code))
    if file_info is None:
        logmessage("serve_temporary_file: file_info was none")
        return ('File not found', 404)
    (section, file_number) = file_info.decode().split('^')
    the_file = SavedFile(file_number, fix=True, section=section)
    the_path = the_file.path
    if not os.path.isfile(the_path):
        return ('File not found', 404)
    (extension, mimetype) = get_ext_and_mimetype(filename + '.' + extension)
    response = send_file(the_path, mimetype=mimetype, download_name=filename + '.' + extension)
    if download:
        response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename + '.' + extension)
    return response


@files.route('/packagestatic/<package>/<path:filename>', methods=['GET'])
def package_static(package, filename):
    try:
        attach = int(request.args.get('attachment', 0))
    except:
        attach = 0
    if '../' in filename:
        return ('File not found', 404)
    if package == 'fonts':
        return redirect(url_for('static', filename='bootstrap/fonts/' + filename, v=da_version))
    try:
        filename = re.sub(r'^\.+', '', filename)
        filename = re.sub(r'\/\.+', '\/', filename)
        the_file = docassemble.base.functions.package_data_filename(str(package) + ':data/static/' + str(filename))
    except:
        return ('File not found', 404)
    if the_file is None:
        return ('File not found', 404)
    if not os.path.isfile(the_file):
        return ('File not found', 404)
    extension, mimetype = get_ext_and_mimetype(the_file)
    response = send_file(the_file, mimetype=str(mimetype), download_name=filename)
    if attach:
        filename = os.path.basename(filename)
        response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
    return response


@files.route('/speakfile', methods=['GET'])
def speak_file():
    audio_file = None
    filename = request.args.get('i', None)
    if filename is None:
        abort(400)
    session_info = get_session(filename)
    if session_info is None:
        abort(400)
    key = session_info['uid']
    encrypted = session_info['encrypted']
    question = request.args.get('question', None)
    question_type = request.args.get('type', None)
    file_format = request.args.get('format', None)
    the_language = request.args.get('language', None)
    the_dialect = request.args.get('dialect', None)
    the_hash = request.args.get('digest', None)
    secret = request.cookies.get('secret', None)
    if secret is not None:
        secret = str(secret)
    if file_format not in ('mp3', 'ogg') or not (
            filename and key and question and question_type and file_format and the_language and the_dialect):
        logmessage(
            "speak_file: could not serve speak file because invalid or missing data was provided: filename " + str(
                filename) + " and key " + str(key) + " and question number " + str(
                question) + " and question type " + str(question_type) + " and language " + str(
                the_language) + " and dialect " + str(the_dialect))
        return ('File not found', 404)
    entry = db.session.execute(
        select(SpeakList).filter_by(filename=filename, key=key, question=question, digest=the_hash, type=question_type,
                                    language=the_language, dialect=the_dialect)).scalar()
    if not entry:
        logmessage(
            "speak_file: could not serve speak file because no entry could be found in speaklist for filename " + str(
                filename) + " and key " + str(key) + " and question number " + str(
                question) + " and question type " + str(question_type) + " and language " + str(
                the_language) + " and dialect " + str(the_dialect))
        return ('File not found', 404)
    if not entry.upload:
        existing_entry = db.session.execute(select(SpeakList).where(
            and_(SpeakList.phrase == entry.phrase, SpeakList.language == entry.language,
                 SpeakList.dialect == entry.dialect, SpeakList.upload != None,
                 SpeakList.encrypted == entry.encrypted))).scalar()
        if existing_entry:
            logmessage("speak_file: found existing entry: " + str(existing_entry.id) + ".  Setting to " + str(
                existing_entry.upload))
            entry.upload = existing_entry.upload
        else:
            if not VOICERSS_ENABLED:
                logmessage("speak_file: could not serve speak file because voicerss not enabled")
                return ('File not found', 404)
            new_file_number = get_new_file_number(key, 'speak.mp3', yaml_file_name=filename)
            # phrase = codecs.decode(entry.phrase, 'base64')
            if entry.encrypted:
                phrase = decrypt_phrase(entry.phrase, secret)
            else:
                phrase = unpack_phrase(entry.phrase)
            url = voicerss_config.get('url', "https://api.voicerss.org/")
            # logmessage("Retrieving " + url)
            audio_file = SavedFile(new_file_number, extension='mp3', fix=True, should_not_exist=True)
            audio_file.fetch_url_post(url, dict(f=voicerss_config.get('format', '16khz_16bit_stereo'),
                                                key=voicerss_config['key'], src=phrase,
                                                hl=str(entry.language) + '-' + str(entry.dialect)))
            if audio_file.size_in_bytes() > 100:
                call_array = [daconfig.get('pacpl', 'pacpl'), '-t', 'ogg', audio_file.path + '.mp3']
                logmessage("speak_file: calling " + " ".join(call_array))
                result = subprocess.run(call_array, check=False).returncode
                if result != 0:
                    logmessage("speak_file: failed to convert downloaded mp3 (" + audio_file.path + '.mp3' + ") to ogg")
                    return ('File not found', 404)
                entry.upload = new_file_number
                audio_file.finalize()
                db.session.commit()
            else:
                logmessage("speak_file: download from voicerss (" + url + ") failed")
                return ('File not found', 404)
    if not entry.upload:
        logmessage("speak_file: upload file number was not set")
        return ('File not found', 404)
    if not audio_file:
        audio_file = SavedFile(entry.upload, extension='mp3', fix=True)
    the_path = audio_file.path + '.' + file_format
    if not os.path.isfile(the_path):
        logmessage("speak_file: could not serve speak file because file (" + the_path + ") not found")
        return ('File not found', 404)
    response = send_file(the_path, mimetype=audio_mimetype_table[file_format])
    return response


@files.route('/packagezip', methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def download_zip_package():
    package_name = request.args.get('package', None)
    if not package_name:
        return ('File not found', 404)
    package_name = werkzeug.utils.secure_filename(package_name)
    package = db.session.execute(select(Package).filter_by(active=True, name=package_name, type='zip')).scalar()
    if package is None:
        return ('File not found', 404)
    if not current_user.has_role('admin'):
        auth = db.session.execute(
            select(PackageAuth).filter_by(package_id=package.id, user_id=current_user.id)).scalar()
        if auth is None:
            return ('File not found', 404)
    try:
        file_info = get_info_from_file_number(package.upload, privileged=True)
    except:
        return ('File not found', 404)
    filename = re.sub(r'\.', '-', package_name) + '.zip'
    response = send_file(file_info['path'] + '.zip', mimetype='application/zip', download_name=filename)
    response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(filename)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


def do_serve_uploaded_file_with_filename_and_extension(number, filename, extension, download=False):
    filename = secure_filename_spaces_ok(filename)
    extension = werkzeug.utils.secure_filename(extension)
    privileged = bool(current_user.is_authenticated and current_user.has_role('admin', 'advocate'))
    number = re.sub(r'[^0-9]', '', str(number))
    if cloud is not None and daconfig.get('use cloud urls', False):
        if not (privileged or can_access_file_number(number, uids=get_session_uids())):
            return ('File not found', 404)
        the_file = SavedFile(number)
        if download:
            return redirect(the_file.temp_url_for(_attachment=True))
        else:
            return redirect(the_file.temp_url_for())
    else:
        try:
            file_info = get_info_from_file_number(number, privileged=privileged, uids=get_session_uids())
        except:
            return ('File not found', 404)
        if 'path' not in file_info:
            return ('File not found', 404)
        else:
            # logmessage("Filename is " + file_info['path'] + '.' + extension)
            if os.path.isfile(file_info['path'] + '.' + extension):
                # logmessage("Using " + file_info['path'] + '.' + extension)
                extension, mimetype = get_ext_and_mimetype(file_info['path'] + '.' + extension)
                response = send_file(file_info['path'] + '.' + extension, mimetype=mimetype,
                                     download_name=filename + '.' + extension)
                if download:
                    response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(
                        filename + '.' + extension)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            if os.path.isfile(os.path.join(os.path.dirname(file_info['path']), filename + '.' + extension)):
                # logmessage("Using " + os.path.join(os.path.dirname(file_info['path']), filename + '.' + extension))
                extension, mimetype = get_ext_and_mimetype(filename + '.' + extension)
                response = send_file(os.path.join(os.path.dirname(file_info['path']), filename + '.' + extension),
                                     mimetype=mimetype, download_name=filename + '.' + extension)
                if download:
                    response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(
                        filename + '.' + extension)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            return ('File not found', 404)


@files.route('/uploadedfile/<number>/<filename>.<extension>', methods=['GET'])
def serve_uploaded_file_with_filename_and_extension(number, filename, extension):
    return do_serve_uploaded_file_with_filename_and_extension(number, filename, extension)


@files.route('/uploadedfiledownload/<number>/<filename>.<extension>', methods=['GET'])
def serve_uploaded_file_with_filename_and_extension_download(number, filename, extension):
    return do_serve_uploaded_file_with_filename_and_extension(number, filename, extension, download=True)


@files.route('/uploadedfile/<number>.<extension>', methods=['GET'])
def serve_uploaded_file_with_extension(number, extension):
    return do_serve_uploaded_file_with_extension(number, extension)


@files.route('/uploadedfiledownload/<number>.<extension>', methods=['GET'])
def serve_uploaded_file_with_extension_download(number, extension):
    return do_serve_uploaded_file_with_extension(number, extension, download=True)


def do_serve_uploaded_file_with_extension(number, extension, download=False):
    extension = werkzeug.utils.secure_filename(extension)
    privileged = bool(current_user.is_authenticated and current_user.has_role('admin', 'advocate'))
    number = re.sub(r'[^0-9]', '', str(number))
    if cloud is not None and daconfig.get('use cloud urls', False):
        if not can_access_file_number(number, uids=get_session_uids()):
            return ('File not found', 404)
        the_file = SavedFile(number)
        if download:
            return redirect(the_file.temp_url_for(_attachment=True))
        else:
            return redirect(the_file.temp_url_for())
    else:
        try:
            file_info = get_info_from_file_number(number, privileged=privileged, uids=get_session_uids())
        except:
            return ('File not found', 404)
        if 'path' not in file_info:
            return ('File not found', 404)
        else:
            if os.path.isfile(file_info['path'] + '.' + extension):
                extension, mimetype = get_ext_and_mimetype(file_info['path'] + '.' + extension)
                response = send_file(file_info['path'] + '.' + extension, mimetype=mimetype,
                                     download_name=str(number) + '.' + extension)
                if download:
                    response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(
                        str(number) + '.' + extension)
                response.headers[
                    'Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
                return response
            else:
                return ('File not found', 404)
    return ('File not found', 404)


@files.route('/uploadedfile/<number>', methods=['GET'])
def serve_uploaded_file(number):
    return do_serve_uploaded_file(number)


def do_serve_uploaded_file(number, download=False):
    number = re.sub(r'[^0-9]', '', str(number))
    privileged = bool(current_user.is_authenticated and current_user.has_role('admin', 'advocate'))
    try:
        file_info = get_info_from_file_number(number, privileged=privileged, uids=get_session_uids())
    except:
        return ('File not found', 404)
    if 'path' not in file_info:
        return ('File not found', 404)
    else:
        if not os.path.isfile(file_info['path']):
            return ('File not found', 404)
        response = send_file(file_info['path'], mimetype=file_info['mimetype'],
                             download_name=os.path.basename(file_info['path']))
        if download:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(
                os.path.basename(file_info['path']))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    return ('File not found', 404)


@files.route('/uploadedpage/<number>/<page>', methods=['GET'])
def serve_uploaded_page(number, page):
    return do_serve_uploaded_page(number, page, size='page')


@files.route('/uploadedpagedownload/<number>/<page>', methods=['GET'])
def serve_uploaded_page_download(number, page):
    return do_serve_uploaded_page(number, page, download=True, size='page')


@files.route('/uploadedpagescreen/<number>/<page>', methods=['GET'])
def serve_uploaded_pagescreen(number, page):
    return do_serve_uploaded_page(number, page, size='screen')


@files.route('/uploadedpagescreendownload/<number>/<page>', methods=['GET'])
def serve_uploaded_pagescreen_download(number, page):
    return do_serve_uploaded_page(number, page, download=True, size='screen')


def do_serve_uploaded_page(number, page, download=False, size='page'):
    number = re.sub(r'[^0-9]', '', str(number))
    page = re.sub(r'[^0-9]', '', str(page))
    privileged = bool(current_user.is_authenticated and current_user.has_role('admin', 'advocate'))
    try:
        file_info = get_info_from_file_number(number, privileged=privileged, uids=get_session_uids())
    except Exception as err:
        logmessage("do_serve_uploaded_page: " + err.__class__.__name__ + str(err))
        return ('File not found', 404)
    if 'path' not in file_info:
        logmessage('serve_uploaded_page: no access to file number ' + str(number))
        return ('File not found', 404)
    try:
        the_file = DAFile(mimetype=file_info['mimetype'], extension=file_info['extension'], number=number,
                          make_thumbnail=page)
        filename = the_file.page_path(page, size)
    except Exception as err:
        logmessage("Could not make thumbnail: " + err.__class__.__name__ + ": " + str(err))
        filename = None
    if filename is None:
        logmessage("do_serve_uploaded_page: sending blank image")
        the_file = docassemble.base.functions.package_data_filename('docassemble.base:data/static/blank_page.png')
        response = send_file(the_file, mimetype='image/png', download_name='blank_page.png')
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    if os.path.isfile(filename):
        response = send_file(filename, mimetype='image/png', download_name=os.path.basename(filename))
        if download:
            response.headers['Content-Disposition'] = 'attachment; filename=' + json.dumps(os.path.basename(filename))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        return response
    else:
        logmessage('do_serve_uploaded_page: path ' + filename + ' is not a file')
        return ('File not found', 404)


@files.route('/updatingpackages', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def update_package_wait():
    setup_translation()
    next_url = current_app.user_manager.make_safe_url_function(request.args.get('next', url_for('admin.update_package')))
    my_csrf = generate_csrf()
    script = """
    <script>
      var daCheckinInterval = null;
      var resultsAreIn = false;
      var pollDelay = 0;
      var pollFail = 0;
      var pollPending = false;
      function daRestartCallback(data){
        //console.log("Restart result: " + data.success);
      }
      function daRestart(){
        $.ajax({
          type: 'POST',
          url: """ + json.dumps(url_for('util.restart_ajax')) + """,
          data: 'csrf_token=""" + my_csrf + """&action=restart',
          success: daRestartCallback,
          dataType: 'json'
        });
        return true;
      }
      function daBadCallback(data){
        pollPending = false;
        pollFail += 1;
      }
      function daUpdateCallback(data){
        pollPending = false;
        if (data.success){
          if (data.status == 'finished'){
            resultsAreIn = true;
            if (data.ok){
              $("#notification").html(""" + json.dumps(
        word("The package update did not report an error.  The logs are below.")) + """);
              $("#notification").removeClass("alert-info");
              $("#notification").removeClass("alert-danger");
              $("#notification").addClass("alert-success");
            }
            else{
              $("#notification").html(""" + json.dumps(
        word("The package update reported an error.  The logs are below.")) + """);
              $("#notification").removeClass("alert-info");
              $("#notification").removeClass("alert-success");
              $("#notification").addClass("alert-danger");
            }
            $("#resultsContainer").show();
            $("#resultsArea").html(data.summary);
            if (daCheckinInterval != null){
              clearInterval(daCheckinInterval);
            }
            //daRestart();
          }
          else if (data.status == 'failed' && !resultsAreIn){
            resultsAreIn = true;
            $("#notification").html(""" + json.dumps(word("There was an error updating the packages.")) + """);
            $("#notification").removeClass("alert-info");
            $("#notification").removeClass("alert-success");
            $("#notification").addClass("alert-danger");
            $("#resultsContainer").show();
            if (data.error_message){
              $("#resultsArea").html(data.error_message);
            }
            else if (data.summary){
              $("#resultsArea").html(data.summary);
            }
            if (daCheckinInterval != null){
              clearInterval(daCheckinInterval);
            }
          }
        }
        else if (!resultsAreIn){
          $("#notification").html(""" + json.dumps(word("There was an error.")) + """);
          $("#notification").removeClass("alert-info");
          $("#notification").removeClass("alert-success");
          $("#notification").addClass("alert-danger");
          if (daCheckinInterval != null){
            clearInterval(daCheckinInterval);
          }
        }
      }
      function daUpdate(){
        if (pollDelay > 25 || pollFail > 8){
          $("#notification").html(""" + json.dumps(word("Server did not respond to request for update.")) + """);
          $("#notification").removeClass("alert-info");
          $("#notification").removeClass("alert-success");
          $("#notification").addClass("alert-danger");
          if (daCheckinInterval != null){
            clearInterval(daCheckinInterval);
          }
          return;
        }
        if (pollPending){
          pollDelay += 1;
          return;
        }
        if (resultsAreIn){
          return;
        }
        pollDelay = 0;
        pollPending = true;
        $.ajax({
          type: 'POST',
          url: """ + json.dumps(url_for('files.update_package_ajax')) + """,
          data: 'csrf_token=""" + my_csrf + """',
          success: daUpdateCallback,
          error: daBadCallback,
          timeout: 10000,
          dataType: 'json'
        });
        return true;
      }
      $( document ).ready(function() {
        //console.log("page loaded");
        daCheckinInterval = setInterval(daUpdate, 6000);
      });
    </script>"""
    response = make_response(
        render_template('pages/update_package_wait.html', version_warning=None, bodyclass='daadminbody',
                        extra_js=Markup(script), tab_title=word('Updating'), page_title=word('Updating'),
                        next_page=next_url), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@files.route('/update_package_ajax', methods=['POST'])
@login_required
@roles_required(['admin', 'developer'])
def update_package_ajax():
    if 'taskwait' not in session or 'serverstarttime' not in session:
        return jsonify(success=False)
    setup_translation()
    result = docassemble.webapp.worker.workerapp.AsyncResult(id=session['taskwait'])
    if result.ready():
        the_result = result.get()
        if isinstance(the_result, ReturnValue):
            if the_result.ok:
                if (hasattr(the_result, 'restart') and not the_result.restart) or START_TIME > session[
                    'serverstarttime']:
                    return jsonify(success=True, status='finished', ok=the_result.ok,
                                   summary=summarize_results(the_result.results, the_result.logmessages))
                else:
                    return jsonify(success=True, status='waiting')
            if hasattr(the_result, 'error_message'):
                logmessage("update_package_ajax: failed return value is " + str(the_result.error_message))
                return jsonify(success=True, status='failed', error_message=str(the_result.error_message))
            if hasattr(the_result, 'results') and hasattr(the_result, 'logmessages'):
                return jsonify(success=True, status='failed',
                               summary=summarize_results(the_result.results, the_result.logmessages))
            return jsonify(success=True, status='failed',
                           error_message=str("No error message.  Result is " + str(the_result)))
        else:
            logmessage("update_package_ajax: failed return value is a " + str(type(the_result)))
            logmessage("update_package_ajax: failed return value is " + str(the_result))
            return jsonify(success=True, status='failed', error_message=str(the_result))
    return jsonify(success=True, status='waiting')

def formatted_current_date():
    if current_user.timezone:
        the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
    else:
        the_timezone = zoneinfo.ZoneInfo(get_default_timezone())
    return datetime.datetime.utcnow().replace(tzinfo=tz.tzutc()).astimezone(the_timezone).strftime("%Y-%m-%d")

@files.route('/createpackage', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def create_package():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    form = CreatePackageForm(request.form)
    if request.method == 'POST' and form.validate():
        pkgname = re.sub(r'^docassemble-', r'', form.name.data)
        initpy = """\
try:
    __import__('pkg_resources').declare_namespace(__name__)
except ImportError:
    __path__ = __import__('pkgutil').extend_path(__path__, __name__)

"""
        licensetext = """\
The MIT License (MIT)

"""
        licensetext += 'Copyright (c) ' + str(datetime.datetime.now().year) + ' ' + str(name_of_user(current_user)) + """

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
        readme = '# docassemble.' + str(pkgname) + "\n\nA docassemble extension.\n\n## Author\n\n" + name_of_user(
            current_user, include_email=True) + "\n"
        manifestin = """\
include README.md
"""
        setupcfg = """\
[metadata]
description-file = README
"""
        setuppy = """\
import os
import sys
from setuptools import setup, find_packages
from fnmatch import fnmatchcase
from distutils2.util import convert_path

standard_exclude = ('*.pyc', '*~', '.*', '*.bak', '*.swp*')
standard_exclude_directories = ('.*', 'CVS', '_darcs', os.path.join('.', 'build'), os.path.join('.', 'dist'), 'EGG-INFO', '*.egg-info')
def find_package_data(where='.', package='', exclude=standard_exclude, exclude_directories=standard_exclude_directories):
    out = {}
    stack = [(convert_path(where), '', package)]
    while stack:
        where, prefix, package = stack.pop(0)
        for name in os.listdir(where):
            fn = os.path.join(where, name)
            if os.path.isdir(fn):
                bad_name = False
                for pattern in exclude_directories:
                    if (fnmatchcase(name, pattern)
                        or fn.lower() == pattern.lower()):
                        bad_name = True
                        break
                if bad_name:
                    continue
                if os.path.isfile(os.path.join(fn, '__init__.py')):
                    if not package:
                        new_package = name
                    else:
                        new_package = package + '.' + name
                        stack.append((fn, '', new_package))
                else:
                    stack.append((fn, prefix + name + os.path.sep, package))
            else:
                bad_name = False
                for pattern in exclude:
                    if (fnmatchcase(name, pattern)
                        or fn.lower() == pattern.lower()):
                        bad_name = True
                        break
                if bad_name:
                    continue
                out.setdefault(package, []).append(prefix+name)
    return out

"""
        setuppy += "setup(name='docassemble." + str(pkgname) + "',\n" + """\
      version='0.0.1',
      description=('A docassemble extension.'),
      long_description=""" + repr(readme) + """,
      long_description_content_type='text/markdown',
      author=""" + repr(str(name_of_user(current_user))) + """,
      author_email=""" + repr(str(current_user.email)) + """,
      license='MIT',
      url='https://docassemble.org',
      packages=find_packages(),
      namespace_packages = ['docassemble'],
      zip_safe = False,
      package_data=find_package_data(where=os.path.join('docassemble', '""" + str(
            pkgname) + """', ''), package='docassemble.""" + str(pkgname) + """'),
     )

"""
        questionfiletext = """\
---
metadata:
  title: I am the title of the application
  short title: Mobile title
  description: |
    Insert description of question file here.
  authors:
    - name: """ + str(current_user.first_name) + " " + str(current_user.last_name) + """
      organization: """ + str(current_user.organization) + """
  revision_date: """ + formatted_current_date() + """
---
mandatory: True
code: |
  user_done
---
question: |
  % if user_doing_well:
  Good to hear it!
  % else:
  Sorry to hear that!
  % endif
sets: user_done
buttons:
  - Exit: exit
  - Restart: restart
---
question: Are you doing well today?
yesno: user_doing_well
...
"""
        templatereadme = """\
# Template directory

If you want to use templates for document assembly, put them in this directory.
"""
        staticreadme = """\
# Static file directory

If you want to make files available in the web app, put them in
this directory.
"""
        sourcesreadme = """\
# Sources directory

This directory is used to store word translation files,
machine learning training files, and other source files.
"""
        objectfile = """\
# This is a Python module in which you can write your own Python code,
# if you want to.
#
# Include this module in a docassemble interview by writing:
# ---
# modules:
#   - docassemble.""" + pkgname + """.objects
# ---
#
# Then you can do things like:
# ---
# objects:
#   - favorite_fruit: Fruit
# ---
# mandatory: True
# question: |
#   When I eat some ${ favorite_fruit.name },
#   I think, "${ favorite_fruit.eat() }"
# ---
# question: What is the best fruit?
# fields:
#   - Fruit Name: favorite_fruit.name
# ---
from docassemble.base.util import DAObject

class Fruit(DAObject):
    def eat(self):
        return "Yum, that " + self.name + " was good!"
"""
        directory = tempfile.mkdtemp()
        packagedir = os.path.join(directory, 'docassemble-' + str(pkgname))
        questionsdir = os.path.join(packagedir, 'docassemble', str(pkgname), 'data', 'questions')
        templatesdir = os.path.join(packagedir, 'docassemble', str(pkgname), 'data', 'templates')
        staticdir = os.path.join(packagedir, 'docassemble', str(pkgname), 'data', 'static')
        sourcesdir = os.path.join(packagedir, 'docassemble', str(pkgname), 'data', 'sources')
        os.makedirs(questionsdir, exist_ok=True)
        os.makedirs(templatesdir, exist_ok=True)
        os.makedirs(staticdir, exist_ok=True)
        os.makedirs(sourcesdir, exist_ok=True)
        with open(os.path.join(packagedir, 'README.md'), 'w', encoding='utf-8') as the_file:
            the_file.write(readme)
        with open(os.path.join(packagedir, 'LICENSE'), 'w', encoding='utf-8') as the_file:
            the_file.write(licensetext)
        with open(os.path.join(packagedir, 'setup.py'), 'w', encoding='utf-8') as the_file:
            the_file.write(setuppy)
        with open(os.path.join(packagedir, 'setup.cfg'), 'w', encoding='utf-8') as the_file:
            the_file.write(setupcfg)
        with open(os.path.join(packagedir, 'MANIFEST.in'), 'w', encoding='utf-8') as the_file:
            the_file.write(manifestin)
        with open(os.path.join(packagedir, 'docassemble', '__init__.py'), 'w', encoding='utf-8') as the_file:
            the_file.write(initpy)
        with open(os.path.join(packagedir, 'docassemble', pkgname, '__init__.py'), 'w', encoding='utf-8') as the_file:
            the_file.write('__version__ = "0.0.1"')
        with open(os.path.join(packagedir, 'docassemble', pkgname, 'objects.py'), 'w', encoding='utf-8') as the_file:
            the_file.write(objectfile)
        with open(os.path.join(templatesdir, 'README.md'), 'w', encoding='utf-8') as the_file:
            the_file.write(templatereadme)
        with open(os.path.join(staticdir, 'README.md'), 'w', encoding='utf-8') as the_file:
            the_file.write(staticreadme)
        with open(os.path.join(sourcesdir, 'README.md'), 'w', encoding='utf-8') as the_file:
            the_file.write(sourcesreadme)
        with open(os.path.join(questionsdir, 'questions.yml'), 'w', encoding='utf-8') as the_file:
            the_file.write(questionfiletext)
        nice_name = 'docassemble-' + str(pkgname) + '.zip'
        file_number = get_new_file_number(None, nice_name)
        file_set_attributes(file_number, private=False, persistent=True)
        saved_file = SavedFile(file_number, extension='zip', fix=True, should_not_exist=True)
        zf = zipfile.ZipFile(saved_file.path, mode='w')
        trimlength = len(directory) + 1
        if current_user.timezone:
            the_timezone = zoneinfo.ZoneInfo(current_user.timezone)
        else:
            the_timezone = zoneinfo.ZoneInfo(get_default_timezone())
        for root, dirs, files in os.walk(packagedir):
            for the_file in files:
                thefilename = os.path.join(root, the_file)
                info = zipfile.ZipInfo(thefilename[trimlength:])
                info.date_time = datetime.datetime.utcfromtimestamp(os.path.getmtime(thefilename)).replace(
                    tzinfo=datetime.timezone.utc).astimezone(the_timezone).timetuple()
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o644 << 16
                with open(thefilename, 'rb') as fp:
                    zf.writestr(info, fp.read())
                # zf.write(thefilename, thefilename[trimlength:])
        zf.close()
        saved_file.save()
        saved_file.finalize()
        shutil.rmtree(directory)
        response = send_file(saved_file.path, mimetype='application/zip', as_attachment=True,
                             attachment_filename=nice_name)
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        flash(word("Package created"), 'success')
        return response
    response = make_response(
        render_template('pages/create_package.html', version_warning=version_warning, bodyclass='daadminbody',
                        form=form, tab_title=word('Create Package'), page_title=word('Create Package')), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response
