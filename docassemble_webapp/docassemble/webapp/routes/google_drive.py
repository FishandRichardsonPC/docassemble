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
from docassemble.webapp.config_server import version_warning
from docassemble.webapp.onedrive import get_od_folder
from docassemble.webapp.util import set_gd_folder, add_br, RedisCredStorage, get_current_project, get_gd_flow, noquote
from flask import Blueprint

if not in_celery:
    import docassemble.webapp.worker

import json

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

from docassemble.base.config import in_celery
from docassemble.base.functions import ReturnValue, word
from docassemble.base.logger import logmessage
from docassemble.webapp.backend import generate_csrf, url_for
from docassemble.webapp.develop import GoogleDriveForm
from docassemble.webapp.google_api import get_gd_folder
from docassemble.webapp.translations import setup_translation

if not in_celery:
    import docassemble.webapp.worker

import apiclient
from docassemble_flask_user import login_required, roles_required
from flask import make_response, render_template, request, session, redirect, \
    current_app, flash, Markup, jsonify
from flask_login import current_user
import httplib2

google_drive = Blueprint('google_drive', __name__)


@google_drive.route('/google_drive_callback', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def google_drive_callback():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    for key in request.args:
        logmessage("google_drive_callback: argument " + str(key) + ": " + str(request.args[key]))
    if 'code' in request.args:
        flow = get_gd_flow()
        credentials = flow.step2_exchange(request.args['code'])
        storage = RedisCredStorage(app='googledrive')
        storage.put(credentials)
        error = None
    elif 'error' in request.args:
        error = request.args['error']
    else:
        error = word("could not connect to Google Drive")
    if error:
        flash(word('There was a Google Drive error: ' + error), 'error')
        return redirect(url_for('user.profile'))
    else:
        flash(word('Connected to Google Drive'), 'success')
    return redirect(url_for('google_drive_page'))


@google_drive.route('/sync_with_google_drive', methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def sync_with_google_drive():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    next = current_app.user_manager.make_safe_url_function(
        request.args.get('next', url_for('playground_page', project=current_project)))
    auto_next = request.args.get('auto_next', None)
    if current_app.config['USE_GOOGLE_DRIVE'] is False:
        flash(word("Google Drive is not configured"), "error")
        return redirect(next)
    storage = RedisCredStorage(app='googledrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        flow = get_gd_flow()
        uri = flow.step1_get_authorize_url()
        return redirect(uri)
    task = docassemble.webapp.worker.sync_with_google_drive.delay(current_user.id)
    session['taskwait'] = task.id
    if auto_next:
        return redirect(url_for('gd_sync_wait', auto_next=auto_next))
    else:
        return redirect(url_for('gd_sync_wait', next=next))


@google_drive.route('/gdsyncing', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def gd_sync_wait():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    next_url = current_app.user_manager.make_safe_url_function(
        request.args.get('next', url_for('playground_page', project=current_project)))
    auto_next_url = request.args.get('auto_next', None)
    my_csrf = generate_csrf()
    script = """
    <script>
      var daCheckinInterval = null;
      var autoNext = """ + json.dumps(auto_next_url) + """;
      var resultsAreIn = false;
      function daRestartCallback(data){
        //console.log("Restart result: " + data.success);
      }
      function daRestart(){
        $.ajax({
          type: 'POST',
          url: """ + json.dumps(url_for('restart_ajax')) + """,
          data: 'csrf_token=""" + my_csrf + """&action=restart',
          success: daRestartCallback,
          dataType: 'json'
        });
        return true;
      }
      function daSyncCallback(data){
        if (data.success){
          if (data.status == 'finished'){
            resultsAreIn = true;
            if (data.ok){
              if (autoNext != null){
                window.location.replace(autoNext);
              }
              $("#notification").html(""" + json.dumps(word("The synchronization was successful.")) + """);
              $("#notification").removeClass("alert-info");
              $("#notification").removeClass("alert-danger");
              $("#notification").addClass("alert-success");
            }
            else{
              $("#notification").html(""" + json.dumps(word("The synchronization was not successful.")) + """);
              $("#notification").removeClass("alert-info");
              $("#notification").removeClass("alert-success");
              $("#notification").addClass("alert-danger");
            }
            $("#resultsContainer").show();
            $("#resultsArea").html(data.summary);
            if (daCheckinInterval != null){
              clearInterval(daCheckinInterval);
            }
            if (data.restart){
              daRestart();
            }
          }
          else if (data.status == 'failed' && !resultsAreIn){
            resultsAreIn = true;
            $("#notification").html(""" + json.dumps(word("There was an error with the synchronization.")) + """);
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
      function daSync(){
        if (resultsAreIn){
          return;
        }
        $.ajax({
          type: 'POST',
          url: """ + json.dumps(url_for('checkin_sync_with_google_drive')) + """,
          data: 'csrf_token=""" + my_csrf + """',
          success: daSyncCallback,
          dataType: 'json'
        });
        return true;
      }
      $( document ).ready(function() {
        //console.log("page loaded");
        daCheckinInterval = setInterval(daSync, 2000);
      });
    </script>"""
    response = make_response(render_template('pages/gd_sync_wait.html', version_warning=None, bodyclass='daadminbody',
                                             extra_js=Markup(script), tab_title=word('Synchronizing'),
                                             page_title=word('Synchronizing'), next_page=next_url), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@google_drive.route('/checkin_sync_with_google_drive', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def checkin_sync_with_google_drive():
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    setup_translation()
    if 'taskwait' not in session:
        return jsonify(success=False)
    result = docassemble.webapp.worker.workerapp.AsyncResult(id=session['taskwait'])
    if result.ready():
        if 'taskwait' in session:
            del session['taskwait']
        the_result = result.get()
        if isinstance(the_result, ReturnValue):
            if the_result.ok:
                logmessage("checkin_sync_with_google_drive: success")
                return jsonify(success=True, status='finished', ok=the_result.ok, summary=add_br(the_result.summary),
                               restart=the_result.restart)
            if hasattr(the_result, 'error'):
                logmessage("checkin_sync_with_google_drive: failed return value is " + str(the_result.error))
                return jsonify(success=True, status='failed', error_message=str(the_result.error), restart=False)
            if hasattr(the_result, 'summary'):
                return jsonify(success=True, status='failed', summary=add_br(the_result.summary), restart=False)
            return jsonify(success=True, status='failed',
                           error_message=str("No error message.  Result is " + str(the_result)), restart=False)
        else:
            logmessage("checkin_sync_with_google_drive: failed return value is a " + str(type(the_result)))
            logmessage("checkin_sync_with_google_drive: failed return value is " + str(the_result))
            return jsonify(success=True, status='failed', error_message=noquote(str(the_result)), restart=False)
    else:
        return jsonify(success=True, status='waiting', restart=False)


def gd_fix_subdirs(service, the_folder):
    subdirs = []
    page_token = None
    while True:
        response = service.files().list(spaces="drive", pageToken=page_token, fields="nextPageToken, files(id, name)",
                                        q="mimeType='application/vnd.google-apps.folder' and trashed=false and '" + str(
                                            the_folder) + "' in parents").execute()
        for the_file in response.get('files', []):
            subdirs.append(the_file)
        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break
    todo = set(['questions', 'static', 'sources', 'templates', 'modules'])
    done = set(x['name'] for x in subdirs if x['name'] in todo)
    for key in todo - done:
        file_metadata = {
            'name': key,
            'mimeType': 'application/vnd.google-apps.folder',
            'parents': [the_folder]
        }
        new_file = service.files().create(body=file_metadata,
                                          fields='id').execute()

@google_drive.route('/google_drive', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def google_drive_page():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if current_app.config['USE_GOOGLE_DRIVE'] is False:
        flash(word("Google Drive is not configured"), "error")
        return redirect(url_for('user.profile'))
    form = GoogleDriveForm(request.form)
    if request.method == 'POST' and form.cancel.data:
        return redirect(url_for('user.profile'))
    storage = RedisCredStorage(app='googledrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        flow = get_gd_flow()
        uri = flow.step1_get_authorize_url()
        return redirect(uri)
    http = credentials.authorize(httplib2.Http())
    try:
        service = apiclient.discovery.build('drive', 'v3', http=http)
    except:
        set_gd_folder(None)
        storage.release_lock()
        storage.locked_delete()
        flow = get_gd_flow()
        uri = flow.step1_get_authorize_url()
        return redirect(uri)
    items = [dict(id='', name=word('-- Do not link --'))]
    # items = []
    page_token = None
    while True:
        try:
            response = service.files().list(spaces="drive", pageToken=page_token,
                                            fields="nextPageToken, files(id, name, mimeType, shortcutDetails)",
                                            q="trashed=false and 'root' in parents and (mimeType = 'application/vnd.google-apps.folder' or (mimeType = 'application/vnd.google-apps.shortcut' and shortcutDetails.targetMimeType = 'application/vnd.google-apps.folder'))").execute()
        except Exception as err:
            logmessage("google_drive_page: " + err.__class__.__name__ + ": " + str(err))
            set_gd_folder(None)
            storage.release_lock()
            storage.locked_delete()
            flash(word('There was a Google Drive error: ' + err.__class__.__name__ + ": " + str(err)), 'error')
            return redirect(url_for('google_drive_page'))
        for the_file in response.get('files', []):
            if the_file['mimeType'] == 'application/vnd.google-apps.shortcut':
                the_file['id'] = the_file['shortcutDetails']['targetId']
            items.append(the_file)
        page_token = response.get('nextPageToken', None)
        if page_token is None:
            break
    item_ids = [x['id'] for x in items if x['id'] != '']
    if request.method == 'POST' and form.submit.data:
        if form.folder.data == '':
            set_gd_folder(None)
            storage.locked_delete()
            flash(word("Google Drive is not linked."), 'success')
        elif form.folder.data == -1 or form.folder.data == '-1':
            file_metadata = {
                'name': 'docassemble',
                'mimeType': 'application/vnd.google-apps.folder'
            }
            new_file = service.files().create(body=file_metadata,
                                              fields='id').execute()
            new_folder = new_file.get('id', None)
            set_gd_folder(new_folder)
            gd_fix_subdirs(service, new_folder)
            if new_folder is not None:
                active_folder = dict(id=new_folder, name='docassemble')
                items.append(active_folder)
                item_ids.append(new_folder)
            flash(word("Your Playground is connected to your Google Drive."), 'success')
        elif form.folder.data in item_ids:
            flash(word("Your Playground is connected to your Google Drive."), 'success')
            set_gd_folder(form.folder.data)
            gd_fix_subdirs(service, form.folder.data)
        else:
            flash(word("The supplied folder " + str(form.folder.data) + "could not be found."), 'error')
            set_gd_folder(None)
        return redirect(url_for('user.profile'))
    the_folder = get_gd_folder()
    active_folder = None
    if the_folder is not None:
        try:
            response = service.files().get(fileId=the_folder, fields="mimeType, trashed").execute()
        except:
            set_gd_folder(None)
            return redirect(url_for('google_drive_page'))
        the_mime_type = response.get('mimeType', None)
        trashed = response.get('trashed', False)
        if trashed is False and the_mime_type == "application/vnd.google-apps.folder":
            active_folder = dict(id=the_folder, name=response.get('name', 'no name'))
            if the_folder not in item_ids:
                items.append(active_folder)
        else:
            set_gd_folder(None)
            the_folder = None
            flash(word("The mapping was reset because the folder does not appear to exist anymore."), 'error')
    if the_folder is None:
        for item in items:
            if item['name'].lower() == 'docassemble':
                active_folder = item
                break
    if active_folder is None:
        active_folder = dict(id=-1, name='docassemble')
        items.append(active_folder)
        item_ids.append(-1)
    if the_folder is not None:
        gd_fix_subdirs(service, the_folder)
    if the_folder is None:
        the_folder = ''
    description = 'Select the folder from your Google Drive that you want to be synchronized with the Playground.'
    if current_app.config['USE_ONEDRIVE'] is True and get_od_folder() is not None:
        description += '  ' + word(
            'Note that if you connect to a Google Drive folder, you will disable your connection to OneDrive.')

    response = make_response(
        render_template('pages/googledrive.html', version_warning=version_warning, description=description,
                        bodyclass='daadminbody', header=word('Google Drive'), tab_title=word('Google Drive'),
                        items=items, the_folder=the_folder, page_title=word('Google Drive'), form=form), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response

