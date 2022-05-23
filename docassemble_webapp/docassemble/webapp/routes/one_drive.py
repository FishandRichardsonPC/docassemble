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
from docassemble.base.config import in_celery
from docassemble.base.error import DAError
from docassemble.webapp.config_server import version_warning
from docassemble.webapp.develop import OneDriveForm
from docassemble.webapp.onedrive import get_od_folder
from docassemble.webapp.util import RedisCredStorage, add_br, get_current_project, get_gd_flow, set_od_folder
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
from docassemble.webapp.google_api import get_gd_folder
from docassemble.webapp.translations import setup_translation

if not in_celery:
    import docassemble.webapp.worker

from docassemble_flask_user import login_required, roles_required
from flask import make_response, render_template, request, session, redirect, \
    current_app, flash, Markup, jsonify
from flask_login import current_user
import httplib2

one_drive = Blueprint('one_drive', __name__)


def get_od_flow():
    app_credentials = current_app.config['OAUTH_CREDENTIALS'].get('onedrive', {})
    client_id = app_credentials.get('id', None)
    client_secret = app_credentials.get('secret', None)
    if client_id is None or client_secret is None:
        raise DAError('OneDrive is not configured.')
    flow = oauth2client.client.OAuth2WebServerFlow(
        client_id=client_id,
        client_secret=client_secret,
        scope='files.readwrite.all user.read offline_access',
        redirect_uri=url_for('onedrive_callback', _external=True),
        response_type='code',
        auth_uri='https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        token_uri='https://login.microsoftonline.com/common/oauth2/v2.0/token')
    return flow


def od_fix_subdirs(http, the_folder):
    subdirs = set()
    r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(
        the_folder) + "/children?$select=id,name,deleted,folder", "GET")
    while True:
        if int(r['status']) != 200:
            raise DAError("od_fix_subdirs: could not get contents of folder")
        info = json.loads(content.decode())
        logmessage("Found " + repr(info))
        for item in info['value']:
            if 'folder' in item:
                subdirs.add(item['name'])
        if "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    todo = set(['questions', 'static', 'sources', 'templates', 'modules'])
    for folder_name in (todo - subdirs):
        headers = {'Content-Type': 'application/json'}
        data = {}
        data['name'] = folder_name
        data['folder'] = {}
        data["@microsoft.graph.conflictBehavior"] = "rename"
        r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(the_folder) + "/children",
                                  "POST", headers=headers, body=json.dumps(data))
        if int(r['status']) != 201:
            raise DAError("od_fix_subdirs: could not create subfolder " + folder_name + ' in ' + str(
                the_folder) + '.  ' + content.decode() + ' status: ' + str(r['status']))


@one_drive.route('/onedrive_callback', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def onedrive_callback():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    for key in request.args:
        logmessage("onedrive_callback: argument " + str(key) + ": " + str(request.args[key]))
    if 'code' in request.args:
        flow = get_od_flow()
        credentials = flow.step2_exchange(request.args['code'])
        storage = RedisCredStorage(app='onedrive')
        storage.put(credentials)
        error = None
    elif 'error' in request.args:
        error = request.args['error']
        if 'error_description' in request.args:
            error += '; ' + str(request.args['error_description'])
    else:
        error = word("could not connect to OneDrive")
    if error:
        flash(word('There was a OneDrive error: ' + error), 'error')
        return redirect(url_for('user.profile'))
    else:
        flash(word('Connected to OneDrive'), 'success')
    return redirect(url_for('onedrive_page'))


@one_drive.route('/sync_with_onedrive', methods=['GET'])
@login_required
@roles_required(['admin', 'developer'])
def sync_with_onedrive():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    next = current_app.user_manager.make_safe_url_function(
        request.args.get('next', url_for('playground_page', project=get_current_project())))
    auto_next = request.args.get('auto_next', None)
    if current_app.config['USE_ONEDRIVE'] is False:
        flash(word("OneDrive is not configured"), "error")
        return redirect(next)
    storage = RedisCredStorage(app='onedrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        flow = get_gd_flow()
        uri = flow.step1_get_authorize_url()
        return redirect(uri)
    task = docassemble.webapp.worker.sync_with_onedrive.delay(current_user.id)
    session['taskwait'] = task.id
    if auto_next:
        return redirect(url_for('od_sync_wait', auto_next=auto_next))
    else:
        return redirect(url_for('od_sync_wait', next=next))


@one_drive.route('/odsyncing', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def od_sync_wait():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    current_project = get_current_project()
    next_url = current_app.user_manager.make_safe_url_function(
        request.args.get('next', url_for('playground_page', project=current_project)))
    auto_next_url = request.args.get('auto_next', None)
    if auto_next_url is not None:
        auto_next_url = current_app.user_manager.make_safe_url_function(auto_next_url)
    my_csrf = generate_csrf()
    script = """
    <script>
      var daCheckinInterval = null;
      var autoNext = """ + json.dumps(auto_next_url) + """;
      var resultsAreIn = false;
      function daRestartCallback(data){
        if (autoNext != null){
          setTimeout(function(){
            window.location.replace(autoNext);
          }, 1000);
        }
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
            else{
              if (autoNext != null){
                window.location.replace(autoNext);
              }
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
          url: """ + json.dumps(url_for('checkin_sync_with_onedrive')) + """,
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
    response = make_response(render_template('pages/od_sync_wait.html', version_warning=None, bodyclass='daadminbody',
                                             extra_js=Markup(script), tab_title=word('Synchronizing'),
                                             page_title=word('Synchronizing'), next_page=next_url), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response


@one_drive.route('/checkin_sync_with_onedrive', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def checkin_sync_with_onedrive():
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
                logmessage("checkin_sync_with_onedrive: success")
                return jsonify(success=True, status='finished', ok=the_result.ok, summary=add_br(the_result.summary),
                               restart=the_result.restart)
            if hasattr(the_result, 'error'):
                logmessage("checkin_sync_with_onedrive: failed return value is " + str(the_result.error))
                return jsonify(success=True, status='failed', error_message=str(the_result.error), restart=False)
            if hasattr(the_result, 'summary'):
                return jsonify(success=True, status='failed', summary=add_br(the_result.summary), restart=False)
            return jsonify(success=True, status='failed',
                           error_message=str("No error message.  Result is " + str(the_result)), restart=False)
        logmessage("checkin_sync_with_onedrive: failed return value is a " + str(type(the_result)))
        logmessage("checkin_sync_with_onedrive: failed return value is " + str(the_result))
        return jsonify(success=True, status='failed', error_message=str(the_result), restart=False)
    return jsonify(success=True, status='waiting', restart=False)


@one_drive.route('/onedrive', methods=['GET', 'POST'])
@login_required
@roles_required(['admin', 'developer'])
def onedrive_page():
    setup_translation()
    if not current_app.config['ENABLE_PLAYGROUND']:
        return ('File not found', 404)
    if current_app.config['USE_ONEDRIVE'] is False:
        flash(word("OneDrive is not configured"), "error")
        return redirect(url_for('user.profile'))
    form = OneDriveForm(request.form)
    if request.method == 'POST' and form.cancel.data:
        return redirect(url_for('user.profile'))
    storage = RedisCredStorage(app='onedrive')
    credentials = storage.get()
    if not credentials or credentials.invalid:
        flow = get_od_flow()
        uri = flow.step1_get_authorize_url()
        logmessage("one_drive_page: uri is " + str(uri))
        return redirect(uri)
    items = [dict(id='', name=word('-- Do not link --'))]
    http = credentials.authorize(httplib2.Http())
    try:
        r, content = http.request(
            "https://graph.microsoft.com/v1.0/me/drive/root/children?$select=id,name,deleted,folder", "GET")
    except Exception as err:
        set_od_folder(None)
        storage.release_lock()
        storage.locked_delete()
        flow = get_od_flow()
        uri = flow.step1_get_authorize_url()
        logmessage("one_drive_page: uri is " + str(uri))
        return redirect(uri)
    while True:
        if int(r['status']) != 200:
            flash("Error: could not connect to OneDrive; response code was " + str(
                r['status']) + ".   " + content.decode(), 'danger')
            return redirect(url_for('user.profile'))
        info = json.loads(content.decode())
        for item in info['value']:
            if 'folder' not in item:
                continue
            items.append(dict(id=item['id'], name=item['name']))
        if "@odata.nextLink" not in info:
            break
        r, content = http.request(info["@odata.nextLink"], "GET")
    item_ids = [x['id'] for x in items if x['id'] != '']
    if request.method == 'POST' and form.submit.data:
        if form.folder.data == '':
            set_od_folder(None)
            storage.locked_delete()
            flash(word("OneDrive is not linked."), 'success')
        elif form.folder.data == -1 or form.folder.data == '-1':
            headers = {'Content-Type': 'application/json'}
            info = {}
            info['name'] = 'docassemble'
            info['folder'] = {}
            info["@microsoft.graph.conflictBehavior"] = "fail"
            r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/root/children", "POST",
                                      headers=headers, body=json.dumps(info))
            if int(r['status']) == 201:
                new_item = json.loads(content.decode())
                set_od_folder(new_item['id'])
                od_fix_subdirs(http, new_item['id'])
                flash(word("Your Playground is connected to your OneDrive."), 'success')
            else:
                flash(word("Could not create folder.  " + content.decode()), 'danger')
        elif form.folder.data in item_ids:
            set_od_folder(form.folder.data)
            od_fix_subdirs(http, form.folder.data)
            flash(word("Your Playground is connected to your OneDrive."), 'success')
        else:
            flash(word("The supplied folder " + str(form.folder.data) + "could not be found."), 'danger')
            set_od_folder(None)
        return redirect(url_for('user.profile'))
    the_folder = get_od_folder()
    active_folder = None
    if the_folder is not None:
        r, content = http.request("https://graph.microsoft.com/v1.0/me/drive/items/" + str(the_folder), "GET")
        if int(r['status']) != 200:
            set_od_folder(None)
            flash(word("The previously selected OneDrive folder does not exist.") + "  " + str(the_folder) + " " + str(
                content) + " status: " + repr(r['status']), "info")
            return redirect(url_for('onedrive_page'))
        info = json.loads(content.decode())
        logmessage("Found " + repr(info))
        if info.get('deleted', None):
            set_od_folder(None)
            flash(word("The previously selected OneDrive folder was deleted."), "info")
            return redirect(url_for('onedrive_page'))
        active_folder = dict(id=the_folder, name=info.get('name', 'no name'))
        if the_folder not in item_ids:
            items.append(active_folder)
            item_ids.append(the_folder)
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
        od_fix_subdirs(http, the_folder)
    if the_folder is None:
        the_folder = ''
    description = word('Select the folder from your OneDrive that you want to be synchronized with the Playground.')
    if current_app.config['USE_GOOGLE_DRIVE'] is True and get_gd_folder() is not None:
        description += '  ' + word(
            'Note that if you connect to a OneDrive folder, you will disable your connection to Google Drive.')
    response = make_response(
        render_template('pages/onedrive.html', version_warning=version_warning, bodyclass='daadminbody',
                        header=word('OneDrive'), tab_title=word('OneDrive'), items=items, the_folder=the_folder,
                        page_title=word('OneDrive'), form=form, description=Markup(description)), 200)
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
    return response
