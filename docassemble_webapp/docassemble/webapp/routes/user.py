import email
import json
import re
from urllib.parse import quote_plus as urllibquoteplus

import docassemble_flask_user.emails
import docassemble_flask_user.emails
import docassemble_flask_user.forms
import docassemble_flask_user.forms
import docassemble_flask_user.signals
import docassemble_flask_user.signals
import docassemble_flask_user.views
import docassemble_flask_user.views
from docassemble.base.config import daconfig
from docassemble.base.functions import word
from docassemble.base.generate_key import random_alphanumeric
from docassemble.base.logger import logmessage
from docassemble.webapp.api_key import encrypt_api_key, get_api_key
from docassemble.webapp.app_object import csrf
from docassemble.webapp.authentication import delete_session_info, manual_checkout, user_interviews
from docassemble.webapp.backend import delete_temp_user_data, delete_user_data, reset_user_dict, url_for
from docassemble.webapp.config_server import PERMISSIONS_LIST, exit_page
from docassemble.webapp.daredis import r, r_user
from docassemble.webapp.db_object import db
from docassemble.webapp.develop import APIKey
from docassemble.webapp.translations import setup_translation
from docassemble.webapp.user_util import api_verify
from docassemble.webapp.users.forms import ManageAccountForm
from docassemble.webapp.users.models import MyUserInvitation, Role, UserDictKeys, UserModel
from docassemble.webapp.util import add_user_privilege, create_user, get_requester_ip, get_user_info, \
    jsonify_with_status, \
    make_user_inactive, remove_user_privilege, set_user_info, true_or_false
from docassemble_flask_user import login_required
from flask import Blueprint, Markup, abort, current_app, flash, jsonify, redirect, render_template, request, session
from flask_cors import cross_origin
from flask_login import current_user, logout_user
from sqlalchemy import select

user = Blueprint('user', __name__)


def update_api_key(user_id, api_key, name, method, allowed, add_to_allowed, remove_from_allowed, permissions,
                   add_to_permissions, remove_from_permissions):
    key = 'da:apikey:userid:' + str(user_id) + ':key:' + encrypt_api_key(api_key, current_app.secret_key) + ':info'
    try:
        info = json.loads(r.get(key).decode())
    except:
        return False
    if name is not None:
        info['name'] = name
    if method is not None:
        if info['method'] != method:
            info['constraints'] = []
        info['method'] = method
    if allowed is not None:
        info['constraints'] = allowed
    if add_to_allowed is not None:
        if isinstance(add_to_allowed, list):
            info['constraints'].extend(add_to_allowed)
        elif isinstance(add_to_allowed, str):
            info['constraints'].append(add_to_allowed)
    if remove_from_allowed is not None:
        if isinstance(remove_from_allowed, list):
            to_remove = remove_from_allowed
        elif isinstance(remove_from_allowed, str):
            to_remove = [remove_from_allowed]
        else:
            to_remove = []
        for item in to_remove:
            if item in info['constraints']:
                info['constraints'].remove(item)
    if permissions is not None:
        info['permissions'] = permissions
    if add_to_permissions is not None:
        if isinstance(add_to_permissions, list):
            info['permissions'].extend(add_to_permissions)
        elif isinstance(add_to_permissions, str):
            info['permissions'].append(add_to_permissions)
    if remove_from_permissions is not None:
        if isinstance(remove_from_permissions, list):
            to_remove = remove_from_permissions
        elif isinstance(remove_from_permissions, str):
            to_remove = [remove_from_permissions]
        else:
            to_remove = []
        for item in to_remove:
            if item in info['permissions']:
                info['permissions'].remove(item)
    r.set(key, json.dumps(info))
    return True


def delete_api_key(user_id, api_key):
    key = 'da:apikey:userid:' + str(user_id) + ':key:' + encrypt_api_key(api_key, current_app.secret_key) + ':info'
    r.delete(key)


def get_api_info(user_id, name=None, api_key=None):
    result = []
    rkeys = r.keys('da:apikey:userid:' + str(user_id) + ':key:*:info')
    if api_key is not None:
        api_key = encrypt_api_key(api_key, current_app.secret_key)
    for key in rkeys:
        key = key.decode()
        try:
            info = json.loads(r.get(key).decode())
        except:
            logmessage("API information could not be unpacked.")
            continue
        if name is not None:
            if info['name'] == name:
                return info
        info['key'] = ('*' * 28) + info['last_four']
        this_key = re.sub(r'.*:key:([^:]+):.*', r'\1', key)
        if api_key is not None and this_key == api_key:
            return info
        if name is not None or api_key is not None:
            continue
        if 'permissions' not in info:
            info['permissions'] = []
        result.append(info)
    if name is not None or api_key is not None:
        return None
    return result


def existing_api_names(user_id, except_for=None):
    result = []
    rkeys = r.keys('da:apikey:userid:' + str(user_id) + ':key:*:info')
    for key in rkeys:
        key = key.decode()
        if except_for is not None:
            api_key = re.sub(r'.*:key:([^:]+):.*', r'\1', key)
            if api_key == encrypt_api_key(except_for, current_app.secret_key):
                continue
        try:
            info = json.loads(r.get(key).decode())
            result.append(info['name'])
        except:
            continue
    return result


def add_api_key(user_id, name, method, allowed):
    info = dict(constraints=allowed, method=method, name=name)
    success = False
    for attempt in range(10):
        api_key = random_alphanumeric(32)
        info['last_four'] = api_key[-4:]
        new_api_key = encrypt_api_key(api_key, current_app.secret_key)
        if len(r.keys('da:apikey:userid:*:key:' + new_api_key + ':info')) == 0:
            r.set('da:apikey:userid:' + str(user_id) + ':key:' + new_api_key + ':info', json.dumps(info))
            success = True
            break
    if not success:
        return None
    return api_key


def api_key_exists(user_id, api_key):
    rkeys = r.keys(
        'da:apikey:userid:' + str(user_id) + ':key:' + encrypt_api_key(str(api_key), current_app.secret_key) + ':info')
    if len(rkeys) > 0:
        return True
    return False


def do_api_user_api(user_id):
    if request.method == 'GET':
        name = request.args.get('name', None)
        api_key = request.args.get('api_key', None)
        try:
            result = get_api_info(user_id, name=name, api_key=api_key)
        except:
            return jsonify_with_status("Error accessing API information", 400)
        if (name is not None or api_key is not None) and result is None:
            return jsonify_with_status("No such API key could be found.", 404)
        return jsonify(result)
    if request.method == 'DELETE':
        api_key = request.args.get('api_key', None)
        if api_key is None:
            return jsonify_with_status("An API key must supplied", 400)
        try:
            delete_api_key(user_id, api_key)
        except:
            return jsonify_with_status("Error deleting API key", 400)
        return ('', 204)
    if request.method == 'POST':
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        name = post_data.get('name', None)
        method = post_data.get('method', 'none')
        if method not in ('ip', 'referer', 'none'):
            return jsonify_with_status("Invalid security method", 400)
        allowed = post_data.get('allowed', [])
        if isinstance(allowed, str):
            try:
                allowed = json.loads(allowed)
            except:
                return jsonify_with_status("Allowed sites list not a valid list", 400)
        if not isinstance(allowed, list):
            return jsonify_with_status("Allowed sites list not a valid list", 400)
        try:
            for item in allowed:
                assert isinstance(item, str)
        except:
            return jsonify_with_status("Allowed sites list not a valid list", 400)
        if name is None:
            return jsonify_with_status("A name must be supplied", 400)
        if name in existing_api_names(user_id):
            return jsonify_with_status("The given name already exists", 400)
        if len(name) > 255:
            return jsonify_with_status("The name is invalid", 400)
        new_api_key = add_api_key(user_id, name, method, allowed)
        if new_api_key is None:
            return jsonify_with_status("Error creating API key", 400)
        else:
            return jsonify(new_api_key)
    if request.method == 'PATCH':
        user = db.session.execute(
            select(UserModel).options(db.joinedload(UserModel.roles)).filter_by(id=user_id)).scalar()
        patch_data = request.get_json(silent=True)
        if patch_data is None:
            patch_data = request.form.copy()
        if current_user.id == user_id:
            api_key = patch_data.get('api_key', get_api_key())
        else:
            api_key = patch_data.get('api_key', None)
            if api_key is None:
                return jsonify_with_status("No API key given", 400)
        if not api_key_exists(user_id, api_key):
            return jsonify_with_status("The given API key cannot be modified", 400)
        name = patch_data.get('name', None)
        if name is not None:
            if name in existing_api_names(user_id, except_for=api_key):
                return jsonify_with_status("The given name already exists", 400)
            if len(name) > 255:
                return jsonify_with_status("The name is invalid", 400)
        method = patch_data.get('method', None)
        if method is not None:
            if method not in ('ip', 'referer', 'none'):
                return jsonify_with_status("Invalid security method", 400)
        allowed = patch_data.get('allowed', None)
        add_to_allowed = patch_data.get('add_to_allowed', None)
        if add_to_allowed is not None:
            if add_to_allowed.startswith('['):
                try:
                    add_to_allowed = json.loads(add_to_allowed)
                    for item in add_to_allowed:
                        assert isinstance(item, str)
                except:
                    return jsonify_with_status("add_to_allowed is not a valid list", 400)
        remove_from_allowed = patch_data.get('remove_from_allowed', None)
        if remove_from_allowed is not None:
            if remove_from_allowed.startswith('['):
                try:
                    remove_from_allowed = json.loads(remove_from_allowed)
                    for item in remove_from_allowed:
                        assert isinstance(item, str)
                except:
                    return jsonify_with_status("remove_from_allowed is not a valid list", 400)
        if allowed is not None:
            if isinstance(allowed, str):
                try:
                    allowed = json.loads(allowed)
                except:
                    return jsonify_with_status("Allowed sites list not a valid list", 400)
            if not isinstance(allowed, list):
                return jsonify_with_status("Allowed sites list not a valid list", 400)
            try:
                for item in allowed:
                    assert isinstance(item, str)
            except:
                return jsonify_with_status("Allowed sites list not a valid list", 400)
        if not (user.has_role('admin') and current_user.has_role_or_permission('admin')):
            permissions = None
            add_to_permissions = None
            remove_from_permissions = None
        else:
            permissions = patch_data.get('permissions', None)
            add_to_permissions = patch_data.get('add_to_permissions', None)
            if add_to_permissions is not None:
                if add_to_permissions.startswith('['):
                    try:
                        add_to_permissions = json.loads(add_to_permissions)
                        for item in add_to_permissions:
                            assert isinstance(item, str)
                    except:
                        return jsonify_with_status("add_to_permissions is not a valid list", 400)
                    try:
                        for item in add_to_permissions:
                            assert item in PERMISSIONS_LIST
                    except:
                        return jsonify_with_status("add_to_permissions contained a permission that was not recognized",
                                                   400)
                elif add_to_permissions not in PERMISSIONS_LIST:
                    return jsonify_with_status("add_to_permissions contained a permission that was not recognized", 400)
            remove_from_permissions = patch_data.get('remove_from_permissions', None)
            if remove_from_permissions is not None:
                if remove_from_permissions.startswith('['):
                    try:
                        remove_from_permissions = json.loads(remove_from_permissions)
                        for item in remove_from_permissions:
                            assert isinstance(item, str)
                    except:
                        return jsonify_with_status("remove_from_permissions is not a valid list", 400)
                    try:
                        for item in remove_from_permissions:
                            assert item in PERMISSIONS_LIST
                    except:
                        return jsonify_with_status(
                            "remove_from_permissions contained a permission that was not recognized", 400)
                elif remove_from_permissions not in PERMISSIONS_LIST:
                    return jsonify_with_status("remove_from_permissions contained a permission that was not recognized",
                                               400)
            if permissions is not None:
                if isinstance(permissions, str):
                    try:
                        permissions = json.loads(permissions)
                    except:
                        return jsonify_with_status("Permissions list not a valid list", 400)
                if not isinstance(permissions, list):
                    return jsonify_with_status("Permissions list not a valid list", 400)
                try:
                    for item in permissions:
                        assert isinstance(item, str)
                except:
                    return jsonify_with_status("Permissions list not a valid list", 400)
                try:
                    for item in permissions:
                        assert item in PERMISSIONS_LIST
                except:
                    return jsonify_with_status("Permissions list contained a permission that was not recognized", 400)
        result = update_api_key(user_id, api_key, name, method, allowed, add_to_allowed, remove_from_allowed,
                                permissions, add_to_permissions, remove_from_permissions)
        if not result:
            return jsonify_with_status("Error updating API key", 400)
        return ('', 204)


@user.route('/manage_api', methods=['GET', 'POST'])
@login_required
def manage_api():
    setup_translation()
    if not current_user.has_role(*daconfig.get('api privileges', ['admin', 'developer'])):
        return ('File not found', 404)
    form = APIKey(request.form)
    action = request.args.get('action', None)
    api_key = request.args.get('key', None)
    is_admin = current_user.has_role('admin')
    argu = {'is_admin': is_admin}
    argu['mode'] = 'list'
    if action is None:
        action = 'list'
    argu['form'] = form
    argu['extra_js'] = Markup("""
<script>
  function remove_constraint(elem){
    $(elem).parents('.daconstraintlist div').remove();
    fix_constraints();
  }
  function fix_constraints(){
    var empty;
    var filled_exist = 0;
    var empty_exist = 0;
    if ($("#method").val() == 'none'){
      $(".daconstraintlist").hide();
      return;
    }
    else{
      $(".daconstraintlist").show();
    }
    $(".daconstraintlist input").each(function(){
      if ($(this).val() == ''){
        empty_exist = 1;
      }
      else{
        filled_exist = 1;
      }
      if (!($(this).next().length)){
        var new_button = $('<button>');
        var new_i = $('<i>');
        $(new_button).addClass('btn btn-outline-secondary');
        $(new_i).addClass('fas fa-times');
        $(new_button).append(new_i);
        $(new_button).on('click', function(){remove_constraint(this);});
        $(this).parent().append(new_button);
      }
    });
    if (empty_exist == 0){
      var new_div = $('<div>');
      var new_input = $('<input>');
      $(new_div).append(new_input);
      $(new_div).addClass('input-group');
      $(new_input).addClass('form-control');
      $(new_input).attr('type', 'text');
      if ($("#method").val() == 'ip'){
        $(new_input).attr('placeholder', """ + json.dumps(word('e.g., 56.33.114.49')) + """);
      }
      else{
        $(new_input).attr('placeholder', """ + json.dumps(word('e.g., *example.com')) + """);
      }
      $(new_input).on('change', fix_constraints);
      $(new_input).on('keyup', fix_constraints);
      $(".daconstraintlist").append(new_div);
      var new_button = $('<button>');
      var new_i = $('<i>');
      $(new_button).addClass('btn btn-outline-secondary');
      $(new_i).addClass('fas fa-times');
      $(new_button).append(new_i);
      $(new_button).on('click', function(){remove_constraint(this);});
      $(new_div).append(new_button);
    }
  }
  $( document ).ready(function(){
    $(".daconstraintlist input").on('change', fix_constraints);
    $("#method").on('change', function(){
      $(".daconstraintlist div.input-group").remove();
      fix_constraints();
    });
    $("#submit").on('click', function(){
      var the_constraints = [];
      $(".daconstraintlist input").each(function(){
        if ($(this).val() != ''){
          the_constraints.push($(this).val());
        }
      });
      $("#security").val(JSON.stringify(the_constraints));
    });
    fix_constraints();
  });
</script>
""")
    form.method.choices = [('ip', 'IP Address'), ('referer', 'Referring URL'), ('none', 'No authentication')]
    if is_admin:
        form.permissions.choices = [(permission, permission) for permission in PERMISSIONS_LIST]
    else:
        form.permissions.choices = []
    ip_address = get_requester_ip(request)
    if request.method == 'POST' and form.validate():
        action = form.action.data
        try:
            constraints = json.loads(form.security.data)
            if not isinstance(constraints, list):
                constraints = []
        except:
            constraints = []
        if action == 'new':
            argu['title'] = word("New API Key")
            argu['tab_title'] = argu['title']
            argu['page_title'] = argu['title']
            permissions_data = form.permissions.data if is_admin else []
            info = dict(name=form.name.data, method=form.method.data, constraints=constraints, limits=permissions_data)
            success = False
            for attempt in range(10):
                api_key = random_alphanumeric(32)
                info['last_four'] = api_key[-4:]
                new_api_key = encrypt_api_key(api_key, current_app.secret_key)
                if len(r.keys('da:apikey:userid:*:key:' + new_api_key + ':info')) == 0:
                    r.set('da:apikey:userid:' + str(current_user.id) + ':key:' + new_api_key + ':info',
                          json.dumps(info))
                    success = True
                    break
            if not success:
                flash(word("Could not create new key"), 'error')
                return render_template('pages/manage_api.html', **argu)
            argu['description'] = Markup(word("Your new API key, known internally as %s, is %s") % (
                form.name.data, "<code>" + api_key + "</code>") + '.  ' + word(
                "This is the only time you will be able to see your API key, so make sure to make a note of it and keep it in a secure place."))
        elif action == 'edit':
            argu['title'] = word("Edit API Key")
            argu['tab_title'] = argu['title']
            argu['page_title'] = argu['title']
            api_key = form.key.data
            argu['api_key'] = api_key
            rkey = 'da:apikey:userid:' + str(current_user.id) + ':key:' + str(form.key.data) + ':info'
            existing_key = r.get(rkey)
            if existing_key is None:
                flash(word("The key no longer exists"), 'error')
                return render_template('pages/manage_api.html', **argu)
            existing_key = existing_key.decode()
            if form.delete.data:
                r.delete(rkey)
                flash(word("The key was deleted"), 'info')
            else:
                try:
                    info = json.loads(existing_key)
                except:
                    flash(word("The key no longer exists"), 'error')
                    return render_template('pages/manage_api.html', **argu)
                info['name'] = form.name.data
                if form.method.data != info['method'] and form.method.data in ('ip', 'referer'):
                    info['method'] = form.method.data
                info['constraints'] = constraints
                if is_admin:
                    info['permissions'] = form.permissions.data
                else:
                    info['permissions'] = []
                r.set(rkey, json.dumps(info))
        action = 'list'
    if action == 'new':
        argu['title'] = word("New API Key")
        argu['tab_title'] = argu['title']
        argu['page_title'] = argu['title']
        argu['mode'] = 'new'
    if api_key is not None and action == 'edit':
        argu['title'] = word("Edit API Key")
        argu['tab_title'] = argu['title']
        argu['page_title'] = argu['title']
        argu['api_key'] = api_key
        argu['mode'] = 'edit'
        rkey = 'da:apikey:userid:' + str(current_user.id) + ':key:' + api_key + ':info'
        info = r.get(rkey)
        if info is not None:
            info = json.loads(info.decode())
            if isinstance(info, dict) and info.get('name', None) and info.get('method', None):
                argu['method'] = info.get('method')
                form.method.data = info.get('method')
                form.action.data = 'edit'
                form.key.data = api_key
                form.name.data = info.get('name')
                if is_admin:
                    if 'permissions' in info:
                        form.permissions.data = info['permissions']
                    else:
                        form.permissions.data = []
                argu['constraints'] = info.get('constraints')
                argu['display_key'] = ('*' * 28) + info.get('last_four')
        if ip_address != '127.0.0.1':
            argu['description'] = Markup(word("Your IP address is") + " <code>" + str(ip_address) + "</code>.")
    if action == 'list':
        argu['title'] = word("API Keys")
        argu['tab_title'] = argu['title']
        argu['page_title'] = argu['title']
        argu['mode'] = 'list'
        avail_keys = []
        for rkey in r.keys('da:apikey:userid:' + str(current_user.id) + ':key:*:info'):
            rkey = rkey.decode()
            try:
                info = json.loads(r.get(rkey).decode())
                if not isinstance(info, dict):
                    logmessage("manage_api: response from redis was not a dict")
                    continue
            except:
                logmessage("manage_api: response from redis had invalid json")
                continue
            m = re.match(r'da:apikey:userid:[0-9]+:key:([^:]+):info', rkey)
            if not m:
                logmessage("manage_api: error with redis key")
                continue
            api_key = m.group(1)
            info['encoded_api_key'] = urllibquoteplus(api_key)
            avail_keys.append(info)
        argu['avail_keys'] = avail_keys
        argu['has_any_keys'] = bool(len(avail_keys) > 0)
    return render_template('pages/manage_api.html', **argu)


@user.route('/api/user/api', methods=['GET', 'POST', 'DELETE', 'PATCH'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'PATCH', 'HEAD'], automatic_options=True)
def api_user_api():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if current_user.limited_api:
        if request.method == 'GET' and not current_user.can_do('access_user_api_info'):
            return jsonify_with_status("You do not have sufficient privileges to access user API information", 403)
        if request.method in ('PATCH', 'POST', 'DELETE') and not current_user.can_do('edit_user_api_info'):
            return jsonify_with_status("You do not have sufficient privileges to edit user API information", 403)
    return do_api_user_api(current_user.id)


@user.route('/user/manage', methods=['POST', 'GET'])
def manage_account():
    if (current_user.is_authenticated and current_user.has_roles(['admin'])) or not daconfig.get(
            'user can delete account', True):
        abort(403)
    if current_user.is_anonymous and not daconfig.get('allow anonymous access', True):
        return redirect(url_for('user.login'))
    secret = request.cookies.get('secret', None)
    if current_user.is_anonymous:
        logged_in = False
        if 'tempuser' not in session:
            return ('File not found', 404)
        temp_user_id = int(session['tempuser'])
    else:
        logged_in = True
    delete_shared = daconfig.get('delete account deletes shared', False)
    form = ManageAccountForm(request.form)
    if request.method == 'POST' and form.validate():
        if current_user.is_authenticated:
            user_interviews(user_id=current_user.id, secret=secret, exclude_invalid=False, action='delete_all',
                            delete_shared=delete_shared)
            the_user_id = current_user.id
            logout_user()
            delete_user_data(the_user_id, r, r_user)
        else:
            sessions_to_delete = set()
            interview_query = db.session.execute(select(UserDictKeys.filename, UserDictKeys.key).where(
                UserDictKeys.temp_user_id == temp_user_id).group_by(UserDictKeys.filename, UserDictKeys.key))
            for interview_info in interview_query:
                sessions_to_delete.add((interview_info.key, interview_info.filename))
            for session_id, yaml_filename in sessions_to_delete:
                manual_checkout(manual_session_id=session_id, manual_filename=yaml_filename)
                reset_user_dict(session_id, yaml_filename, temp_user_id=temp_user_id, force=delete_shared)
            delete_temp_user_data(temp_user_id, r)
        delete_session_info()
        session.clear()
        response = redirect(exit_page)
        response.set_cookie('remember_token', '', expires=0)
        response.set_cookie('visitor_secret', '', expires=0)
        response.set_cookie('secret', '', expires=0)
        response.set_cookie('session', '', expires=0)
        return response
    if logged_in:
        description = word(
            """You can delete your account on this page.  Type "delete my account" (in lowercase, without the quotes) into the box below and then press the "Delete account" button.  This will erase your interview sessions and your user profile.  To go back to your user profile page, press the "Cancel" button.""")
    else:
        description = word(
            """You can delete your account on this page.  Type "delete my account" (in lowercase, without the quotes) into the box below and then press the "Delete account" button.  This will erase your interview sessions.""")
    return render_template('pages/manage_account.html', form=form, version_warning=None, title=word("Manage account"),
                           tab_title=word("Manage account"), page_title=word("Manage account"), description=description,
                           logged_in=logged_in)


@user.route('/api/user', methods=['GET', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'HEAD'], automatic_options=True)
def api_user():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    if current_user.limited_api and not current_user.can_do('access_user_info'):
        return jsonify_with_status("You do not have sufficient privileges to access user information", 403)
    try:
        user_info = get_user_info(user_id=current_user.id)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status('User not found', 404)
    if request.method == 'GET':
        return jsonify(user_info)
    if request.method == 'POST':
        if current_user.limited_api and not current_user.can_do('edit_user_info'):
            return jsonify_with_status("You do not have sufficient privileges to edit a user's information", 403)
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        info = {}
        for key in ('first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond', 'subdivisionthird',
                    'organization', 'timezone', 'language', 'password'):
            if key in post_data:
                info[key] = post_data[key]
        if 'password' in info and not current_user.has_role_or_permission('admin', permissions='edit_user_password'):
            return jsonify_with_status("You do not have sufficient privileges to change a user's password.", 403)
        try:
            set_user_info(user_id=current_user.id, **info)
        except Exception as err:
            return jsonify_with_status(str(err), 400)
        return ('', 204)
    return ('', 204)


@user.route('/api/user/privileges', methods=['GET'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_user_privileges():
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    try:
        user_info = get_user_info(user_id=current_user.id)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status('User not found', 404)
    if request.method == 'GET':
        return jsonify(user_info['privileges'])


@user.route('/api/user/new', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_create_user():
    if not api_verify(request, roles=['admin'], permissions=['create_user']):
        return jsonify_with_status("Access denied.", 403)
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    if 'email' in post_data and 'username' not in post_data:  # temporary
        post_data['username'] = post_data['email'].strip()
        del post_data['email']
    if 'username' not in post_data:
        return jsonify_with_status("An e-mail address must be supplied.", 400)
    info = {}
    for key in (
            'first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond', 'subdivisionthird',
            'organization',
            'timezone', 'language'):
        if key in post_data:
            info[key] = post_data[key].strip()
    if 'privileges' in post_data and isinstance(post_data['privileges'], list):
        role_list = post_data['privileges']
    else:
        try:
            role_list = json.loads(post_data.get('privileges', '[]'))
        except:
            role_list = [post_data['privileges']]
    if not isinstance(role_list, list):
        if not isinstance(role_list, str):
            return jsonify_with_status("List of privileges must be a string or a list.", 400)
        role_list = [role_list]
    valid_role_names = set()
    for rol in db.session.execute(select(Role).where(Role.name != 'cron').order_by(Role.id)).scalars():
        valid_role_names.add(rol.name)
    for role_name in role_list:
        if role_name not in valid_role_names:
            return jsonify_with_status("Invalid privilege name.  " + str(role_name) + " is not an existing privilege.",
                                       400)
    password = post_data.get('password', random_alphanumeric(10)).strip()
    if len(password) < 4 or len(password) > 254:
        return jsonify_with_status("Password too short or too long", 400)
    try:
        password = str(password)
        user_id = create_user(post_data['username'], password, role_list, info)
    except Exception as err:
        return jsonify_with_status(str(err), 400)
    return jsonify_with_status(dict(user_id=user_id, password=password), 200)


@user.route('/api/user_invite', methods=['POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['POST', 'HEAD'], automatic_options=True)
def api_invite_user():
    if not api_verify(request, roles=['admin'], permissions=['create_user']):
        return jsonify_with_status("Access denied.", 403)
    is_admin = current_user.has_role('admin')
    post_data = request.get_json(silent=True)
    if post_data is None:
        post_data = request.form.copy()
    send_emails = true_or_false(request.args.get('send_emails', True))
    role_name = str(post_data.get('privilege', 'user')).strip() or 'user'
    valid_role_names = set()
    for rol in db.session.execute(select(Role).where(Role.name != 'cron').order_by(Role.id)).scalars():
        if not is_admin and rol.name in ('admin', 'developer', 'advocate'):
            continue
        valid_role_names.add(rol.name)
    if role_name not in valid_role_names:
        return jsonify_with_status("Invalid privilege name.", 400)
    raw_email_addresses = post_data.get('email_addresses', post_data.get('email_address', []))
    if raw_email_addresses.startswith('[') or raw_email_addresses.startswith('"'):
        try:
            raw_email_addresses = json.loads(raw_email_addresses)
        except:
            return jsonify_with_status("The email_addresses field did not contain valid JSON.", 400)
    if not isinstance(raw_email_addresses, list):
        raw_email_addresses = [str(raw_email_addresses)]
    email_addresses = []
    for email_address in raw_email_addresses:
        (part_one, part_two) = email.utils.parseaddr(str(email_address))
        if not re.match(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', part_two):
            return jsonify_with_status("Invalid e-mail address.", 400)
        email_addresses.append(part_two)
    if len(email_addresses) == 0:
        return jsonify_with_status("One or more 'email_addresses' must be supplied.", 400)
    the_role_id = None
    for role in db.session.execute(select(Role).order_by('id')).scalars():
        if role.name == role_name:
            the_role_id = role.id
            break
    if the_role_id is None:
        return jsonify_with_status("Invalid privilege name.", 400)
    for email_address in email_addresses:
        user, user_email = current_app.user_manager.find_user_by_email(email_address)
        if user:
            return jsonify_with_status("That e-mail address is already being used.", 400)
    invite_info = []
    for email_address in email_addresses:
        user_invite = MyUserInvitation(email=email_address, role_id=the_role_id, invited_by_user_id=current_user.id)
        db.session.add(user_invite)
        db.session.commit()
        token = current_app.user_manager.generate_token(user_invite.id)
        accept_invite_link = url_for('user.register',
                                     token=token,
                                     _external=True)
        user_invite.token = token
        db.session.commit()
        info = dict(email=email_address)
        if send_emails:
            try:
                logmessage("Trying to send invite e-mail to " + str(user_invite.email))
                docassemble_flask_user.emails.send_invite_email(user_invite, accept_invite_link)
                logmessage("Sent e-mail invite to " + str(user_invite.email))
                info['invitation_sent'] = True
                info['url'] = accept_invite_link
            except Exception as e:
                try:
                    logmessage("Failed to send invite e-mail: " + e.__class__.__name__ + ': ' + str(e))
                except:
                    logmessage("Failed to send invite e-mail")
                db.session.delete(user_invite)
                db.session.commit()
                info['invitation_sent'] = False
        else:
            info['url'] = accept_invite_link
        invite_info.append(info)
    return jsonify(invite_info)


@user.route('/api/user_info', methods=['GET'])
@cross_origin(origins='*', methods=['GET', 'HEAD'], automatic_options=True)
def api_user_info():
    if not api_verify(request, roles=['admin', 'advocate'], permissions=['access_user_info']):
        return jsonify_with_status("Access denied.", 403)
    if 'username' not in request.args:
        return jsonify_with_status("An e-mail address must be supplied.", 400)
    case_sensitive = true_or_false(request.args.get('case_sensitive', False))
    try:
        user_info = get_user_info(email=request.args['username'], case_sensitive=case_sensitive)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status("User not found.", 404)
    if request.method == 'GET':
        return jsonify(user_info)


@user.route('/api/user/<int:user_id>', methods=['GET', 'DELETE', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'POST', 'HEAD'], automatic_options=True)
def api_user_by_id(user_id):
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    try:
        user_id = int(user_id)
    except:
        return jsonify_with_status("User ID must be an integer.", 400)
    if not (current_user.same_as(user_id) or current_user.has_role_or_permission('admin', 'advocate',
                                                                                 permissions=['access_user_info'])):
        return jsonify_with_status("You do not have sufficient privileges to access user information", 403)
    try:
        user_info = get_user_info(user_id=user_id)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status("User not found.", 404)
    if request.method == 'GET':
        return jsonify(user_info)
    if request.method == 'DELETE':
        if user_id == 1 or user_id == current_user.id:
            return jsonify_with_status("This user account cannot be deleted or deactivated.", 403)
        if request.args.get('remove', None) == 'account':
            if not (current_user.id == user_id or current_user.has_role_or_permission('admin',
                                                                                      permissions=['delete_user'])):
                return jsonify_with_status("You do not have sufficient privileges to delete user accounts.", 403)
            user_interviews(user_id=user_id, secret=None, exclude_invalid=False, action='delete_all',
                            delete_shared=False)
            delete_user_data(user_id, r, r_user)
        elif request.args.get('remove', None) == 'account_and_shared':
            if not current_user.has_role_or_permission('admin', permissions=['delete_user']):
                return jsonify_with_status("You do not have sufficient privileges to delete user accounts.", 403)
            user_interviews(user_id=user_id, secret=None, exclude_invalid=False, action='delete_all',
                            delete_shared=True)
            delete_user_data(user_id, r, r_user)
        else:
            if not current_user.has_role_or_permission('admin', permissions=['edit_user_active_status']):
                return jsonify_with_status("You do not have sufficient privileges to inactivate user accounts.", 403)
            make_user_inactive(user_id=user_id)
        return ('', 204)
    if request.method == 'POST':
        if not (current_user.has_role_or_permission('admin', permissions=['edit_user_info']) or current_user.same_as(
                user_id)):
            return jsonify_with_status("You do not have sufficient privileges to edit user information.", 403)
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        info = {}
        for key in ('first_name', 'last_name', 'country', 'subdivisionfirst', 'subdivisionsecond', 'subdivisionthird',
                    'organization', 'timezone', 'language', 'password'):
            if key in post_data:
                info[key] = post_data[key]
        if 'password' in info and not current_user.has_role_or_permission('admin', permissions=['edit_user_password']):
            return jsonify_with_status("You must have admin privileges to change a password.", 403)
        try:
            set_user_info(user_id=user_id, **info)
        except Exception as err:
            return jsonify_with_status(str(err), 400)
        return ('', 204)
    return ('', 204)


@user.route('/api/user/<int:user_id>/privileges', methods=['GET', 'DELETE', 'POST'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'DELETE', 'POST', 'HEAD'], automatic_options=True)
def api_user_by_id_privileges(user_id):
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    try:
        user_info = get_user_info(user_id=user_id)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status('User not found', 404)
    if request.method == 'GET':
        return jsonify(user_info['privileges'])
    if request.method in ('DELETE', 'POST'):
        if not current_user.has_role_or_permission('admin', permissions=['edit_user_privileges']):
            return jsonify_with_status("Access denied.", 403)
        if request.method == 'DELETE':
            role_name = request.args.get('privilege', None)
            if role_name is None:
                return jsonify_with_status("A privilege name must be provided", 400)
            try:
                remove_user_privilege(user_id, role_name)
            except Exception as err:
                return jsonify_with_status(str(err), 400)
        elif request.method == 'POST':
            post_data = request.get_json(silent=True)
            if post_data is None:
                post_data = request.form.copy()
            role_name = post_data.get('privilege', None)
            if role_name is None:
                return jsonify_with_status("A privilege name must be provided", 400)
            try:
                add_user_privilege(user_id, role_name)
            except Exception as err:
                return jsonify_with_status(str(err), 400)
        db.session.commit()
        return ('', 204)


@user.route('/api/user/<int:user_id>/api', methods=['GET', 'POST', 'DELETE', 'PATCH'])
@csrf.exempt
@cross_origin(origins='*', methods=['GET', 'POST', 'DELETE', 'PATCH', 'HEAD'], automatic_options=True)
def api_user_userid_api(user_id):
    if not api_verify(request):
        return jsonify_with_status("Access denied.", 403)
    try:
        user_id = int(user_id)
    except:
        return jsonify_with_status("User ID must be an integer.", 400)
    if not current_user.same_as(user_id):
        if request.method == 'GET' and not current_user.has_role_or_permission('admin',
                                                                               permissions=['access_user_api_info']):
            return jsonify_with_status("You do not have sufficient privileges to access user API information", 403)
        if request.method in ('POST', 'DELETE', 'PATCH') and not current_user.has_role_or_permission('admin',
                                                                                                     permissions=[
                                                                                                         'edit_user_api_info']):
            return jsonify_with_status("You do not have sufficient privileges to edit user API information", 403)
    try:
        user_info = get_user_info(user_id=user_id, admin=True)
    except Exception as err:
        return jsonify_with_status("Error obtaining user information: " + str(err), 400)
    if user_info is None:
        return jsonify_with_status("User not found.", 404)
    return do_api_user_api(user_id)
