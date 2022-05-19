from flask import request, current_app
from urllib.parse import unquote as urllibunquote
from docassemble.webapp.backend import url_for
from docassemble.webapp.config_server import HTTP_TO_HTTPS
import re

def as_int(val):
    try:
        return int(val)
    except:
        return 0

def get_safe_next_param(param_name, default_endpoint):
    if param_name in request.args:
        safe_next = current_app.user_manager.make_safe_url_function(urllibunquote(request.args[param_name]))
    else:
        safe_next = endpoint_url(default_endpoint)
    return safe_next

def endpoint_url(endpoint, **kwargs):
    url = url_for('index')
    if endpoint:
        url = url_for(endpoint, **kwargs)
    return url


def get_base_url():
    return re.sub(r'^(https?://[^/]+).*', r'\1', url_for('rootindex', _external=True))


def fix_http(url):
    if HTTP_TO_HTTPS:
        return re.sub(r'^http:', 'https:', url)
    return url