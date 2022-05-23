import codecs
import hashlib
import json

from docassemble.webapp.daredis import r
from flask import request


def add_specific_api_key(name, api_key, user_id, secret_key):
    info = dict(name=name, method='none', constraints=[])
    if not (isinstance(api_key, str) and len(api_key) == 32):
        return False
    info['last_four'] = api_key[-4:]
    new_api_key = encrypt_api_key(api_key, secret_key)
    if len(r.keys('da:apikey:userid:*:key:' + new_api_key + ':info')) > 0:
        return False
    for rkey in r.keys('da:apikey:userid:' + str(user_id) + ':key:*:info'):
        rkey = rkey.decode()
        try:
            info = json.loads(r.get(rkey).decode())
            assert isinstance(info, dict)
        except:
            continue
        if info['name'] == name:
            return False
    r.set('da:apikey:userid:' + str(user_id) + ':key:' + new_api_key + ':info', json.dumps(info))
    return True


def encrypt_api_key(key, secret_key):
    return codecs.encode(
        hashlib.pbkdf2_hmac('sha256', bytearray(key, 'utf-8'), bytearray(secret_key, encoding='utf-8'), 100000),
        'base64').decode().strip()


def get_api_key():
    api_key = request.args.get('key', None)
    if api_key is None and request.method in ('POST', 'PUT', 'PATCH'):
        post_data = request.get_json(silent=True)
        if post_data is None:
            post_data = request.form.copy()
        if 'key' in post_data:
            api_key = post_data['key']
    if api_key is None and 'X-API-Key' in request.cookies:
        api_key = request.cookies['X-API-Key']
    if api_key is None and 'X-API-Key' in request.headers:
        api_key = request.headers['X-API-Key']
    return api_key
