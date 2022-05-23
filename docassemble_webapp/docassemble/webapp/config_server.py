import docassemble.base.config

if not docassemble.base.config.loaded:
    docassemble.base.config.load()

from docassemble.webapp.backend import advance_progress, url_for
from docassemble.base.functions import word
from distutils.version import LooseVersion
from flask import Markup
import docassemble.base.util
import time
import re
import types
import os
import sys
import mimetypes
import tempfile
import ruamel.yaml
from simplekv.memory.redisstore import RedisStore
from docassemble.webapp.daredis import r_store
from docassemble.base.config import daconfig, in_celery
from docassemblekvsession import KVSessionExtension
from docassemble.webapp.app_object import app
from docassemble.webapp.backend import get_info_from_file_reference

docassemble.base.util.set_knn_machine_learner(docassemble.webapp.machinelearning.SimpleTextMachineLearner)
docassemble.base.util.set_machine_learning_entry(docassemble.webapp.machinelearning.MachineLearningEntry)
docassemble.base.util.set_random_forest_machine_learner(docassemble.webapp.machinelearning.RandomForestMachineLearner)
docassemble.base.util.set_svm_machine_learner(docassemble.webapp.machinelearning.SVMMachineLearner)

START_TIME = time.time()

min_system_version = '1.2.0'
re._MAXCACHE = 10000

the_method_type = types.FunctionType
equals_byte = bytes('=', 'utf-8')

TypeType = type(type(None))
NoneType = type(None)

STATS = daconfig.get('collect statistics', False)
DEBUG = daconfig.get('debug', False)
ERROR_TYPES_NO_EMAIL = daconfig.get('suppress error notificiations', [])
COOKIELESS_SESSIONS = daconfig.get('cookieless sessions', False)

if DEBUG:
    PREVENT_DEMO = False
elif daconfig.get('allow demo', False):
    PREVENT_DEMO = False
else:
    PREVENT_DEMO = True

REQUIRE_IDEMPOTENT = not daconfig.get('allow non-idempotent questions', True)
STRICT_MODE = daconfig.get('restrict input variables', False)
PACKAGE_PROTECTION = daconfig.get('package protection', True)
PERMISSIONS_LIST = [
    'access_privileges',
    'access_sessions',
    'access_user_info',
    'access_user_api_info',
    'create_user',
    'delete_user',
    'demo_interviews',
    'edit_privileges',
    'edit_sessions',
    'edit_user_active_status',
    'edit_user_info',
    'edit_user_api_info',
    'edit_user_password',
    'edit_user_privileges',
    'interview_data',
    'log_user_in',
    'playground_control',
    'template_parse'
]

HTTP_TO_HTTPS = daconfig.get('behind https load balancer', False)
GITHUB_BRANCH = daconfig.get('github default branch name', 'main')
request_active = True

global_css = ''

global_js = ''

default_playground_yaml = """metadata:
  title: Default playground interview
  short title: Test
  comment: This is a learning tool.  Feel free to write over it.
---
objects:
  - client: Individual
---
question: |
  What is your name?
fields:
  - First Name: client.name.first
  - Middle Name: client.name.middle
    required: False
  - Last Name: client.name.last
  - Suffix: client.name.suffix
    required: False
    code: name_suffix()
---
question: |
  What is your date of birth?
fields:
  - Date of Birth: client.birthdate
    datatype: date
---
mandatory: True
question: |
  Here is your document, ${ client }.
subquestion: |
  In order ${ quest }, you will need this.
attachments:
  - name: Information Sheet
    filename: info_sheet
    content: |
      Your name is ${ client }.

      % if client.age_in_years() > 60:
      You are a senior.
      % endif
      Your quest is ${ quest }.  You
      are eligible for ${ benefits }.
---
question: |
  What is your quest?
fields:
  - Your quest: quest
    hint: to find the Loch Ness Monster
---
code: |
  if client.age_in_years() < 18:
    benefits = "CHIP"
  else:
    benefits = "Medicaid"
"""

ok_mimetypes = {
    "application/javascript": "javascript",
    "application/json": "javascript",
    "text/css": "css",
    "text/html": "htmlmixed",
    "text/x-python": "python"
}
ok_extensions = {
    "4th": "forth",
    "apl": "apl",
    "asc": "asciiarmor",
    "asn": "asn.1",
    "asn1": "asn.1",
    "aspx": "htmlembedded",
    "b": "brainfuck",
    "bash": "shell",
    "bf": "brainfuck",
    "c": "clike",
    "c++": "clike",
    "cc": "clike",
    "cl": "commonlisp",
    "clj": "clojure",
    "cljc": "clojure",
    "cljs": "clojure",
    "cljx": "clojure",
    "cob": "cobol",
    "coffee": "coffeescript",
    "cpp": "clike",
    "cpy": "cobol",
    "cql": "sql",
    "cr": "crystal",
    "cs": "clike",
    "csharp": "clike",
    "css": "css",
    "cxx": "clike",
    "cyp": "cypher",
    "cypher": "cypher",
    "d": "d",
    "dart": "dart",
    "diff": "diff",
    "dtd": "dtd",
    "dyalog": "apl",
    "dyl": "dylan",
    "dylan": "dylan",
    "e": "eiffel",
    "ecl": "ecl",
    "ecmascript": "javascript",
    "edn": "clojure",
    "ejs": "htmlembedded",
    "el": "commonlisp",
    "elm": "elm",
    "erb": "htmlembedded",
    "erl": "erlang",
    "f": "fortran",
    "f77": "fortran",
    "f90": "fortran",
    "f95": "fortran",
    "factor": "factor",
    "feature": "gherkin",
    "for": "fortran",
    "forth": "forth",
    "fs": "mllike",
    "fth": "forth",
    "fun": "mllike",
    "go": "go",
    "gradle": "groovy",
    "groovy": "groovy",
    "gss": "css",
    "h": "clike",
    "h++": "clike",
    "haml": "haml",
    "handlebars": "htmlmixed",
    "hbs": "htmlmixed",
    "hh": "clike",
    "hpp": "clike",
    "hs": "haskell",
    "html": "htmlmixed",
    "hx": "haxe",
    "hxml": "haxe",
    "hxx": "clike",
    "in": "properties",
    "ini": "properties",
    "ino": "clike",
    "intr": "dylan",
    "j2": "jinja2",
    "jade": "pug",
    "java": "clike",
    "jinja": "jinja2",
    "jinja2": "jinja2",
    "jl": "julia",
    "json": "json",
    "jsonld": "javascript",
    "jsp": "htmlembedded",
    "jsx": "jsx",
    "ksh": "shell",
    "kt": "clike",
    "less": "css",
    "lhs": "haskell-literate",
    "lisp": "commonlisp",
    "ls": "livescript",
    "ltx": "stex",
    "lua": "lua",
    "m": "octave",
    "markdown": "markdown",
    "mbox": "mbox",
    "md": "markdown",
    "mkd": "markdown",
    "mo": "modelica",
    "mps": "mumps",
    "msc": "mscgen",
    "mscgen": "mscgen",
    "mscin": "mscgen",
    "msgenny": "mscgen",
    "node": "javascript",
    "nq": "ntriples",
    "nsh": "nsis",
    "nsi": "nsis",
    "nt": "ntriples",
    "nut": "clike",
    "oz": "oz",
    "p": "pascal",
    "pas": "pascal",
    "patch": "diff",
    "pgp": "asciiarmor",
    "php": "php",
    "php3": "php",
    "php4": "php",
    "php5": "php",
    "php7": "php",
    "phtml": "php",
    "pig": "pig",
    "pl": "perl",
    "pls": "sql",
    "pm": "perl",
    "pp": "puppet",
    "pro": "idl",
    "properties": "properties",
    "proto": "protobuf",
    "ps1": "powershell",
    "psd1": "powershell",
    "psm1": "powershell",
    "pug": "pug",
    "pxd": "python",
    "pxi": "python",
    "py": "python",
    "pyx": "python",
    "q": "q",
    "r": "r",
    "rb": "ruby",
    "rq": "sparql",
    "rs": "rust",
    "rst": "rst",
    "s": "gas",
    "sas": "sas",
    "sass": "sass",
    "scala": "clike",
    "scm": "scheme",
    "scss": "css",
    "sh": "shell",
    "sieve": "sieve",
    "sig": "asciiarmor",
    "siv": "sieve",
    "slim": "slim",
    "smackspec": "mllike",
    "sml": "mllike",
    "soy": "soy",
    "sparql": "sparql",
    "sql": "sql",
    "ss": "scheme",
    "st": "smalltalk",
    "styl": "stylus",
    "swift": "swift",
    "tcl": "tcl",
    "tex": "stex",
    "textile": "textile",
    "toml": "toml",
    "tpl": "smarty",
    "ts": "javascript",
    "tsx": "javascript",
    "ttcn": "ttcn",
    "ttcn3": "ttcn",
    "ttcnpp": "ttcn",
    "ttl": "turtle",
    "vb": "vb",
    "vbs": "vbscript",
    "vhd": "vhdl",
    "vhdl": "vhdl",
    "vtl": "velocity",
    "vue": "vue",
    "wast": "wast",
    "wat": "wast",
    "webidl": "webidl",
    "xml": "xml",
    "xquery": "xquery",
    "xsd": "xml",
    "xsl": "xml",
    "xu": "mscgen",
    "xy": "xquery",
    "yaml": "yaml",
    "yml": "yaml",
    "ys": "yacas",
    "z80": "z80"
}


def update_editable():
    try:
        if 'editable mimetypes' in daconfig and isinstance(daconfig['editable mimetypes'], list):
            for item in daconfig['editable mimetypes']:
                if isinstance(item, str):
                    ok_mimetypes[item] = 'null'
    except:
        pass

    try:
        if 'editable extensions' in daconfig and isinstance(daconfig['editable extensions'], list):
            for item in daconfig['editable extensions']:
                if isinstance(item, str):
                    ok_extensions[item] = 'null'
    except:
        pass


update_editable()

default_yaml_filename = daconfig.get('default interview', None)
final_default_yaml_filename = daconfig.get('default interview', 'docassemble.base:data/questions/default-interview.yml')
keymap = daconfig.get('keymap', None)
google_config = daconfig.get('google', {})

ga_configured = bool(google_config.get('analytics id', None) is not None)

if google_config.get('analytics id', None) is not None or daconfig.get('segment id', None) is not None:
    analytics_configured = True
    reserved_argnames = (
        'i', 'json', 'js_target', 'from_list', 'session', 'cache', 'reset', 'new_session', 'action', 'utm_source',
        'utm_medium', 'utm_campaign', 'utm_term', 'utm_content')
else:
    analytics_configured = False
    reserved_argnames = ('i', 'json', 'js_target', 'from_list', 'session', 'cache', 'reset', 'new_session', 'action')

contains_volatile = re.compile(r'^(x\.|x\[|.*\[[ijklmn]\])')
is_integer = re.compile(r'^[0-9]+$')
detect_mobile = re.compile(
    r'Mobile|iP(hone|od|ad)|Android|BlackBerry|IEMobile|Kindle|NetFront|Silk-Accelerated|(hpw|web)OS|Fennec|Minimo|Opera M(obi|ini)|Blazer|Dolfin|Dolphin|Skyfire|Zune')
alphanumeric_only = re.compile(r'[\W_]+')
phone_pattern = re.compile(r"^[\d\+\-\(\) ]+$")
document_match = re.compile(r'^--- *$', flags=re.MULTILINE)
fix_tabs = re.compile(r'\t')
fix_initial = re.compile(r'^---\n')
noquote_match = re.compile(r'"')
lt_match = re.compile(r'<')
gt_match = re.compile(r'>')
amp_match = re.compile(r'&')
extraneous_var = re.compile(r'^x\.|^x\[')
key_requires_preassembly = re.compile(
    r'^(session_local\.|device_local\.|user_local\.|x\.|x\[|_multiple_choice|.*\[[ijklmn]\])')
match_brackets = re.compile(r'\[[BR]?\'[^\]]*\'\]$')
match_inside_and_outside_brackets = re.compile(r'(.*)(\[[BR]?\'[^\]]*\'\])$')
match_inside_brackets = re.compile(r'\[([BR]?)\'([^\]]*)\'\]')
valid_python_var = re.compile(r'^[A-Za-z][A-Za-z0-9\_]*$')
valid_python_exp = re.compile(r'^[A-Za-z][A-Za-z0-9\_\.]*$')

default_title = daconfig.get('default title', daconfig.get('brandname', 'docassemble'))
default_short_title = daconfig.get('default short title', default_title)
os.environ['PYTHON_EGG_CACHE'] = tempfile.gettempdir()
PNG_RESOLUTION = daconfig.get('png resolution', 300)
PNG_SCREEN_RESOLUTION = daconfig.get('png screen resolution', 72)
PDFTOPPM_COMMAND = daconfig.get('pdftoppm', 'pdftoppm')
DEFAULT_LANGUAGE = daconfig.get('language', 'en')
DEFAULT_LOCALE = daconfig.get('locale', 'en_US.utf8')
DEFAULT_DIALECT = daconfig.get('dialect', 'us')
LOGSERVER = daconfig.get('log server', None)
CHECKIN_INTERVAL = int(daconfig.get('checkin interval', 6000))
# message_sequence = dbtableprefix + 'message_id_seq'
NOTIFICATION_CONTAINER = '<div class="datopcenter col-sm-7 col-md-6 col-lg-5" id="daflash">%s</div>'
NOTIFICATION_MESSAGE = '<div class="da-alert alert alert-%s alert-dismissible fade show" role="alert">%s<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button></div>'

USING_SUPERVISOR = bool(os.environ.get('SUPERVISOR_SERVER_URL', None))

audio_mimetype_table = {'mp3': 'audio/mpeg', 'ogg': 'audio/ogg'}

valid_voicerss_dialects = {
    'ca': ['es'],
    'zh': ['cn', 'hk', 'tw'],
    'da': ['dk'],
    'nl': ['nl'],
    'en': ['au', 'ca', 'gb', 'in', 'us'],
    'fi': ['fi'],
    'fr': ['ca, fr'],
    'de': ['de'],
    'it': ['it'],
    'ja': ['jp'],
    'ko': ['kr'],
    'nb': ['no'],
    'pl': ['pl'],
    'pt': ['br', 'pt'],
    'ru': ['ru'],
    'es': ['mx', 'es'],
    'sv': ['se']
}

voicerss_config = daconfig.get('voicerss', None)
VOICERSS_ENABLED = not bool(
    not voicerss_config or ('enable' in voicerss_config and not voicerss_config['enable']) or not (
            'key' in voicerss_config and voicerss_config['key']))
ROOT = daconfig.get('root', '/')
# app.logger.warning("default sender is " + current_app.config['MAIL_DEFAULT_SENDER'] + "\n")
exit_page = daconfig.get('exitpage', 'https://docassemble.org')

SUPERVISORCTL = daconfig.get('supervisorctl', 'supervisorctl')
# PACKAGE_CACHE = daconfig.get('packagecache', '/var/www/.cache')
WEBAPP_PATH = daconfig.get('webapp', '/usr/share/docassemble/webapp/docassemble.wsgi')
UPLOAD_DIRECTORY = daconfig.get('uploads', '/usr/share/docassemble/files')
PACKAGE_DIRECTORY = daconfig.get('packages', '/usr/share/docassemble/local' + str(sys.version_info.major) + '.' + str(
    sys.version_info.minor))
FULL_PACKAGE_DIRECTORY = os.path.join(PACKAGE_DIRECTORY, 'lib',
                                      'python' + str(sys.version_info.major) + '.' + str(sys.version_info.minor),
                                      'site-packages')
LOG_DIRECTORY = daconfig.get('log', '/usr/share/docassemble/log')

PAGINATION_LIMIT = daconfig.get('pagination limit', 100)
PAGINATION_LIMIT_PLUS_ONE = PAGINATION_LIMIT + 1

init_py_file = """try:
    __import__('pkg_resources').declare_namespace(__name__)
except ImportError:
    __path__ = __import__('pkgutil').extend_path(__path__, __name__)
"""

SHOW_LOGIN = daconfig.get('show login', True)
ALLOW_REGISTRATION = daconfig.get('allow registration', True)

if in_celery:
    LOGFILE = daconfig.get('celery flask log', '/tmp/celery-flask.log')
else:
    LOGFILE = daconfig.get('flask log', '/tmp/flask.log')

mimetypes.add_type('application/x-yaml', '.yml')
mimetypes.add_type('application/x-yaml', '.yaml')

store = RedisStore(r_store)

kv_session = KVSessionExtension(store, app)


def get_clicksend_config():
    if 'clicksend' in daconfig and isinstance(daconfig['clicksend'], (list, dict)):
        the_clicksend_config = {'name': {}, 'number': {}}
        if isinstance(daconfig['clicksend'], dict):
            config_list = [daconfig['clicksend']]
        else:
            config_list = daconfig['clicksend']
        for the_config in config_list:
            if isinstance(the_config,
                          dict) and 'api username' in the_config and 'api key' in the_config and 'number' in the_config:
                if 'country' not in the_config:
                    the_config['country'] = docassemble.webapp.backend.DEFAULT_COUNTRY or 'US'
                if 'from email' not in the_config:
                    the_config['from email'] = app.config['MAIL_DEFAULT_SENDER']
                the_clicksend_config['number'][str(the_config['number'])] = the_config
                if 'default' not in the_clicksend_config['name']:
                    the_clicksend_config['name']['default'] = the_config
                if 'name' in the_config:
                    the_clicksend_config['name'][the_config['name']] = the_config
            else:
                sys.stderr.write("improper setup in clicksend configuration\n")
        if 'default' not in the_clicksend_config['name']:
            the_clicksend_config = None
    else:
        the_clicksend_config = None
    # if fax_provider == 'clicksend' and the_clicksend_config is None:
    #    sys.stderr.write("improper clicksend configuration; faxing will not be functional\n")
    return the_clicksend_config


clicksend_config = get_clicksend_config()

fax_provider = daconfig.get('fax provider', None) or 'clicksend'


def get_telnyx_config():
    if 'telnyx' in daconfig and isinstance(daconfig['telnyx'], (list, dict)):
        the_telnyx_config = {'name': {}, 'number': {}}
        if isinstance(daconfig['telnyx'], dict):
            config_list = [daconfig['telnyx']]
        else:
            config_list = daconfig['telnyx']
        for the_config in config_list:
            if isinstance(the_config,
                          dict) and 'app id' in the_config and 'api key' in the_config and 'number' in the_config:
                if 'country' not in the_config:
                    the_config['country'] = docassemble.webapp.backend.DEFAULT_COUNTRY or 'US'
                if 'from email' not in the_config:
                    the_config['from email'] = app.config['MAIL_DEFAULT_SENDER']
                the_telnyx_config['number'][str(the_config['number'])] = the_config
                if 'default' not in the_telnyx_config['name']:
                    the_telnyx_config['name']['default'] = the_config
                if 'name' in the_config:
                    the_telnyx_config['name'][the_config['name']] = the_config
            else:
                sys.stderr.write("improper setup in twilio configuration\n")
        if 'default' not in the_telnyx_config['name']:
            the_telnyx_config = None
    else:
        the_telnyx_config = None
    if fax_provider == 'telnyx' and the_telnyx_config is None:
        sys.stderr.write("improper telnyx configuration; faxing will not be functional\n")
    return the_telnyx_config


telnyx_config = get_telnyx_config()


def get_twilio_config():
    if 'twilio' in daconfig:
        the_twilio_config = {}
        the_twilio_config['account sid'] = {}
        the_twilio_config['number'] = {}
        the_twilio_config['name'] = {}
        if not isinstance(daconfig['twilio'], list):
            config_list = [daconfig['twilio']]
        else:
            config_list = daconfig['twilio']
        for tconfig in config_list:
            if isinstance(tconfig, dict) and 'account sid' in tconfig and 'number' in tconfig:
                the_twilio_config['account sid'][str(tconfig['account sid'])] = 1
                the_twilio_config['number'][str(tconfig['number'])] = tconfig
                if 'default' not in the_twilio_config['name']:
                    the_twilio_config['name']['default'] = tconfig
                if 'name' in tconfig:
                    the_twilio_config['name'][tconfig['name']] = tconfig
            else:
                sys.stderr.write("improper setup in twilio configuration\n")
        if 'default' not in the_twilio_config['name']:
            the_twilio_config = None
    else:
        the_twilio_config = None
    return the_twilio_config


twilio_config = get_twilio_config()


def get_page_parts():
    the_page_parts = {}
    if 'global footer' in daconfig:
        if isinstance(daconfig['global footer'], dict):
            the_page_parts['global footer'] = {}
            for lang, val in daconfig['global footer'].items():
                the_page_parts['global footer'][lang] = Markup(val)
        else:
            the_page_parts['global footer'] = {'*': Markup(str(daconfig['global footer']))}

    for page_key in (
            'login page', 'register page', 'interview page', 'start page', 'profile page', 'reset password page',
            'forgot password page', 'change password page', '404 page'):
        for part_key in (
                'title', 'tab title', 'extra css', 'extra javascript', 'heading', 'pre', 'submit', 'post', 'footer'):
            key = page_key + ' ' + part_key
            if key in daconfig:
                if isinstance(daconfig[key], dict):
                    the_page_parts[key] = {}
                    for lang, val in daconfig[key].items():
                        the_page_parts[key][lang] = Markup(val)
                else:
                    the_page_parts[key] = {'*': Markup(str(daconfig[key]))}

    the_main_page_parts = {}
    lang_list = set()
    main_page_parts_list = (
        'main page back button label',
        'main page continue button label',
        'main page corner back button label',
        'main page exit label',
        'main page exit link',
        'main page exit url',
        'main page footer',
        'main page help label',
        'main page logo',
        'main page navigation bar html',
        'main page post',
        'main page pre',
        'main page resume button label',
        'main page right',
        'main page short logo',
        'main page short title',
        'main page submit',
        'main page subtitle',
        'main page title url opens in other window',
        'main page title url',
        'main page title',
        'main page under')
    for key in main_page_parts_list:
        if key in daconfig and isinstance(daconfig[key], dict):
            for lang in daconfig[key]:
                lang_list.add(lang)
    lang_list.add(DEFAULT_LANGUAGE)
    lang_list.add('*')
    for lang in lang_list:
        the_main_page_parts[lang] = {}
    for key in main_page_parts_list:
        for lang in lang_list:
            if key in daconfig:
                if isinstance(daconfig[key], dict):
                    the_main_page_parts[lang][key] = daconfig[key].get(lang, daconfig[key].get('*', ''))
                else:
                    the_main_page_parts[lang][key] = daconfig[key]
            else:
                the_main_page_parts[lang][key] = ''
        if the_main_page_parts[DEFAULT_LANGUAGE][key] == '' and the_main_page_parts['*'][key] != '':
            the_main_page_parts[DEFAULT_LANGUAGE][key] = the_main_page_parts['*'][key]
    return (the_page_parts, the_main_page_parts)


(page_parts, main_page_parts) = get_page_parts()

app.debug = False
app.config['CONTAINER_CLASS'] = 'container-fluid' if daconfig.get('admin full width', False) else 'container'
app.config['USE_GOOGLE_LOGIN'] = False
app.config['USE_FACEBOOK_LOGIN'] = False
app.config['USE_TWITTER_LOGIN'] = False
app.config['USE_AUTH0_LOGIN'] = False
app.config['USE_KEYCLOAK_LOGIN'] = False
app.config['USE_AZURE_LOGIN'] = False
app.config['USE_GOOGLE_DRIVE'] = False
app.config['USE_ONEDRIVE'] = False
app.config['USE_PHONE_LOGIN'] = False
app.config['USE_GITHUB'] = False
app.config['USE_PASSWORD_LOGIN'] = not bool(daconfig.get('password login', True) is False)
if twilio_config is not None and daconfig.get('phone login', False) is True:
    app.config['USE_PHONE_LOGIN'] = True
if 'oauth' in daconfig:
    app.config['OAUTH_CREDENTIALS'] = daconfig['oauth']
    app.config['USE_GOOGLE_LOGIN'] = bool('google' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['google'] and daconfig['oauth']['google']['enable'] is False))
    app.config['USE_FACEBOOK_LOGIN'] = bool('facebook' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['facebook'] and daconfig['oauth']['facebook']['enable'] is False))
    app.config['USE_TWITTER_LOGIN'] = bool('twitter' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['twitter'] and daconfig['oauth']['twitter']['enable'] is False))
    app.config['USE_AUTH0_LOGIN'] = bool('auth0' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['auth0'] and daconfig['oauth']['auth0']['enable'] is False))
    app.config['USE_KEYCLOAK_LOGIN'] = bool('keycloak' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['keycloak'] and daconfig['oauth']['keycloak']['enable'] is False))
    app.config['USE_AZURE_LOGIN'] = bool('azure' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['azure'] and daconfig['oauth']['azure']['enable'] is False))
    app.config['USE_GOOGLE_DRIVE'] = bool('googledrive' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['googledrive'] and daconfig['oauth']['googledrive']['enable'] is False))
    app.config['USE_ONEDRIVE'] = bool('onedrive' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['onedrive'] and daconfig['oauth']['onedrive']['enable'] is False))
    app.config['USE_GITHUB'] = bool('github' in daconfig['oauth'] and not (
            'enable' in daconfig['oauth']['github'] and daconfig['oauth']['github']['enable'] is False))
else:
    app.config['OAUTH_CREDENTIALS'] = {}
app.config['USE_PYPI'] = daconfig.get('pypi', False)

if daconfig.get('button size', 'medium') == 'medium':
    app.config['BUTTON_CLASS'] = 'btn-da'
elif daconfig['button size'] == 'large':
    app.config['BUTTON_CLASS'] = 'btn-lg btn-da'
elif daconfig['button size'] == 'small':
    app.config['BUTTON_CLASS'] = 'btn-sm btn-da'
else:
    app.config['BUTTON_CLASS'] = 'btn-da'

if daconfig.get('button style', 'normal') == 'normal':
    app.config['BUTTON_STYLE'] = 'btn-'
elif daconfig['button style'] == 'outline':
    app.config['BUTTON_STYLE'] = 'btn-outline-'
else:
    app.config['BUTTON_STYLE'] = 'btn-'
BUTTON_COLOR_NAV_LOGIN = daconfig['button colors'].get('navigation bar login', 'primary')
app.config['FOOTER_CLASS'] = str(daconfig.get('footer css class', 'bg-light')).strip() + ' dafooter'


def get_base_words():
    documentation = get_info_from_file_reference('docassemble.base:data/sources/base-words.yml')
    if 'fullpath' in documentation and documentation['fullpath'] is not None:
        with open(documentation['fullpath'], 'r', encoding='utf-8') as fp:
            content = fp.read()
            content = fix_tabs.sub('  ', content)
            return ruamel.yaml.safe_load(content)
    return None


base_words = get_base_words()


def get_title_documentation():
    documentation = get_info_from_file_reference('docassemble.base:data/questions/title_documentation.yml')
    if 'fullpath' in documentation and documentation['fullpath'] is not None:
        with open(documentation['fullpath'], 'r', encoding='utf-8') as fp:
            content = fp.read()
            content = fix_tabs.sub('  ', content)
            return ruamel.yaml.safe_load(content)
    return None


title_documentation = get_title_documentation()
DOCUMENTATION_BASE = daconfig.get('documentation base url', 'https://docassemble.org/docs/')


def get_documentation_dict():
    documentation = get_info_from_file_reference('docassemble.base:data/questions/documentation.yml')
    if 'fullpath' in documentation and documentation['fullpath'] is not None:
        with open(documentation['fullpath'], 'r', encoding='utf-8') as fp:
            content = fp.read()
            content = fix_tabs.sub('  ', content)
            return ruamel.yaml.safe_load(content)
    return None


documentation_dict = get_documentation_dict()


def get_name_info():
    docstring = get_info_from_file_reference('docassemble.base:data/questions/docstring.yml')
    if 'fullpath' in docstring and docstring['fullpath'] is not None:
        with open(docstring['fullpath'], 'r', encoding='utf-8') as fp:
            content = fp.read()
            content = fix_tabs.sub('  ', content)
            info = ruamel.yaml.safe_load(content)
        for val in info:
            info[val]['name'] = val
            if 'insert' not in info[val]:
                info[val]['insert'] = val
            if 'show' not in info[val]:
                info[val]['show'] = False
            if 'exclude' not in info[val]:
                info[val]['exclude'] = False
        return info
    return None


base_name_info = get_name_info()

if LooseVersion(min_system_version) > LooseVersion(daconfig['system version']):
    version_warning = word(
        "A new docassemble system version is available.  If you are using Docker, install a new Docker image.")
else:
    version_warning = None

if COOKIELESS_SESSIONS:
    index_path = '/i'
    html_index_path = '/interviefrom docassemble.webapp.backend import advance_progress, can_access_file_number, cloud, directory_for, fetch_previous_user_dict, fetch_user_dict, generate_csrf, get_session_uids, initial_dict, url_for, url_if_existsw'
else:
    index_path = '/interview'
    html_index_path = '/i'

