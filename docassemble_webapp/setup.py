import os
from setuptools import setup, find_packages

def read(fname):
    return open(os.path.join(os.path.dirname(__file__), fname), encoding='utf-8').read()

setup_requires = [
    'enum34==1.1.8'
    ]
install_requires = [
    'docassemble==1.3.21',
    'docassemble.base==1.3.21',
    'docassemble.demo==1.3.21',
    "3to2==1.1.1",
    "airtable-python-wrapper==0.15.2",
    "alembic==1.6.2",
    "aloe==0.2.0",
    "amqp==5.0.6",
    "ansicolors==1.1.8",
    "asn1crypto==1.4.0",
    "astunparse==1.6.3",
    "atomicwrites==1.4.0",
    "attrs==21.2.0",
    "azure-common==1.1.27",
    "azure-core==1.13.0",
    "azure-identity==1.5.0",
    "azure-keyvault-secrets==4.2.0",
    "azure-nspkg==3.0.2",
    "azure-storage-blob==12.8.1",
    "Babel==2.9.1",
    "bcrypt==3.2.0",
    "beautifulsoup4==4.9.3",
    "bidict==0.21.2",
    "billiard==3.6.4.0",
    "bleach==3.3.0",
    "blinker==1.4",
    "boto3==1.17.71",
    "boto==2.49.0",
    "botocore==1.20.71",
    "cachetools==4.2.2",
    "cairocffi==1.3.0",
    "cairosvg==2.5.2",
    "celery==5.2.2",
    "certifi==2020.12.5",
    "cffi==1.14.5",
    "chardet==4.0.0",
    "click-didyoumean==0.0.3",
    "click-plugins==1.1.1",
    "click-repl==0.2.0",
    "click==8.0.3",
    "clicksend-client==5.0.72",
    "colorama==0.4.4",
    "configparser==5.0.2",
    "convertapi==1.4.0",
    "crayons==0.4.0",
    "cryptography==3.4.7",
    "cssselect2==0.4.1",
    "da-pkg-resources==0.0.1",
    "dnspython==1.16.0",
    "Docassemble-Flask-User==0.6.24",
    "Docassemble-Pattern==3.6.4",
    "docassemble-textstat==0.7.1",
    "docassemblekvsession==0.6",
    "docopt==0.6.2",
    "docutils==0.17.1",
    "docxcompose==1.3.2",
    "docxtpl==0.15.2",
    "email-validator==1.1.2",
    "et-xmlfile==1.1.0",
    "eventlet==0.31.0",
    "Flask-Babel==2.0.0",
    "Flask-Cors==3.0.10",
    "Flask-Login==0.5.0",
    "Flask-Mail==0.9.1",
    "Flask-SocketIO==5.0.1",
    "Flask-SQLAlchemy==2.4.4",
    "Flask-WTF==0.14.3",
    "Flask==1.1.2",
    "future==0.18.2",
    "gcs-oauth2-boto-plugin==2.7",
    "geographiclib==1.50",
    "geopy==2.1.0",
    "gherkin-official==4.1.3",
    "google-api-core==1.26.3",
    "google-api-python-client==2.15.0",
    "google-auth-httplib2==0.1.0",
    "google-auth-oauthlib==0.4.4",
    "google-auth==1.30.0",
    "google-cloud-core==1.5.0",
    "google-cloud-storage==1.38.0",
    "google-cloud-translate==3.1.0",
    "google-crc32c==1.1.2",
    "google-i18n-address==2.4.0",
    "google-reauth==0.1.1",
    "google-resumable-media==1.2.0",
    "googleapis-common-protos==1.53.0",
    "greenlet==1.1.0",
    "grpcio==1.37.1",
    "gspread==3.7.0",
    "guess-language-spirit==0.5.3",
    "httplib2==0.19.1",
    "humanize==3.5.0",
    "Hyphenate==1.1.0",
    "idna==2.10",
    "importlib-metadata==4.0.1",
    "importlib-resources==5.1.2",
    "iniconfig==1.1.1",
    "iso8601==0.1.14",
    "isodate==0.6.0",
    "itsdangerous==2.0.0",
    "jdcal==1.4.1",
    "jeepney==0.6.0",
    "jellyfish==0.6.1",
    "Jinja2==3.0.0",
    "jmespath==0.10.0",
    "joblib==1.0.1",
    "keyring==23.0.1",
    "kombu==5.2.2",
    "libcst==0.3.18",
    "links-from-link-header==0.1.0",
    "lxml==4.6.5",
    "Mako==1.1.4",
    "Markdown==3.3.4",
    "MarkupSafe==2.0.0",
    "mdx-smartypants==1.5.1",
    "minio==7.0.3",
    "monotonic==1.6",
    "msal-extensions==0.3.0",
    "msal==1.11.0",
    "msrest==0.6.21",
    "mypy-extensions==0.4.3",
    "namedentities==1.5.2",
    "netifaces==0.10.9",
    "nltk==3.6.6",
    "nose==1.3.7",
    "num2words==0.5.10",
    "numpy==1.21.0",
    "oauth2client==4.1.3",
    "oauthlib==3.1.0",
    "openpyxl==3.0.7",
    "ordered-set==4.0.2",
    "packaging==20.9",
    "pandas==1.2.4",
    "passlib==1.7.4",
    "pathlib==1.0.1",
    "pdfminer.six==20201018",
    "phonenumbers==8.12.22",
    "Pillow==9.0.0",
    "pip==21.1",
    "pkginfo==1.7.0",
    "pluggy==0.13.1",
    "ply==3.11",
    "portalocker==1.7.1",
    "prompt-toolkit==3.0.18",
    "proto-plus==1.18.1",
    "protobuf==3.16.0",
    "psutil==5.8.0",
    "psycopg2-binary==2.8.6",
    "py==1.10.0",
    "pyasn1-modules==0.2.8",
    "pyasn1==0.4.8",
    "pycountry==20.7.3",
    "pycparser==2.20",
    "pycryptodome==3.10.1",
    "pycryptodomex==3.10.1",
    "pycurl==7.43.0.6",
    "Pygments==2.9.0",
    "PyJWT==1.7.1",
    "PyLaTeX==1.4.1",
    "pyOpenSSL==20.0.1",
    "pyotp==2.6.0",
    "pyparsing==2.4.7",
    "PyPDF2==1.26.0",
    "pyPdf==1.13",
    "pypdftk==0.5",
    "pypng==0.0.20",
    "PySocks==1.7.1",
    "pytest==6.2.4",
    "python-dateutil==2.8.1",
    "python-docx==0.8.10",
    "python-editor==1.0.4",
    "python-engineio==4.1.0",
    "python-http-client==3.3.2",
    "python-ldap==3.4.0",
    "python-socketio==5.2.1",
    "pytz==2021.1",
    "pyu2f==0.1.5",
    "PyNaCl==1.4.0",
    "PyYAML==5.4.1",
    "pyzbar==0.1.8",
    "qrcode==6.1",
    "rauth==0.7.3",
    "readme-renderer==29.0",
    "redis==3.5.3",
    "regex==2021.11.2",
    "reportlab==3.5.55",
    "repoze.lru==0.7",
    "requests-oauthlib==1.3.0",
    "requests-toolbelt==0.9.1",
    "requests==2.25.1",
    "retry-decorator==1.1.1",
    "rfc3339==6.2",
    "rfc3986==1.5.0",
    "rsa==4.7.2",
    "ruamel.yaml.clib==0.2.2",
    "ruamel.yaml==0.17.4",
    "s3transfer==0.4.2",
    "s4cmd==2.1.0",
    "scikit-learn==0.24.2",
    "scipy==1.5.4",
    "SecretStorage==3.3.1",
    "selenium==3.141.0",
    "sendgrid==6.7.0",
    "simplekv==0.14.1",
    "six==1.16.0",
    "sklearn==0.0",
    "SocksiPy-branch==1.1",
    "sortedcontainers==2.3.0",
    "soupsieve==2.2.1",
    "SQLAlchemy==1.4.15",
    "starkbank-ecdsa==2.0.1",
    "tailer==0.4.1",
    "telnyx==1.4.0",
    "threadpoolctl==2.1.0",
    "tinycss2==1.1.1",
    "titlecase==2.0.0",
    "toml==0.10.2",
    "tqdm==4.60.0",
    "twilio==6.58.0",
    "twine==3.4.1",
    "typing-extensions==3.10.0.0",
    "typing-inspect==0.6.0",
    "tzlocal==2.1",
    "ua-parser==0.10.0",
    "uritemplate==3.0.1",
    "urllib3==1.26.5",
    "us==2.0.2",
    "user-agents==2.2.0",
    "uWSGI==2.0.19.1",
    "vine==5.0.0",
    "wcwidth==0.2.5",
    "webdriver-manager==3.4.1",
    "webencodings==0.5.1",
    "Werkzeug==2.0.0",
    "WTForms==2.3.3",
    "xfdfgen==0.4",
    "xlrd==2.0.1",
    "XlsxWriter==1.4.3",
    "xlwt==1.3.0",
    "zipp==3.4.1"
]

setup(name='docassemble.webapp',
      version='1.3.21',
      python_requires='>=3.8',
      description=('The web application components of the docassemble system.'),
      long_description=read("README.md"),
      long_description_content_type='text/markdown',
      author='Jonathan Pyle',
      author_email='jhpyle@gmail.com',
      license='MIT',
      url='https://docassemble.org',
      packages=find_packages(),
      namespace_packages = ['docassemble'],
      install_requires = install_requires,
      zip_safe = False,
      package_data={'docassemble.webapp': ['alembic.ini', os.path.join('alembic', '*'), os.path.join('alembic', 'versions', '*'), os.path.join('data', '*.*'), os.path.join('data', 'static', '*.*'), os.path.join('data', 'static', 'favicon', '*.*'), os.path.join('data', 'questions', '*.*'), os.path.join('templates', 'base_templates', '*.html'), os.path.join('templates', 'flask_user', '*.html'), os.path.join('templates', 'flask_user', 'emails', '*.*'), os.path.join('templates', 'pages', '*.html'), os.path.join('templates', 'pages', '*.xml'), os.path.join('templates', 'pages', '*.js'), os.path.join('templates', 'users', '*.html'), os.path.join('static', 'app', '*.*'), os.path.join('static', 'yamlmixed', '*.*'), os.path.join('static', 'sounds', '*.*'), os.path.join('static', 'examples', '*.*'), os.path.join('static', 'fontawesome', 'js', '*.*'), os.path.join('static', 'office', '*.*'), os.path.join('static', 'bootstrap-fileinput', 'img', '*'), os.path.join('static', 'img', '*'), os.path.join('static', 'bootstrap-fileinput', 'themes', 'fas', '*'), os.path.join('static', 'bootstrap-fileinput', 'js', 'locales', '*'), os.path.join('static', 'bootstrap-fileinput', 'js', 'plugins', '*'), os.path.join('static', 'bootstrap-slider', 'dist', '*.js'), os.path.join('static', 'bootstrap-slider', 'dist', 'css', '*.css'), os.path.join('static', 'bootstrap-fileinput', 'css', '*.css'), os.path.join('static', 'bootstrap-fileinput', 'js', '*.js'), os.path.join('static', 'bootstrap-fileinput', 'themes', 'fa', '*.js'), os.path.join('static', 'bootstrap-fileinput', 'themes', 'fas', '*.js'), os.path.join('static', 'bootstrap-combobox', 'css', '*.css'), os.path.join('static', 'bootstrap-combobox', 'js', '*.js'), os.path.join('static', 'bootstrap-fileinput', '*.md'), os.path.join('static', 'bootstrap', 'js', '*.*'), os.path.join('static', 'bootstrap', 'css', '*.*'), os.path.join('static', 'labelauty', 'source', '*.*'), os.path.join('static', 'codemirror', 'lib', '*.*'), os.path.join('static', 'codemirror', 'addon', 'search', '*.*'), os.path.join('static', 'codemirror', 'addon', 'display', '*.*'), os.path.join('static', 'codemirror', 'addon', 'scroll', '*.*'), os.path.join('static', 'codemirror', 'addon', 'dialog', '*.*'), os.path.join('static', 'codemirror', 'addon', 'edit', '*.*'), os.path.join('static', 'codemirror', 'addon', 'hint', '*.*'), os.path.join('static', 'codemirror', 'mode', 'yaml', '*.*'), os.path.join('static', 'codemirror', 'mode', 'markdown', '*.*'), os.path.join('static', 'codemirror', 'mode', 'javascript', '*.*'), os.path.join('static', 'codemirror', 'mode', 'css', '*.*'), os.path.join('static', 'codemirror', 'mode', 'python', '*.*'), os.path.join('static', 'codemirror', 'mode', 'htmlmixed', '*.*'), os.path.join('static', 'codemirror', 'mode', 'xml', '*.*'), os.path.join('static', 'codemirror', 'keymap', '*.*'), os.path.join('static', 'areyousure', '*.js'), os.path.join('static', 'popper', '*.*'), os.path.join('static', 'popper', 'umd', '*.*'), os.path.join('static', 'popper', 'esm', '*.*'), os.path.join('static', '*.html')]},
     )
