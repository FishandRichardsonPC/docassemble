from docassemble.base.config import daconfig
from docassemble.webapp.app_object import app
import docassemble.base.functions
from docassemble.webapp.authentication import login_as_admin
from flask import current_app

class TestContext:
    def __init__(self, package):
        self.package = package

    def __enter__(self):
        url_root = daconfig.get('url root', 'http://localhost') + daconfig.get('root', '/')
        url = url_root + 'interview'
        self.app_context = app.app_context()
        self.app_context.push()
        self.test_context = app.test_request_context(base_url=url_root, path=url)
        self.test_context.push()
        login_as_admin(url, url_root)
        docassemble.base.functions.this_thread.current_package = self.package
        docassemble.base.functions.this_thread.current_info.update(dict(yaml_filename=self.package + ':data/questions/test.yml'))
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        current_app.login_manager._update_request_context_with_user()
        self.test_context.pop()
        self.app_context.pop()