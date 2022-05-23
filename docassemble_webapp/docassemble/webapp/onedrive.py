from docassemble.webapp.daredis import r, r_user, r_store
from flask_login import login_user, logout_user, current_user


def get_od_folder():
    key = 'da:onedrive:mapping:userid:' + str(current_user.id)
    folder = r.get(key)
    if folder is not None:
        return folder.decode()
    return folder
