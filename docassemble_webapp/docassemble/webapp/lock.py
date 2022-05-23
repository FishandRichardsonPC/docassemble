import sys
import time

from docassemble.webapp.daredis import r


def obtain_lock(user_code, filename):
    key = 'da:lock:' + user_code + ':' + filename
    found = False
    count = 4
    while count > 0:
        record = r.get(key)
        if record:
            sys.stderr.write("obtain_lock: waiting for " + key + "\n")
            time.sleep(1.0)
        else:
            found = False
            break
        found = True
        count -= 1
    if found:
        sys.stderr.write("Request for " + key + " deadlocked\n")
        release_lock(user_code, filename)
    pipe = r.pipeline()
    pipe.set(key, 1)
    pipe.expire(key, 4)
    pipe.execute()


def obtain_lock_patiently(user_code, filename):
    key = 'da:lock:' + user_code + ':' + filename
    # sys.stderr.write("obtain_lock: getting " + key + "\n")
    found = False
    count = 20
    while count > 0:
        record = r.get(key)
        if record:
            sys.stderr.write("obtain_lock: waiting for " + key + "\n")
            time.sleep(3.0)
        else:
            found = False
            break
        found = True
        count -= 1
    if found:
        sys.stderr.write("Request for " + key + " deadlocked\n")
        release_lock(user_code, filename)
    pipe = r.pipeline()
    pipe.set(key, 1)
    pipe.expire(key, 4)
    pipe.execute()


def release_lock(user_code, filename):
    key = 'da:lock:' + user_code + ':' + filename
    # sys.stderr.write("obtain_lock: releasing " + key + "\n")
    r.delete(key)
