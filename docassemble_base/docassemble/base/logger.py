import sys
import inspect

the_logger = None

def default_logmessage(message):
    try:
        sys.stderr.write(message + "\n")
    except:
        sys.stderr.write("default_logmessage: unable to print message\n")

the_logmessage = default_logmessage

def set_logmessage(func):
    global the_logmessage
    the_logmessage = func

def set_logger(func):
    global the_logger
    the_logger = func

def logmessage(message):
    if the_logger is not None:
        curframe = inspect.currentframe()
        calframe = inspect.getouterframes(curframe, 2)
        return the_logger.warning(message, extra={
            'caller_name': calframe[1][3],
            'caller_file': calframe[1][1]
        })
    else:
        return the_logmessage(message)
