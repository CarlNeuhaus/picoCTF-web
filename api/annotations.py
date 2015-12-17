""" API annotations and assorted wrappers. """

import json, traceback, bson
import api

from api.common import WebSuccess, WebError, WebException, InternalException, SevereInternalException
import datetime
from functools import wraps
from flask import session, request, abort
from pymongo import ReturnDocument

write_logs_to_db = False # Default value, can be overwritten by api.py

log = api.logger.use(__name__)

_get_message = lambda exception: exception.args[0]

def log_action(f):
    """
    Logs a given request if available.
    """

    @wraps(f)
    def wrapper(*args, **kwds):
        """
        Provides contextual information to the logger.
        """

        log_information = {
            "name": "{}.{}".format(f.__module__, f.__name__),
            "args": args,
            "kwargs": kwds,
            "result": None,
        }

        try:
            log_information["result"] = f(*args, **kwds)
        except WebException as error:
            log_information["exception"] = _get_message(error)
            raise
        finally:
            log.info(log_information)

        return log_information["result"]

    return wrapper

def api_wrapper(f):
    """
    Wraps api routing and handles potential exceptions
    """

    @wraps(f)
    def wrapper(*args, **kwds):
        web_result = {}
        wrapper_log = api.logger.use(f.__module__)
        try:
            web_result = f(*args, **kwds)
        except WebException as error:
            web_result = WebError(_get_message(error), error.data)
        except InternalException as error:
            message = _get_message(error)
            if type(error) == SevereInternalException:
                wrapper_log.critical(traceback.format_exc())
                web_result = WebError("There was a critical internal error. Contact an administrator.")
            else:
                wrapper_log.error(traceback.format_exc())
                web_result = WebError(message)
        except Exception as error:
            wrapper_log.error(traceback.format_exc())
            web_result = WebError("An error occured. Please contact an administrator.")

        return bson.json_util.dumps(web_result)

    return wrapper

def require_login(f):
    """
    Wraps routing functions that require a user to be logged in
    """

    @wraps(f)
    def wrapper(*args, **kwds):
        if not api.auth.is_logged_in():
            raise WebException("You must be logged in")
        return f(*args, **kwds)
    return wrapper

def require_teacher(f):
    """
    Wraps routing functions that require a user to be a teacher
    """

    @require_login
    @wraps(f)
    def wrapper(*args, **kwds):
        if not api.user.is_teacher() or not api.config.get_settings()["enable_teachers"]:
            raise WebException("You must be a teacher!")
        return f(*args, **kwds)
    return wrapper

def check_csrf(f):
    @wraps(f)
    @require_login
    def wrapper(*args, **kwds):
        if 'token' not in session:
            raise InternalException("CSRF token not in session")
        if 'token' not in request.form:
            raise InternalException("CSRF token not in form")
        if session['token'] != request.form['token']:
            raise InternalException("CSRF token is not correct")
        return f(*args, **kwds)
    return wrapper

def deny_blacklisted(f):
    @wraps(f)
    @require_login
    def wrapper(*args, **kwds):
        #if auth.is_blacklisted(session['tid']):
         #   abort(403)
        return f(*args, **kwds)
    return wrapper

def require_admin(f):
    """
    Wraps routing functions that require a user to be an admin
    """

    @wraps(f)
    def wrapper(*args, **kwds):
        if not api.user.is_admin():
            raise WebException("You do not have permission to view this page.")
        return f(*args, **kwds)
    return wrapper

def block_before_competition(return_result):
    """
    Wraps a routing function that should be blocked before the start time of the competition
    """

    def decorator(f):
        """
        Inner decorator
        """

        @wraps(f)
        def wrapper(*args, **kwds):
            if datetime.datetime.utcnow().timestamp() > api.config.get_settings()["start_time"].timestamp():
                return f(*args, **kwds)
            else:
                return return_result
        return wrapper
    return decorator

def block_after_competition(return_result):
    """
    Wraps a routing function that should be blocked after the end time of the competition
    """

    def decorator(f):
        """
        Inner decorator
        """

        @wraps(f)
        def wrapper(*args, **kwds):
            if datetime.datetime.utcnow().timestamp() < api.config.get_settings()["end_time"].timestamp():
                return f(*args, **kwds)
            else:
                return return_result
        return wrapper
    return decorator

def rate_limit(requests=100, window=60):
    """
    Limits the number of requests by the current remote IP for a wrapped endpoint

    Default limit is 100 requests per minute.
    """

    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            db = api.common.get_conn()

            entry = {
                "ip": request.remote_addr,
                "endpoint": request.endpoint
            }

            expireTime = datetime.datetime.now() + datetime.timedelta(seconds=window)

            result = db.rate_limits.find_one_and_update(
                    filter = entry,
                    update = {
                        "$inc": {"count": 1},
                        "$setOnInsert": dict(entry, expireAt=expireTime)
                    },
                    projection = {"count" : 1, "expireAt" : 1},
                    upsert = True,
                    return_document = ReturnDocument.AFTER)

            if result["count"] > requests:
                # they will likely have to wait less than the full window, but oh well
                raise WebException("Too Many Requests. Wait {} seconds before sending another.".format(window))
            else:
                return f(*args, **kwargs)
        return wrapped
    return decorator
