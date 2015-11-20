"""
API functions relating to user management and registration.
"""

import bcrypt, re, urllib.parse, urllib.request, flask, json, string, re

import api

from api.common import check, validate, safe_fail
from api.common import WebException, InternalException
from api.annotations import log_action
from voluptuous import Required, Length, Schema

def verify_email_in_whitelist(email, whitelist=None):
    """
    Verify that the email address passes the global whitelist if one exists.

    Args:
        email: The email address to verify
    """

    if whitelist is None:
        settings = api.config.get_settings()
        whitelist = settings["email_filter"]

    #Nothing to check against!
    if len(whitelist) == 0:
        return True

    for email_domain in whitelist:
        if re.match(r".*?@{}$".format(email_domain), email) is not None:
            return True

    return False

def hash_password(password):
    """
    Hash plaintext password.

    Args:
        password: plaintext password
    Returns:
        Secure hash of password.
    """

    return bcrypt.hashpw(password, bcrypt.gensalt(8))

def get_team(uid=None):
    """
    Retrieve the the corresponding team to the user's uid.

    Args:
        uid: user's userid
    Returns:
        The user's team.
    """

    user = get_user(uid=uid)
    return api.team.get_team(tid=user["tid"])

def get_user(name=None, uid=None):
    """
    Retrieve a user based on a property. If the user is logged in,
    it will return that user object.

    Args:
        name: the user's username
        uid: the user's uid
    Returns:
        Returns the corresponding user object or None if it could not be found
    """

    db = api.common.get_conn()

    match = {}

    if uid is not None:
        match.update({'uid': uid})
    elif name is not None:
        match.update({'username': name})
    elif api.auth.is_logged_in():
        match.update({'uid': api.auth.get_uid()})
    else:
        raise InternalException("Uid or name must be specified for get_user")

    user = db.users.find_one(match)

    if user is None:
        raise InternalException("User does not exist")

    return user

def create_user(username, firstname, lastname, email, password_hash, tid,
                teacher=False, country="US", admin=False, verified=False):
    """
    This inserts a user directly into the database. It assumes all data is valid.

    Args:
        username: user's username
        firstname: user's first name
        lastname: user's last name
        email: user's email
        password_hash: a hash of the user's password
        tid: the team id to join
        teacher: whether this account is a teacher
    Returns:
        Returns the uid of the newly created user
    """

    db = api.common.get_conn()
    settings = api.config.get_settings()
    uid = api.common.token()

    if safe_fail(get_user, name=username) is not None:
        raise InternalException("User already exists!")

    max_team_size = api.config.get_settings()["max_team_size"]

    updated_team = db.teams.find_and_modify(
        query={"tid": tid, "size": {"$lt": max_team_size}},
        update={"$inc": {"size": 1}},
        new=True)

    if not updated_team:
        raise InternalException("There are too many users on this team!")

    #All teachers are admins.
    if admin or db.users.count() == 0:
        admin = True
        teacher = True

    user = {
        'uid': uid,
        'firstname': firstname,
        'lastname': lastname,
        'username': username,
        'email': email,
        'password_hash': password_hash,
        'tid': tid,
        'teacher': teacher,
        'admin': admin,
        'disabled': False,
        'country': country,
        'verified': not settings["email"]["email_verification"] or verified,
    }

    db.users.insert(user)

    if settings["email"]["email_verification"] and not user["verified"]:
        api.email.send_user_verification_email(username)

    return uid

def get_all_users(show_teachers=False):
    """
    Finds all the users in the database

    Args:
        show_teachers: whether or not to include teachers in the response
    Returns:
        Returns the uid, username, and email of all users.
    """

    db = api.common.get_conn()

    match = {}
    projection = {"uid": 1, "username": 1, "email": 1, "tid": 1}

    if not show_teachers:
        match.update({"teacher": False})
        projection.update({"teacher": 1})

    return list(db.users.find(match, projection))

def _validate_captcha(data):
    """
    Validates a captcha with google's reCAPTCHA.

    Args:
        data: the posted form data
    """

    settings = api.config.get_settings()["captcha"]

    post_data = urllib.parse.urlencode({
        "secret": api.config.reCAPTCHA_private_key,
        "response": data["g-recaptcha-response"],
        "remoteip": flask.request.remote_addr
    }).encode("utf-8")

    request = urllib.request.Request(api.config.captcha_url, post_data, method='POST')
    response = urllib.request.urlopen(request).read().decode("utf-8")
    parsed_response = json.loads(response)
    return parsed_response['success']

def is_teacher(uid=None):
    """
    Determines if a user is a teacher.

    Args:
        uid: user's uid
    Returns:
        True if the user is a teacher, False otherwise
    """

    user = get_user(uid=uid)
    return user.get('teacher', False)

def is_admin(uid=None):
    """
    Determines if a user is an admin.

    Args:
        uid: user's uid
    Returns:
        True if the user is an admin, False otherwise
    """

    user = get_user(uid=uid)
    return user.get('admin', False)


def verify_user(uid, token_value):
    """
    Verify an unverified user account. Link should have been sent to the user's email.

    Args:
        uid: the user id
        token_value: the verification token value
    Returns:
        True if successful verification based on the (uid, token_value)
    """

    db = api.common.get_conn()

    if uid is None:
        raise InternalException("You must specify a uid.")

    token_user = api.token.find_key_by_token("email_verification", token_value)

    if token_user["uid"] == uid:
        db.users.find_and_modify({"uid": uid}, {"$set": {"verified": True}})
        api.token.delete_token({"uid": uid}, "email_verification")
        return True
    else:
        raise InternalException("This is not a valid token for your user.")

def update_password(uid, password):
    """
    Updates an account's password.

    Args:
        uid: user's uid.
        password: the new user password.
    """

    db = api.common.get_conn()
    db.users.update({'uid': uid}, {'$set': {'password_hash': hash_password(password)}})

def disable_account(uid):
    """
    Disables a user account. They will no longer be able to login and do not count
    towards a team's maximum size limit.

    Args:
        uid: user's uid
    """

    db = api.common.get_conn()
    result = db.users.update(
        {"uid": uid, "disabled": False},
        {"$set": {"disabled": True}})

    tid = api.user.get_team(uid=uid)["tid"]

    # Making certain that we have actually made a change.
    # result["n"] refers to how many documents have been updated.
    if result["n"] == 1:
        db.teams.find_and_modify(
            query={"tid": tid, "size": {"$gt": 0}},
            update={"$inc": {"size": -1}},
            new=True)
