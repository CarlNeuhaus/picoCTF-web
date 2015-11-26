from flask import Flask, request, session, send_from_directory, render_template
from flask import Blueprint, redirect, abort
import api
import json
import mimetypes
import os.path

import string, re

from api.common import check, validate, safe_fail
from api.common import WebException, InternalException
from api.annotations import log_action
from voluptuous import Required, Length, Schema

from datetime import datetime
from api.common import WebSuccess, WebError, safe_fail
from api.annotations import api_wrapper, require_login, require_teacher, require_admin, check_csrf
from api.annotations import block_before_competition, block_after_competition

blueprint = Blueprint("user_api", __name__)

user_schema = Schema({
    Required('email'): check(
        ("Email must be between 5 and 50 characters.", [str, Length(min=5, max=50)]),
        ("Your email does not look like an email address.", [lambda email: re.match(r".+@.+\..{2,}", email) is not None]),
    ),
    Required('firstname'): check(
        ("First Name must be between 1 and 50 characters.", [str, Length(min=1, max=50)])
    ),
    Required('lastname'): check(
        ("Last Name must be between 1 and 50 characters.", [str, Length(min=1, max=50)])
    ),
    Required('country'): check(
        ("Please select a country.", [str, Length(min=2, max=2)])
    ),
    Required('username'): check(
        ("Usernames must be between 3 and 20 characters.", [str, Length(min=3, max=20)]),
        ("Usernames must be alphanumeric.", [lambda u: all([c in string.digits + string.ascii_lowercase for c in u.lower()])]),
        ("This username already exists.", [
            lambda name: safe_fail(api.user.get_user, name=name) is None]),
        ("This username conflicts with an existing team.", [
            lambda name: safe_fail(api.team.get_team, name=name) is None])
    ),
    Required('password'):
        check(("Passwords must be between 3 and 20 characters.", [str, Length(min=3, max=20)])
    ),
    Required('affiliation'):
        check(("You must specify an affiliation.", [str, Length(min=3, max=50)])
    ),
    Required('eligibility'):
        check(("You must specify whether or not your account is eligibile.", [str,
            lambda status: status in ["eligible", "ineligible"]])
    ),
}, extra=True)

new_team_schema = Schema({
    Required('team-name-new'): check(
        ("The team name must be between 3 and 40 characters.", [str, Length(min=3, max=40)]),
        ("A team with that name already exists.", [
            lambda name: safe_fail(api.team.get_team, name=name) is None])
    ),
    Required('team-password-new'):
        check(("Team passphrase must be between 3 and 20 characters.", [str, Length(min=3, max=20)])),

}, extra=True)

existing_team_schema = Schema({
    Required('team-name-existing'): check(
        ("Existing team names must be between 3 and 50 characters.", [str, Length(min=3, max=50)]),
        ("There is no existing team named that.", [
            lambda name: api.team.get_team(name=name) != None]),
        ("There are too many members on that team for you to join.", [
            lambda name: len(api.team.get_team_uids(name=name, show_disabled=False)) < api.config.get_settings()["max_team_size"]
        ])
    ),
    Required('team-password-existing'):
        check(("Team passwords must be between 3 and 50 characters.", [str, Length(min=3, max=50)]))
}, extra=True)

@blueprint.route("/authorize/<role>")
def authorize_role(role=None):
    """
    This route is used to ensure sensitive static content is witheld from withheld from clients.
    """

    if role == "user" and safe_fail(api.user.get_user):
        return "Client is logged in.", 200
    elif role == "teacher" and safe_fail(api.user.is_teacher):
        return "Client is a teacher.", 200
    elif role == "admin" and safe_fail(api.user.is_admin):
        return "Client is an administrator.", 200
    elif role == "anonymous":
        return "Client is authorized.", 200
    else:
        return "Client is not authorized.", 401

@blueprint.route('/create_simple', methods=['POST'])
@api_wrapper
def create_simple_user_hook():
    """
    Registers a new user and creates a team for them automatically. Validates all fields.
    Assume arguments to be specified in a dict.

    Args:
        username: user's username
        password: user's password
        firstname: user's first name
        lastname: user's first name
        email: user's email
        eligibile: "eligibile" or "ineligibile"
        affiliation: user's affiliation
        gid: group registration
        rid: registration id
    """

    settings = api.config.get_settings()
    params = api.common.flat_multi(request.form)

    #Will need to fix for pico
    params["country"] = "US"
    validate(user_schema, params)

    whitelist = None

    if params.get("gid", None):
        group = api.group.get_group(gid=params["gid"])
        group_settings = api.group.get_group_settings(gid=group["gid"])

        #Force affiliation
        params["affiliation"] = group["name"]

        whitelist = group_settings["email_filter"]

    user_is_teacher = False
    user_was_invited = False

    if params.get("rid", None):
        key = api.token.find_key_by_token("registration_token", params["rid"])

        if params.get("gid") != key["gid"]:
            raise WebException("Registration token group and supplied gid do not match.")

        if params["email"] != key["email"]:
            raise WebException("Registration token email does not match the supplied one.")

        user_is_teacher = key["teacher"]
        user_was_invited = True

        api.token.delete_token(key, "registration_token")
    else:
        if not api.user.verify_email_in_whitelist(params["email"], whitelist):
            raise WebException("Your email does not belong to the whitelist. Please see the registration form for details.")

    if api.config.get_settings()["captcha"]["enable_captcha"] and not api.user._validate_captcha(params):
        raise WebException("Incorrect captcha!")

    team_params = {
        "team_name": params["username"],
        "password": api.common.token(),
        "eligible": params["eligibility"] == "eligible",
        "affiliation": params["affiliation"]
    }

    tid = api.team.create_team(team_params)

    if tid is None:
        raise InternalException("Failed to create new team")

    team = api.team.get_team(tid=tid)

    # Create new user
    uid = api.user.create_user(
        params["username"],
        params["firstname"],
        params["lastname"],
        params["email"],
        api.user.hash_password(params["password"]),
        team["tid"],
        country=params["country"],
        teacher=user_is_teacher,
        verified=user_was_invited
    )

    if uid is None:
        raise InternalException("There was an error during registration.")

    # Join group after everything else has succeeded
    if params.get("gid", None):
        api.group.join_group(params["gid"], team["tid"], teacher=user_is_teacher)

    #Only automatically login if we don't have to verify
    if api.user.get_user(uid=uid)["verified"]:
        session['uid'] = uid

    return WebSuccess("User '{}' registered successfully!".format(request.form["username"]))


update_password_schema = Schema({
    Required('new-password'): check(("You need to specify a new password.", [str, Length(min=1)])),
    Required('new-password-confirmation'): check(("You need to specify a confirmation password.", [str, Length(min=1)])),
    Required('current-password'): check(("You must provide a valid token to reset your password.", [str, Length(min=1)]))
}, extra=True)

@blueprint.route('/update_password', methods=['POST'])
@api_wrapper
@check_csrf
@require_login
def update_password_hook():
    """
    Update account password.
    Assumes args are keys in params.

    Args:
        uid: uid to reset
        check_current: whether to ensure that current-password is correct
        params:
            current-password: the users current password
            new-password: the new password
            new-password-confirmation: confirmation of password
    """

    params = api.common.flat_multi(request.form)

    validate(update_password_schema, params)

    user = api.user.get_user()

    if not api.auth.confirm_password(params["current-password"], user['password_hash']):
        raise WebException("Your current password is incorrect.")

    if params["new-password"] != params["new-password-confirmation"]:
        raise WebException("Your passwords do not match.")

    if len(params["new-password"]) == 0:
        raise WebException("Your password cannot be empty.")

    api.user.update_password(user['uid'], params["new-password"])

    return WebSuccess("Your password has been successfully updated!")


disable_account_schema = Schema({
    Required('new-password'): check(("You need to specify a new password.", [str, Length(min=1)])),
    Required('new-password-confirmation'): check(("You did not specify a confirmation password.", [str, Length(min=1)])),
    Required('reset-token'): check(("You must provide a valid token to reset your password.", [str, Length(min=1)]))
}, extra=True)

@blueprint.route('/disable_account', methods=['POST'])
@api_wrapper
@check_csrf
@require_login
def disable_account_hook():
    """
    Disable user account so they can't login or consume space on a team.
    Assumes args are keys in params.

    Args:
        uid: uid to reset
        check_current: whether to ensure that current-password is correct
        params:
            current-password: the users current password
    """

    params = api.common.flat_multi(request.form)

    validate(disable_account_schema, params)

    user = api.user.get_user(uid=uid)

    if not api.auth.confirm_password(params["current-password"], user['password_hash']):
        raise WebException("Your current password is incorrect.")

    api.user.disable_account(user['uid'])
    api.auth.logout()

    return WebSuccess("Your have successfully disabled your account!")

reset_password_schema = Schema({
    Required('username'): check(
        ("You need to specify a username to reset its password.", [str, Length(min=1)]))}, extra=True)

@blueprint.route('/reset_password', methods=['POST'])
@api_wrapper
def reset_password_hook():

    validate(reset_password_schema, dict(request.form))

    username = request.form["username"]

    api.email.request_password_reset(username)
    return WebSuccess("A password reset link has been sent to the email address provided during registration.")

confirm_password_reset_schema = Schema({
    Required('new-password'): check(("You need to specify a new password.", [str, Length(min=1)])),
    Required('new-password-confirmation'): check(("You did not specify a confirmation password.", [str, Length(min=1)])),
    Required('reset-token'): check(("You must provide a valid token to reset your password.", [str, Length(min=1)]))
}, extra=True)

@blueprint.route('/confirm_password_reset', methods=['POST'])
@api_wrapper
def confirm_password_reset_hook():

    validate(confirm_password_reset_schema, dict(request.form))

    password = request.form["new-password"]
    confirm = request.form["new-password-confirmation"]
    token_value = request.form["reset-token"]

    api.email.reset_password(token_value, password, confirm)
    return WebSuccess("Your password has been reset")

@blueprint.route('/verify', methods=['GET'])
#@api_wrapper -- not using vouluptous as this isn't api_wrapped
def verify_user_hook():
    uid = request.args.get("uid", "")
    token = request.args.get("token", "")

    # Needs to be more telling of success
    if api.common.safe_fail(api.user.verify_user, uid, token):
        if api.config.get_settings()["max_team_size"] > 1:
            return redirect("/#team-builder")
        else:
            return redirect("/#status=verified")
    else:
        return redirect("/")

login_schema = Schema({
    Required('username'): check(("You need to specify a username to login.", [str, Length(min=1)])),
    Required('password'): check(("You need to speify a password to login.", [str, Length(min=1)]))
}, extra=True)

@blueprint.route('/login', methods=['POST'])
@api_wrapper
def login_hook():

    validate(login_schema, dict(request.form))
    username = request.form["username"]
    password = request.form["password"]

    api.auth.login(username, password)
    return WebSuccess(message="Successfully logged in as " + username,
                      data={'teacher': api.user.is_teacher(), 'admin': api.user.is_admin()})

@blueprint.route('/logout', methods=['GET'])
@api_wrapper
def logout_hook():
    if api.auth.is_logged_in():
        api.auth.logout()
        return WebSuccess("Successfully logged out.")
    else:
        return WebError("You do not appear to be logged in.")

@blueprint.route('/status', methods=['GET'])
@api_wrapper
def status_hook():
    settings = api.config.get_settings()
    status = {
        "logged_in": api.auth.is_logged_in(),
        "admin": api.auth.is_logged_in() and api.user.is_admin(),
        "teacher": api.auth.is_logged_in() and api.user.is_teacher(),
        "enable_teachers": settings["enable_teachers"],
        "enable_feedback": settings["enable_feedback"],
        "enable_captcha": settings["captcha"]["enable_captcha"],
        "reCAPTCHA_public_key": settings["captcha"]["reCAPTCHA_public_key"],
        "competition_active": api.utilities.check_competition_active(),
        "username": api.user.get_user()['username'] if api.auth.is_logged_in() else "",
        "tid": api.user.get_user()["tid"] if api.auth.is_logged_in() else "",
        "email_verification": settings["email"]["email_verification"]
    }

    if api.auth.is_logged_in():
        team = api.user.get_team()
        status["team_name"] = team["team_name"]
        status["score"] = api.stats.get_score(tid=team["tid"])

    return WebSuccess(data=status)

@blueprint.route('/shell_servers', methods=['GET'])
@api_wrapper
@require_login
def shell_servers_hook():
    servers = [{"host":server['host'], "protocol":server['protocol']} for server in api.shell_servers.get_servers()]
    return WebSuccess(data=servers)
