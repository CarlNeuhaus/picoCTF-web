from flask import Flask, request, session, send_from_directory, render_template
from flask import Blueprint
import api

from api.common import WebSuccess, WebError
from api.annotations import api_wrapper, require_login, require_teacher, require_admin, check_csrf
from api.annotations import block_before_competition, block_after_competition
from api.annotations import log_action

from api.common import check, validate, safe_fail
from voluptuous import Required, Length, Schema

blueprint = Blueprint("team_api", __name__)

@blueprint.route('', methods=['GET'])
@api_wrapper
@require_login
def team_information_hook():
    return WebSuccess(data=api.team.get_team_information())

@blueprint.route('/score', methods=['GET'])
@api_wrapper
@require_login
def get_team_score_hook():
    score = api.stats.get_score(tid=api.user.get_user()['tid'])
    if score is not None:
        return WebSuccess(data={'score': score})
    return WebError("There was an error retrieving your score.")

new_team_schema = Schema({
    Required("team_name"): check(
        ("The team name must be between 3 and 40 characters.", [str, Length(min=3, max=40)]),
        ("A team with that name already exists.", [
            lambda name: safe_fail(api.team.get_team, name=name) is None]),
        ("A username with that name already exists.", [
            lambda name: safe_fail(api.user.get_user, name=name) is None]),
    ),
    Required("team_password"): check(
        ("Passwords must be between 3 and 20 characters.", [str, Length(min=3, max=20)]))
}, extra=True)

@blueprint.route('/create', methods=['POST'])
@api_wrapper
@require_login
def create_new_team_hook():
    """
    Fulfills new team requests for users who have already registered.

    Args:
        team_name: The desired name for the team. Must be unique across users and teams.
        team_password: The team's password.
    Returns:
        True if successful, exception thrown elsewise. 
    """

    params = api.common.flat_multi(request.form)
    validate(new_team_schema, params)

    user = api.user.get_user(uid=uid)
    current_team = api.team.get_team(tid=user["tid"])

    if current_team["team_name"] != user["username"]:
        raise InternalException("You can only create one new team per user account!")

    desired_tid = create_team({
        "team_name": params["team_name"],
        "password": params["team_password"],
        # The team's affiliation becomes the creator's affiliation.
        "affiliation": current_team["affiliation"],
        "eligible": True
    })

    api.team.join_team(params["team_name"], params["team_password"], user["uid"])

    return WebSuccess("You now belong to your newly created team.")

join_team_schema = Schema({
    Required("team_name"): check(
        ("The team name must be between 3 and 40 characters.", [str, Length(min=3, max=40)]),
    ),
    Required("team_password"): check(
        ("Passwords must be between 3 and 20 characters.", [str, Length(min=3, max=20)]))
}, extra=True)

@blueprint.route('/join', methods=['POST'])
@api_wrapper
@require_login
def join_team_hook():

    params = api.common.flat_multi(request.form)
    validate(join_team_schema, params)

    api.team.join_team(params["team_name"], params["team_password"])

    return WebSuccess("You have successfully joined that team!")

@blueprint.route("/settings")
@api_wrapper
def get_team_status():
    settings = api.config.get_settings()

    filtered_settings = {
        "max_team_size": settings["max_team_size"],
        "email_filter": settings["email_filter"]
    }

    return WebSuccess(data=filtered_settings)
