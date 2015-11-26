from flask import Flask, request, session, send_from_directory, render_template
from flask import Blueprint
import api
import bson

from api.common import WebSuccess, WebError
from api.annotations import api_wrapper, require_login, require_teacher, require_admin
from api.annotations import log_action

from api.common import check, validate, safe_fail
from voluptuous import Required, Length, Schema, Range

blueprint = Blueprint("admin_api", __name__)

@blueprint.route('/problems', methods=['GET'])
@api_wrapper
@require_admin
def get_problem_data_hook():
    has_instances = lambda p: len(p["instances"]) > 0
    problems = list(filter(has_instances, api.problem.get_all_problems(show_disabled=True)))

    for problem in problems:
        problem["reviews"] = api.problem_feedback.get_problem_feedback(pid=problem["pid"])

    data = {
        "problems": problems,
        "bundles": api.problem.get_all_bundles()
    }

    return WebSuccess(data=data)

@blueprint.route('/users', methods=['GET'])
@api_wrapper
@require_admin
def get_all_users_hook():
    users = api.user.get_all_users()
    return WebSuccess(data=users)

exceptions_scheme = Schema({
    Required("limit"): check(
            ("Exception limit should be a positive integer.", [int, Range(min=1)]),
    )})

@blueprint.route('/exceptions', methods=['GET'])
@api_wrapper
@require_admin
def get_exceptions_hook():

    validate(exceptions_scheme, dict(request.form))

    exceptions = api.admin.get_api_exceptions(result_limit=request.form["limit"])
    return WebSuccess(data=exceptions)

dismiss_exception_scheme = Schema({
    Required("trace"): check(
            ("You have to specify a trace to dismiss.", [str]),
    )})

@blueprint.route('/exceptions/dismiss', methods=['POST'])
@api_wrapper
@require_admin
def dismiss_exceptions_hook():

    validate(dismiss_exception_scheme, request.form)

    trace = request.form["trace"]
    api.admin.dismiss_api_exceptions(trace)

    return WebSuccess(data="Successfuly changed exception visibility.")

@blueprint.route("/problems/submissions", methods=["GET"])
@api_wrapper
@require_admin
def get_problem():
    submission_data = {p["name"]:api.stats.get_problem_submission_stats(pid=p["pid"]) \
                       for p in api.problem.get_all_problems(show_disabled=True)}
    return WebSuccess(data=submission_data)

problem_availability_schema = Schema({
    Required("pid"): check(("You must specify a pid to change availability.", [str])),
    Required("state"): check(("Problems are available (true) or (false).", [str, lambda x: x in ["true", "false"]]))
})

@blueprint.route("/problems/availability", methods=["POST"])
@api_wrapper
@require_admin
def change_problem_availability_hook():

    validate(problem_availability_schema, dict(request.form))
    state = bson.json_util.loads(request.form["state"])

    api.admin.set_problem_availability(request.form["pid"], state)
    return WebSuccess(data="Problem state changed successfully.")

@blueprint.route("/shell_servers", methods=["GET"])
@api_wrapper
@require_admin
def get_shell_servers():
    return WebSuccess(data=api.shell_servers.get_servers())

@blueprint.route("/shell_servers/add", methods=["POST"])
@api_wrapper
@require_admin
def add_shell_server():

    params = api.common.flat_multi(request.form)
    validate(api.shell_servers.server_schema, params)

    api.shell_servers.add_server(params)
    return WebSuccess("Shell server added.")

@blueprint.route("/shell_servers/update", methods=["POST"])
@api_wrapper
@require_admin
def update_shell_server():

    params = api.common.flat_multi(request.form)
    validate(api.shell_servers.server_schema, params)

    api.shell_servers.update_server(params["sid"], params)
    return WebSuccess("Shell server updated.")

sid_schema = Schema({
    Required("sid"): check(("You must specify a sid to remove a shell server.", [str])),
})

@blueprint.route("/shell_servers/remove", methods=["POST"])
@api_wrapper
@require_admin
def remove_shell_server():
    validate(sid_schema, dict(request.form))

    api.shell_servers.remove_server(request.form["sid"])
    return WebSuccess("Shell server removed.")

@blueprint.route("/shell_servers/load_problems", methods=["POST"])
@api_wrapper
@require_admin
def load_problems_from_shell_server():
    validate(sid_schema, dict(request.form))

    number = api.shell_servers.load_problems_from_server(request.form["sid"])
    return WebSuccess("Loaded {} problems from the server".format(number))

@blueprint.route("/shell_servers/check_status", methods=["GET"])
@api_wrapper
@require_admin
def check_status_of_shell_server():

    validate(sid_schema, dict(request.args))

    all_online, data = api.shell_servers.get_problem_status_from_server(request.args["sid"])

    if all_online:
        return WebSuccess("All problems are online", data=data)
    else:
        return WebError("One or more problems are offline. Please connect and fix the errors.", data=data)

bundle_availability_schema = Schema({
    Required("bid"): check(("You must specify a bid to change availability.", [str])),
    Required("state"): check(("The state is (true) or (false).", [str, lambda x: x in ["true", "false"]]))
})

@blueprint.route("/bundle/dependencies_active", methods=["POST"])
@api_wrapper
@require_admin
def bundle_dependencies():
    validate(bundle_availability_schema, dict(request.form))

    state = bson.json_util.loads(request.form["state"])
    api.problem.set_bundle_dependencies_enabled(request.form["bid"], state)

    return WebSuccess("Dependencies are now {}.".format("enabled" if state else "disabled"))

@blueprint.route("/settings", methods=["GET"])
@api_wrapper
@require_admin
def get_settings():
    return WebSuccess(data=api.config.get_settings())

admin_settings_schema = Schema({
    Required("json"): check(("You have to provide the updated settings as a json string.", [str])),
})

@blueprint.route("/settings/change", methods=["POST"])
@api_wrapper
@require_admin
def change_settings():
    validate(admin_settings_schema, dict(request.form))

    data = bson.json_util.loads(request.form["json"])
    api.config.change_settings(data)

    return WebSuccess("Settings updated")
