import requests
import json
import time
import sys

from application import get_app_id_from_name
from args import get_args
from container import update_container_image
from session import make_session
from tools import get_tools_body
from version import create_version, get_version, update_version

APPLICATION_PATH = "SecureDesigner/api/v1/applications/"

class issue_info:
    title = ""
    tool = ""
    total_cost = 0
    CVSS = ""
    CVSS_value = 0.0
    affectedURL = ""
    summary = ""
    severity = ""
    explanation = ""
    recommendation = ""


class ids:
    application_id = ""
    version_id = ""


class failure_thresholds:
    fail_if_issue_risk_over = 0
    fail_if_risk_over = 0
    fail_if_risk_change_over = 0
    fail_if_issues_over = 0
    fail_if_issues_change_over = 0
    fail_if_CVSS_over = 0


class version_info:
    name = ""
    id = ""


def _main():
    # Capture command line arguments
    args = get_args()

    application = ""  # id
    version = ""  # id

    thresholds = failure_thresholds()

    # Grab the host from the command line arguments
    host = args.uleska_host
    make_session(host)

    # Set debug
    if args.debug:
        debug = True
        print("Debug enabled")


    # Grab the token from the command line arguments
    token = args.token
    if debug:
        print("Token: " + token)


    # Grab the application id from the command line arguments
    if args.application_id is not None:
        application = args.application_id

        if debug:
            print("Application id: " + application)

    # Grab the version from the command line arguments
    if args.version_id is not None:
        version = args.version_id

        if debug:
            print("Version id: " + version)

    # Set test_and_compare
    if args.test_and_compare:
        test_and_compare = True

        if debug:
            print("test_and_compare enabled")

    # Set test_and_results
    if args.test_and_results:
        test_and_results = True

        if debug:
            print("test_and_results enabled")

    # Set test
    if args.test:
        test = True

        if debug:
            print("test enabled")

    # Set latest_results
    if args.latest_results:
        latest_results = True

        if debug:
            print("latest_results enabled")

    # Set compare_latest_results
    if args.compare_latest_results:
        compare_latest_results = True

        if debug:
            print("compare_latest_results enabled")

    # Set print_json flag
    if args.print_json:
        print_json = True

    # Set get_ids
    if args.get_ids:
        get_ids = True

        if debug:
            print("get_ids enabled")

    # Set compare_app_results
    if args.app_stats:
        app_stats = True

        if debug:
            print("app_stats enabled")

    # Grab the application_name from the command line arguments
    if args.application_name is not None:
        application_name = args.application_name

        if debug:
            print("Application name: " + application_name)

    # Grab the version_name from the command line arguments
    if args.version_name is not None:
        version_name = args.version_name

        if debug:
            print("Version name: " + version_name)

    # Grab SAST Pipeline from the command line arguments
    if args.update_sast:
        update_sast = True

        if debug:
            print("update_sast is set")

    # Grab the SAST Git from the command line arguments
    if args.sast_git is not None:
        sast_git = args.sast_git

        if debug:
            print("sast_git: " + sast_git)

    # Grab the SAST username from the command line arguments
    if args.sast_username is not None:
        sast_username = args.sast_username

        if debug:
            print("sast_username: " + sast_username)

    # Grab the SAST token from the command line arguments
    if args.sast_token is not None:
        sast_token = args.sast_token

        if debug:
            print("sast_token: " + sast_token)

    # Grab the tools string from the command line arguments (comma separated at this stage)
    if args.tools is not None:
        tools = args.tools

        if debug:
            print("tools: " + tools)

    # Grab container Pipeline from the command line arguments
    if args.update_container:
        update_container = True

        if debug:
            print("update_container is set")

    # Grab the container image from the command line arguments
    if args.container_image is not None:
        container_image = args.container_image

        if debug:
            print("container_image: " + container_image)

    # Grab the container tag from the command line arguments
    if args.container_tag is not None:
        container_tag = args.container_tag

        if debug:
            print("container_tag: " + container_tag)

    # Grab the container connection from the command line arguments
    if args.container_connection is not None:
        container_connection = args.container_connection

        if debug:
            print("container_connection: " + container_connection)

    # Grab the fail_if_issue_risk_over from the command line arguments
    if args.fail_if_issue_risk_over is not None:
        thresholds.fail_if_issue_risk_over = int(args.fail_if_issue_risk_over)

        if debug:
            print("fail_if_issue_risk_over: " + str(thresholds.fail_if_issue_risk_over))

    # Grab the fail_if_risk_over from the command line arguments
    if args.fail_if_risk_over is not None:
        thresholds.fail_if_risk_over = int(args.fail_if_risk_over)

        if debug:
            print("fail_if_risk_over: " + str(thresholds.fail_if_risk_over))

    # Grab the fail_if_risk_change_over from the command line arguments
    if args.fail_if_risk_change_over is not None:
        thresholds.fail_if_risk_change_over = int(args.fail_if_risk_change_over)

        if debug:
            print(
                "fail_if_risk_change_over: " + str(thresholds.fail_if_risk_change_over)
            )

    # Grab the fail_if_issues_over from the command line arguments
    if args.fail_if_issues_over is not None:
        thresholds.fail_if_issues_over = int(args.fail_if_issues_over)

        if debug:
            print("fail_if_issues_over: " + str(thresholds.fail_if_issues_over))

    # Grab the fail_if_issues_change_over from the command line arguments
    if args.fail_if_issues_change_over is not None:
        thresholds.fail_if_issues_change_over = int(args.fail_if_issues_change_over)

        if debug:
            print(
                "fail_if_issues_change_over: "
                + str(thresholds.fail_if_issues_change_over)
            )

    # Grab the fail_if_CVSS_over from the command line arguments
    if args.fail_if_CVSS_over is not None:
        thresholds.fail_if_CVSS_over = float(args.fail_if_CVSS_over)

        if debug:
            print("fail_if_CVSS_over: " + str(thresholds.fail_if_CVSS_over))

    if app_stats and application_name is not None:
        # user is requesting app results (therefore won't pass an individual version)
        pass

    if update_sast:
        # when update_sast is called, the version_name will be checked, updated, or added

        # check we have application_name and version_name (required)
        if application_name is None or version_name is None:
            print(
                "Error, for --update_sast both --application_name and --version_name are required."
            )
            sys.exit(2)

        # map application_name to an id
        application = get_app_id_from_name(host, application_name, print_json)

        # attempt to get the version id for the passed version name. This will return either the ID if it exists, or "" if it doesn't
        version = run_check_for_existing_version(
            host, application_name, version_name, token, print_json
        )

        tools_to_add = get_tools_body(host, tools)

        # check if version_name exists for the app
        if version == "":

            # this version_name doesn't exist, create it depending on authentication needed
            if sast_git is not None:
                # if creating a new version, we need the git URL, return an error
                print(
                    "Error, when passing --update_sast for a new version, --sast_git URL is required"
                )
                sys.exit(2)

            if args.sast_username is not None and args.sast_token is None:
                    print(
                        "Error, when passing --sast_username to setup authentication, --sast_token is required"
                    )
                    sys.exit(2)

            # "user has passed both sast_username and sast_token
            version = create_version(
                host,
                application,
                version_name,
                print_json,
                sast_git,
                sast_username,
                sast_token,
                tools_to_add,
            )
        else:
            # version does exist, so get the current info (as JSON), and update it
            version_data = get_version(
                host, application, version
            )

            # if sast_git was supplied, update this
            if sast_git is not None:
                # "updating sast_git

                version_data["scmConfiguration"]["address"] = sast_git

            # if username was passed, update it
            if sast_username is not None:
                # updating username
                version_data["scmConfiguration"]["identity"] = sast_username
                version_data["scmConfiguration"]["authenticationType"] = "USER_PASS"

            # if sast_token was passed, update it
            # TODO - we don't check if this is passed with sast_username - should we require this?  Should someone update username but not token?
            if sast_token != "":
                # updating sast_token
                version_data["scmConfiguration"]["secret"] = sast_token

            # update the version
            update_version(
                host,
                application,
                version,
                version_data,
                tools_to_add,
            )

    elif update_container:
        # when update_container is called, the container config will be updated
        update_container_image(application_name, version_name,  container_image, container_tag, host, token, print_json, container_connection)

    elif not app_stats and (application_name is not None or version_name is not None):
        if not print_json:
            print("Application or version name passed, looking up ids...")

        results = map_app_name_and_version_to_ids(
            host, application_name, version_name, token, print_json
        )

        application = results.application_id
        version = results.version_id

    # Args retrieved, now decide what we're doing
    if get_ids:
        # No action as map_app_name_and_version_to_ids will have already returned the ids
        pass
    elif app_stats:
        run_app_stats(host, application_name, token, print_json, thresholds)
    elif test_and_compare:
        run_test_and_compare(host, application, version, token, print_json, thresholds)
    elif test_and_results:
        run_test_and_results(host, application, version, token, print_json, thresholds)
    elif test:
        run_scan(host, application, version, token, print_json)
    elif latest_results:
        run_latest_results(host, application, version, token, print_json, thresholds)
    elif compare_latest_results:
        run_compare_latest_results(
            host, application, version, token, print_json, thresholds
        )
    else:
        print("No recognised function specified.")
        sys.exit(2)


def run_test_and_results(host, application, version, token, print_json, thresholds):

    # First run a new scan in blocking mode (so we can check the results afterwards)
    run_scan_blocking(host, application, version, token, print_json)

    reports = get_reports_list(host, application, version, token, print_json)

    report_info = get_report_info(
        host, application, version, token, reports, -1, print_json
    )

    results = print_report_info(report_info, "Latest", print_json)

    max_cvss_found = 0.0
    max_issue_risk_found = 0

    output = {}
    results_to_print = []
    overall_risk = 0

    for i in results:

        json_issue = {}
        json_issue["title"] = i.title
        json_issue["tool"] = i.tool
        json_issue["risk"] = i.total_cost
        json_issue["cvss"] = i.CVSS
        json_issue["summary"] = i.summary
        json_issue["severity"] = i.severity
        json_issue["explanation"] = i.explanation
        json_issue["recommendation"] = i.recommendation

        if i.CVSS_value > max_cvss_found:
            max_cvss_found = i.CVSS_value

        if i.total_cost > max_issue_risk_found:
            max_issue_risk_found = i.total_cost

        overall_risk += i.total_cost

        results_to_print.append(json_issue)

    output["overall_risk"] = overall_risk
    output["num_issues"] = len(results)
    output["issues"] = results_to_print

    if print_json:
        print(json.dumps(output, indent=4, sort_keys=True))

    if (
        thresholds.fail_if_issue_risk_over > 0
        and max_issue_risk_found > thresholds.fail_if_issue_risk_over
    ):
        print(
            "Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is "
            + str(max_issue_risk_found)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_risk_over > 0
        and output["overall_risk"] > thresholds.fail_if_risk_over
    ):
        print(
            "Returning failure as fail_if_risk_over threshold has been exceeded [risk is "
            + str(output["overall_risk"])
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_issues_over > 0
        and output["num_issues"] > thresholds.fail_if_issues_over
    ):
        print(
            "Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is "
            + str(output["num_issues"])
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_CVSS_over > 0
        and max_cvss_found > thresholds.fail_if_CVSS_over
    ):
        print(
            "Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is "
            + str(max_cvss_found)
            + "]."
        )
        sys.exit(1)


def run_latest_results(host, application, version, token, print_json, thresholds):

    reports = get_reports_list(host, application, version, token, print_json)

    report_info = get_report_info(
        host, application, version, token, reports, -1, print_json
    )

    results = print_report_info(report_info, "Latest", print_json)

    max_cvss_found = 0.0
    max_issue_risk_found = 0

    output = {}
    results_to_print = []
    overall_risk = 0

    for i in results:

        json_issue = {}
        json_issue["title"] = i.title
        json_issue["tool"] = i.tool
        json_issue["risk"] = i.total_cost
        json_issue["cvss"] = i.CVSS
        json_issue["summary"] = i.summary
        json_issue["severity"] = i.severity
        json_issue["explanation"] = i.explanation
        json_issue["recommendation"] = i.recommendation

        if i.CVSS_value > max_cvss_found:
            max_cvss_found = i.CVSS_value

        if i.total_cost > max_issue_risk_found:
            max_issue_risk_found = i.total_cost

        overall_risk += i.total_cost

        results_to_print.append(json_issue)

    output["overall_risk"] = overall_risk
    output["num_issues"] = len(results)
    output["issues"] = results_to_print

    if print_json:
        print(json.dumps(output, indent=4, sort_keys=True))

    if (
        thresholds.fail_if_issue_risk_over > 0
        and max_issue_risk_found > thresholds.fail_if_issue_risk_over
    ):
        print(
            "Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is "
            + str(max_issue_risk_found)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_risk_over > 0
        and output["overall_risk"] > thresholds.fail_if_risk_over
    ):
        print(
            "Returning failure as fail_if_risk_over threshold has been exceeded [risk is "
            + str(output["overall_risk"])
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_issues_over > 0
        and output["num_issues"] > thresholds.fail_if_issues_over
    ):
        print(
            "Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is "
            + str(output["num_issues"])
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_CVSS_over > 0
        and max_cvss_found > thresholds.fail_if_CVSS_over
    ):
        print(
            "Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is "
            + str(max_cvss_found)
            + "]."
        )
        sys.exit(1)


def run_app_stats(host, application_name, token, print_json, thresholds):

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    GetApplicationsURL = host + APPLICATION_PATH

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting applications and versions.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    applications_info = {}

    try:
        applications_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting applications and versions.  Exception: ["
            + str(jex)
            + "]"
        )
        sys.exit(2)

    version_infos = []
    application_id = ""

    for application in applications_info:

        if "name" in application:

            if application["name"] == application_name:

                application_id = application["id"]

                # Now that we're in the right record for the application, for each version, retrieve the lists of reports
                if "versions" in application:

                    for version in application["versions"]:

                        this_version_info = version_info()

                        if "name" in version:

                            this_version_info.name = version["name"]
                            this_version_info.id = version["id"]

                            version_infos.append(this_version_info)

    num_vulns = 0
    aggregate_risk = 0

    # iterate through versions
    for version in version_infos:

        reports = get_reports_list(host, application_id, version.id, token, print_json)

        latest_report_info = get_report_info(
            host, application_id, version.id, token, reports, -1, print_json
        )

        latest_report_issues = print_report_info(latest_report_info, "Latest", True)

        for latest_iss in latest_report_issues:
            aggregate_risk = aggregate_risk + latest_iss.total_cost

            # latest_report_titles.append(latest_iss.title)

            num_vulns += 1

    if print_json:
        output = {}
        output["total_vulnerabilities"] = num_vulns
        output["aggregate_risk"] = aggregate_risk

        print(json.dumps(output, indent=4, sort_keys=True))
    else:
        print("total num_vuls [" + str(num_vulns) + "]")
        print("total aggregate_risk [" + str(aggregate_risk) + "]")

    # run thresholds
    if (
        thresholds.fail_if_risk_over > 0
        and aggregate_risk > thresholds.fail_if_risk_over
    ):
        print(
            "Returning failure as fail_if_risk_over threshold has been exceeded [application aggregate risk is "
            + str(aggregate_risk)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_issues_over > 0
        and num_vulns > thresholds.fail_if_issues_over
    ):
        print(
            "Returning failure as fail_if_issues_over threshold has been exceeded [application number of issues is "
            + str(num_vulns)
            + "]."
        )
        sys.exit(1)


def run_compare_latest_results(
    host, application, version, token, print_json, thresholds
):

    reports = get_reports_list(host, application, version, token, print_json)

    if len(reports) < 2:
        print(
            "Error, compare_latest_results called with less than 2 reports.  Unable to compare."
        )
        sys.exit(2)

    latest_report_info = get_report_info(
        host, application, version, token, reports, -1, print_json
    )

    penultumate_report_info = get_report_info(
        host, application, version, token, reports, -2, print_json
    )

    compare_report_infos(
        latest_report_info, penultumate_report_info, print_json, thresholds
    )


def run_test_and_compare(host, application, version, token, print_json, thresholds):

    # First run a new scan in blocking mode (so we can check the results afterwards
    run_scan_blocking(host, application, version, token, print_json)

    reports = get_reports_list(host, application, version, token, print_json)

    latest_report_info = get_report_info(
        host, application, version, token, reports, -1, print_json
    )

    penultumate_report_info = get_report_info(
        host, application, version, token, reports, -2, print_json
    )

    compare_report_infos(
        latest_report_info, penultumate_report_info, print_json, thresholds
    )


# Runs a scan and waits until it's completed.
def run_scan_blocking(host, application, version, token, print_json):

    if not print_json:
        print("Running blocking scan")

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    # Build API URL
    # Kick off a scan
    ScanURL = (
        host
        + APPLICATION_PATH
        + application
        + "/versions/"
        + version
        + "/scan"
    )

    # Run scan
    if not print_json:
        print("Kicking off the scan")

    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print("Exception running scan\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:

        # If you kick off a scan for a version when one is already running, it'll return 400 with a body saying "Scan already running"
        if (
            StatusResponse.status_code == 400
            and StatusResponse.text == "Scan already running"
        ):
            if not print_json:
                print(
                    "Got a 'Scan already running' response, will wait for that scan to finish"
                )
        else:
            # Something went wrong, maybe server not up, maybe auth wrong
            print(
                "Non 200 status code returned when running scan.  Code ["
                + str(StatusResponse.status_code)
                + "]"
            )
            sys.exit(2)

    if not print_json:
        print("Scan running")

    #### Scan should be running, run check scans to see if it's still running
    scanfinished = False

    CheckScanURL = host + "SecureDesigner/api/v1/scans"

    while scanfinished is False:

        try:
            StatusResponse = s.request("Get", CheckScanURL)
        except requests.exceptions.RequestException as err:
            print("Exception checking for running scan\n" + str(err))
            sys.exit(2)

        if StatusResponse.status_code != 200:
            # Something went wrong, maybe server not up, maybe auth wrong
            print(
                "Non 200 status code returned when checking for running scan.  Code ["
                + str(StatusResponse.status_code)
                + "]"
            )
            sys.exit(2)

        #### we have a response, check to see if this scan is still running.  Note there could be multiple scans running
        running_scans_json = {}

        try:
            running_scans_json = json.loads(StatusResponse.text)
        except json.JSONDecodeError as jex:
            print(
                "Invalid JSON when checking for running scans.  Exception: ["
                + str(jex)
                + "]"
            )
            sys.exit(2)

        if len(running_scans_json) == 0:
            #### if there's no scans running, then it must have finished
            if not print_json:
                print("No more scans running\n")
            scanfinished = True
            break

        versions_running = []

        for scan in running_scans_json:
            if "versionId" in scan:

                versions_running.append(scan["versionId"])

            else:
                print("No versionId in the scan\n")

        if version in versions_running:
            if not print_json:
                print("Our Toolkit " + version + " is still running, waiting...\n")
            time.sleep(10)
        else:
            if not print_json:
                print("Our Toolkit " + version + " has completed\n")
            scanfinished = True
            break


# Runs a scan and moves on with it's life.
def run_scan(host, application, version, token, print_json):

    if not print_json:
        print("Running non-blocking scan")

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    ##### Kick off a scan
    ScanURL = (
        host
        + APPLICATION_PATH
        + application
        + "/versions/"
        + version
        + "/scan"
    )

    # Run scan
    if not print_json:
        print("Kicking off the scan")

    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print("Exception running scan\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:

        # If you kick off a scan for a version when one is already running, it'll return 400 with a body saying "Scan already running"
        if (
            StatusResponse.status_code == 400
            and StatusResponse.text == "Scan already running"
        ):
            if not print_json:
                print("Got a 'Scan already running' response, nothing to do here")
        else:
            # Something went wrong, maybe server not up, maybe auth wrong
            print(
                "Non 200 status code returned when running scan.  Code ["
                + str(StatusResponse.status_code)
                + "]"
            )
            sys.exit(2)

    if not print_json:
        print("Scan running, this is non-blocking mode so now exiting.")


def get_reports_list(host, application, version, token, print_json):

    if not print_json:
        print("Getting list of reports for this pipeline")

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    #### Get the latest report Id for the app & version

    GetVersionReportsURL = (
        host
        + APPLICATION_PATH
        + application
        + "/versions/"
        + version
    )

    try:
        StatusResponse = s.request("Get", GetVersionReportsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting version reports\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting version reports.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    version_info = {}

    try:
        version_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when checking for version reports.  Exception: ["
            + str(jex)
            + "]"
        )
        sys.exit(2)

    reports_dict = []

    class report_obj:
        id = ""
        vulncount = 0
        tools = ""

    if "reports" in version_info:
        for report in version_info["reports"]:

            this_report = report_obj()

            if "id" in report:
                this_report.id = report["id"]

            if "vulnerabilityCount" in report:
                this_report.vulncount = report["vulnerabilityCount"]

            reports_dict.append(this_report)

    return reports_dict


def get_report_info(host, application, version, token, reports_dict, index, print_json):

    if not print_json:
        print("Getting information on this report")

    # Just wait a few seconds for the background thread to update the report (encase the scan has *just* finished)
    time.sleep(10)

    # Get the report id for the scan
    try:
        latest_report_handle = reports_dict[index]  #
    except IndexError:
        print(
            "Error obtaining handle to report.  Are you examining a latest report without any reports existing?  Or are you attempting to compare reports have have less than two reports?"
        )
        exit(2)

    report_info = {}

    report_info = get_reports_dict(
        host, application, version, token, latest_report_handle
    )

    # Return dict which is the latest report
    return report_info


def get_latest_report_info(host, application, version, token, reports_dict, print_json):

    if not print_json:
        print("Getting information on this report")

    if len(reports_dict) < 1:
        print("Error: no reports found.")
        sys.exit(2)

    # Get the report id for the scan
    latest_report_handle = reports_dict[-1]  # get the latest report

    report_info = {}

    report_info = get_reports_dict(
        host, application, version, token, latest_report_handle
    )

    # Return dict which is the latest report
    return report_info


def print_report_info(report_info, descriptor, print_json):

    if not print_json:
        print(
            "\n=== Listing issues in " + descriptor + " report ======================="
        )

    report_issues = []

    # Print some info about the latest scan
    for reported_issue in report_info:

        this_issue = issue_info()

        if "falsePositive" in reported_issue:
            if reported_issue["falsePositive"] is True:
                # print ("False positive being ignored\n")
                continue

        if "title" in reported_issue:
            this_issue.title = reported_issue["title"]

        if "affectedURL" in reported_issue:
            this_issue.affectedURL = reported_issue["affectedURL"]

        if "summary" in reported_issue:
            this_issue.summary = reported_issue["summary"]

        if "tool" in reported_issue:
            this_issue.tool = reported_issue["tool"]["title"]

        if "totalCost" in reported_issue:
            this_issue.total_cost = reported_issue["totalCost"]

        if "vulnerabilitySeverity" in reported_issue:
            this_issue.severity = reported_issue["vulnerabilitySeverity"]

        if "explanation" in reported_issue:
            this_issue.explanation = reported_issue["explanation"]

        if "recommendation" in reported_issue:
            this_issue.recommendation = reported_issue["recommendation"]

        if "vulnerabilityDefinition" in reported_issue:
            try:
                this_issue.CVSS = (
                    reported_issue["vulnerabilityDefinition"]["standards"][0][
                        "description"
                    ]
                    + " : "
                    + reported_issue["vulnerabilityDefinition"]["standards"][0]["title"]
                )
                this_issue.CVSS_value = float(
                    reported_issue["vulnerabilityDefinition"]["standards"][0][
                        "description"
                    ]
                )
            except IndexError:
                this_issue.CVSS_value = 0.0
                this_issue.CVSS = "CVSS not set"

        report_issues.append(this_issue)

    total_risk = 0

    for iss in report_issues:
        if not print_json:
            print("\nIssue [" + iss.title + "] from tool [" + iss.tool + "]")
            print("Resource affected [" + iss.affectedURL + "]")
            print("Summary [" + iss.summary + "]")
            print("CVSS [" + iss.CVSS + "]")
            print("Cost [$" + str(f"{iss.total_cost:,}") + "]\n")
        total_risk = total_risk + iss.total_cost

    if not print_json:
        print("\n" + descriptor + " security toolkit run:")
        print("    Total risk:                   = $" + str(f"{total_risk:,}"))
        print("    Total issues:                 = " + str(len(report_issues)))
        print("\n==============================================\n")

    return report_issues


def get_reports_dict(host, application, version, token, report):

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    GetLatestReportsURL = (
        host
        + APPLICATION_PATH
        + application
        + "/versions/"
        + version
        + "/reports/"
        + report.id
        + "/vulnerabilities"
    )

    try:
        StatusResponse = s.request("Get", GetLatestReportsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting latest reports\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting latest report.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    latest_report_info = {}

    try:
        latest_report_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting latest report.  Exception: [" + str(jex) + "]"
        )
        sys.exit(2)

    return latest_report_info


def compare_report_infos(
    latest_report_info, penultumate_report_info, print_json, thresholds
):

    if not print_json:
        print("Comparing the latest scan report with the previous one")

    latest_report_issues = print_report_info(
        latest_report_info, "Latest", print_json
    )  # Pass false for 'json' as we want to print compare json, not each report
    previous_report_issues = print_report_info(
        penultumate_report_info, "Previous", print_json
    )

    latest_risk = 0
    previous_risk = 0

    latest_report_titles = []
    penultumate_report_titles = []

    for latest_iss in latest_report_issues:
        latest_risk = latest_risk + latest_iss.total_cost
        latest_report_titles.append(latest_iss.title)

    for prev_iss in previous_report_issues:
        previous_risk = previous_risk + prev_iss.total_cost
        penultumate_report_titles.append(prev_iss.title)

    results = {}

    if previous_risk == latest_risk:
        if not print_json:
            print("\nNo change in risk levels since last check\n")
        results["risk_increase"] = 0
        results["risk_decrease"] = 0
        results["risk_increase_percentage"] = 0
        results["risk_decrease_percentage"] = 0
    elif previous_risk > latest_risk:
        reduced = previous_risk - latest_risk
        if not print_json:
            print("\n    Risk level has REDUCED by       $" + str(f"{reduced:,}"))

        # About to calculate risk % changes, but be careful encase 'latest_risk' is 0
        if latest_risk == 0:
            reduced_percentage = 100
        else:
            reduced_percentage = 100 - (100 / previous_risk) * latest_risk

        if not print_json:
            print(
                "    Risk level has REDUCED by       "
                + str(reduced_percentage)[0:4]
                + "%\n"
            )

        results["risk_increase"] = 0
        results["risk_decrease"] = reduced
        results["risk_increase_percentage"] = 0
        results["risk_decrease_percentage"] = reduced_percentage
    else:
        increased = latest_risk - previous_risk
        if not print_json:
            print("\n    Risk level has INCREASED by    $" + str(f"{increased:,}"))

        # About to calculate risk % changes, but be careful encase 'previous_risk' was 0 and we get an exception
        try:
            increased_percentage = ((100 / previous_risk) * latest_risk) - 100
        except ZeroDivisionError:
            increased_percentage = latest_risk * 100

        if not print_json:
            print(
                "    Risk level has INCREASED by     "
                + str(increased_percentage)[0:4]
                + "%\n"
            )

        results["risk_increase"] = increased
        results["risk_decrease"] = 0
        results["risk_increase_percentage"] = increased_percentage
        results["risk_decrease_percentage"] = 0

    if len(latest_report_issues) == len(previous_report_issues):
        if not print_json:
            print("No change in number of issues since last check\n")
        results["num_increase"] = 0
        results["num_decrease"] = 0
        results["num_increase_percentage"] = 0
        results["num_decrease_percentage"] = 0
    elif len(latest_report_issues) < len(previous_report_issues):
        if not print_json:
            print(
                "    Number of issues has REDUCED by   "
                + str((len(previous_report_issues) - len(latest_report_issues)))
            )
        reduced_issue_percentage = 100 - (100 / len(previous_report_issues)) * len(
            latest_report_issues
        )
        if not print_json:
            print(
                "    Number of issues has REDUCED by   "
                + str(reduced_issue_percentage)[0:4]
                + "%\n"
            )

        results["num_increase"] = 0
        results["num_decrease"] = len(previous_report_issues) - len(
            latest_report_issues
        )
        results["num_increase_percentage"] = 0
        results["num_decrease_percentage"] = reduced_issue_percentage
    else:
        if not print_json:
            print(
                "    Number of issues has INCREASED by   "
                + str((len(latest_report_issues) - len(previous_report_issues)))
            )
        increased_issue_percentage = (
            (100 / len(previous_report_issues)) * len(latest_report_issues)
        ) - 100
        if not print_json:
            print(
                "    Number of issues has INCREASED by   "
                + str(increased_issue_percentage)[0:4]
                + "%\n"
            )

        results["num_increase"] = len(latest_report_issues) - len(
            previous_report_issues
        )
        results["num_decrease"] = 0
        results["num_increase_percentage"] = increased_issue_percentage
        results["num_decrease_percentage"] = 0

    new_issues = []
    json_issues_dict = []

    ### penultumate_report_titles is set, so is latest_report_titles, so compare them
    new_risk = 0
    max_cvss_found = 0.0
    max_issue_risk_found = 0

    for latest_title in latest_report_titles:

        if latest_title in penultumate_report_titles:
            # This issue was there before, not new
            # Note this comparison needs to be improved, as it's likely to have duplicate titles - need to add codeline/reference
            continue
        else:
            # It's a new issue
            if not print_json:
                print("\nNEW ISSUE in this toolkit run:")

            json_issue = {}

            for i in latest_report_issues:
                if i.title == latest_title:
                    if not print_json:
                        print(
                            "        "
                            + i.title
                            + ": tool ["
                            + i.tool
                            + "]:     Risk $"
                            + str(f"{i.total_cost:,}")
                            + ""
                        )
                        print("        CVSS : " + i.CVSS)
                    new_risk = new_risk + i.total_cost

                    json_issue["title"] = i.title
                    json_issue["tool"] = i.tool
                    json_issue["risk"] = i.total_cost
                    json_issue["cvss"] = i.CVSS
                    json_issue["summary"] = i.summary
                    json_issue["severity"] = i.severity
                    json_issue["explanation"] = i.explanation
                    json_issue["recommendation"] = i.recommendation

                    if i.CVSS_value > max_cvss_found:
                        max_cvss_found = i.CVSS_value

                    if i.total_cost > max_issue_risk_found:
                        max_issue_risk_found = i.total_cost

            new_issues.append(i)
            json_issues_dict.append(json_issue)

    if new_risk != 0:
        if not print_json:
            print("\n    New risk in this tookit run    = $" + str(f"{new_risk:,}"))

    for pen_title in penultumate_report_titles:

        if pen_title in latest_report_titles:
            # This issue is in both, don't mention
            continue
        else:
            if not print_json:
                print("\nISSUE FIXED before this toolkit run:")

                for i in previous_report_issues:
                    if i.title == pen_title:
                        print(
                            "        "
                            + i.title
                            + ": tool ["
                            + i.tool
                            + "]:     Risk $"
                            + str(f"{i.total_cost:,}")
                            + ""
                        )
                        print("        CVSS : " + i.CVSS)

    results["new_issues"] = json_issues_dict

    if print_json:
        print(json.dumps(results, indent=4, sort_keys=True))

    if (
        thresholds.fail_if_issue_risk_over > 0
        and max_issue_risk_found > thresholds.fail_if_issue_risk_over
    ):
        print(
            "Returning failure as fail_if_issue_risk_over threshold has been exceeded [risk is "
            + str(max_issue_risk_found)
            + "]."
        )
        sys.exit(1)

    if thresholds.fail_if_risk_over > 0 and latest_risk > thresholds.fail_if_risk_over:
        print(
            "Returning failure as fail_if_risk_over threshold has been exceeded [risk is "
            + str(latest_risk)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_issues_over > 0
        and len(latest_report_issues) > thresholds.fail_if_issues_over
    ):
        print(
            "Returning failure as fail_if_issues_over threshold has been exceeded [number of issues is "
            + str(len(latest_report_issues))
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_CVSS_over > 0
        and max_cvss_found > thresholds.fail_if_CVSS_over
    ):
        print(
            "Returning failure as fail_if_CVSS_over threshold has been exceeded [max CVSS found is "
            + str(max_cvss_found)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_risk_change_over > 0
        and new_risk > thresholds.fail_if_risk_change_over
    ):
        print(
            "Returning failure as fail_if_risk_change_over threshold has been exceeded [new risk found is "
            + str(new_risk)
            + "]."
        )
        sys.exit(1)

    if (
        thresholds.fail_if_issues_change_over > 0
        and len(new_issues) > thresholds.fail_if_issues_change_over
    ):
        print(
            "Returning failure as fail_if_issues_change_over threshold has been exceeded [new issues found is "
            + str(len(new_issues))
            + "]."
        )
        sys.exit(1)


def map_app_name_and_version_to_ids(
    host, application_name, version_name, token, print_json
):

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting applications and versions.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    application_and_versions_info = {}

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting applications and versions.  Exception: ["
            + str(jex)
            + "]"
        )
        sys.exit(2)

    application_id = ""
    version_id = ""

    for application in application_and_versions_info:

        if "name" in application:

            if application["name"] == application_name:
                # We have found the application, record the GUID
                application_id = application["id"]
                if not print_json:
                    print(
                        "Application ID found for ["
                        + application_name
                        + "]: "
                        + application_id
                    )

                # Now that we're in the right record for the application, find the version name
                if "versions" in application:

                    for version in application["versions"]:
                        if "name" in version:

                            if version["name"] == version_name:
                                # We're in the right version, record the GUID
                                version_id = version["id"]
                                if not print_json:
                                    print(
                                        "Version ID found for ["
                                        + version_name
                                        + "]: "
                                        + version_id
                                    )

                                break

    # check ""
    if application_id == "" or version_id == "":
        # we didn't find one of the ids, so return a failure
        print(
            "Failed to find one or both ids: application name ["
            + application_name
            + "], id ["
            + application_id
            + "], version name ["
            + version_name
            + "] id ["
            + version_id
            + "]"
        )
        sys.exit(2)

    results = ids()
    results.application_id = application_id
    results.version_id = version_id

    if not print_json:
        print(
            "Mapped names to ids: application name ["
            + application_name
            + "], id ["
            + results.application_id
            + "], version name ["
            + version_name
            + "] id ["
            + results.version_id
            + "]"
        )

    return results


def run_check_for_existing_version(
    host, application_name, version_name, token, print_json
):

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    GetApplicationsURL = host + "SecureDesigner/api/v1/applications/"

    try:
        StatusResponse = s.request("Get", GetApplicationsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting applications and versions\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting applications and versions.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    application_and_versions_info = {}

    try:
        application_and_versions_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting applications and versions.  Exception: ["
            + str(jex)
            + "]"
        )
        sys.exit(2)

    version_id = ""

    for application in application_and_versions_info:

        if "name" in application:

            if application["name"] == application_name:
                # We have found the application

                if not print_json:
                    print("Application found for [" + application_name + "]")

                # Now that we're in the right record for the application, find the version name
                if "versions" in application:

                    for version in application["versions"]:
                        if "name" in version:

                            if version["name"] == version_name:
                                # We're in the right version, record the GUID
                                version_id = version["id"]
                                if not print_json:
                                    print(
                                        "Version ID found for ["
                                        + version_name
                                        + "]: "
                                        + version_id
                                    )

                                break

    if not print_json:
        print(
            "Mapped names to id: version name ["
            + version_name
            + "] id ["
            + version_id
            + "]"
        )

    return version_id


if __name__ == "__main__":
    _main()
