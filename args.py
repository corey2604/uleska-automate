import argparse


def get_args():
    arg_options = argparse.ArgumentParser(
        description="Uleska command line interface. To identify the project/pipeline to test you can specify either --application_name and --version_name, or --application and --version (passing GUIDs). (Version 0.2)",
    )
    arg_options.add_argument(
        "--uleska_host",
        help="URL to the Uleska host (e.g. https://s1.uleska.com/) (note final / is required)",
        required=True,
        type=str,
    )
    arg_options.add_argument(
        "--token", help="String for the authentication token", required=True, type=str
    )

    arg_options.add_argument(
        "--application_id", help="GUID for the application to reference", type=str
    )
    arg_options.add_argument(
        "--version_id",
        help="GUID for the application version/pipeline to reference",
        type=str,
    )
    arg_options.add_argument(
        "--application_name", help="Name for the application to reference", type=str, default=None
    )
    arg_options.add_argument(
        "--version_name", help="Name for the version/pipeline to reference", type=str, default=None
    )

    arg_options.add_argument(
        "--update_sast",
        help="Add or update a SAST pipeline.  Requires an pre-existing application. See documentation for other settings",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--sast_git",
        help="Git URL for SAST repo.  Required with --update_sast.",
        type=str,
        default=None
    )
    arg_options.add_argument(
        "--sast_username",
        help="If repo requires authentication, this is the username to use.  Optional with --update_sast.",
        type=str,
        default=None
    )
    arg_options.add_argument(
        "--sast_token",
        help="If repo requires authentication, this is the token value to use.  Optional with --update_sast.",
        type=str,
        default=None
    )

    arg_options.add_argument(
        "--tools",
        help="List of tool names to use for this version.  Optional with --update_sast.  Comma separated",
        type=str,
        default=None
    )

    arg_options.add_argument(
        "--update_container",
        help="Update a container pipeline.  Requires an pre-existing application/config. See documentation for other settings",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--container_image",
        help="Name of image to use. Required with --update_container.",
        type=str,
        default=None
    )
    arg_options.add_argument(
        "--container_tag",
        help="Tag to use. Required with --update_container.",
        type=str,
        default=None
    )
    arg_options.add_argument(
        "--container_connection",
        help="Connection name to use for container access. Optional with --update_container.  If not included Docker Hub is assumed.",
        type=str,
        default=None
    )

    arg_options.add_argument(
        "--test",
        help="Run tests only for the application and version referenced, do not wait for the results",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--test_and_results",
        help="Run tests for the application and version referenced, and return the results from the last as JSON",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--test_and_compare",
        help="Run tests for the application and version referenced, and return any differences in the results from the last test",
        action="store_true",
        default=False
    )

    arg_options.add_argument(
        "--latest_results",
        help="Retrieve the latest test results for application and version referenced",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--compare_latest_results",
        help="Retrieve the latest test results for version and compare",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--print_json",
        help="Print the relevant output as JSON to stdout",
        action="store_true",
        default=False
    )
    arg_options.add_argument(
        "--get_ids",
        help="Retrieve GUID for the application_name and version_name supplied",
        action="store_true",
    )
    arg_options.add_argument(
        "--app_stats",
        help="Retrieve the latest risk and vulnerabiltiy for the whole application",
        action="store_true",
    )

    arg_options.add_argument(
        "--fail_if_issue_risk_over",
        help="Causes the CLI to return a failure if any new issue risk is over the integer specified",
        type=str,
        default=0
    )
    arg_options.add_argument(
        "--fail_if_risk_over",
        help="Causes the CLI to return a failure if the risk is over the integer specified",
        type=str,
        default=0
    )
    arg_options.add_argument(
        "--fail_if_risk_change_over",
        help="Causes the CLI to return a failure if the percentage change of increased risk is over the integer specified. Requires 'test_and_compare' or 'compare_latest_results' functions",
        type=str,
        default=0
    )
    arg_options.add_argument(
        "--fail_if_issues_over",
        help="Causes the CLI to return a failure if the number of issues is over the integer specified",
        type=str,
    )
    arg_options.add_argument(
        "--fail_if_issues_change_over",
        help="Causes the CLI to return a failure if the percentage change in new issues is over the integer specified.  Requires 'test_and_compare' or 'compare_latest_results' function",
        type=str,
        default=0
    )
    arg_options.add_argument(
        "--fail_if_CVSS_over",
        help="Causes the CLI to return a failure if the any new issue has a CVSS over the integer specified.  Requires 'test_and_compare' or 'compare_latest_results' function",
        type=str,
        default=0
    )

    arg_options.add_argument(
        "--debug", help="Prints debug messages", action="store_true", default=False
    )

    return arg_options.parse_args()