import json
import sys

from controller.application_controller import ApplicationController


def run_map_app_name_to_id(host, application_name, print_json):
    response = ApplicationController.get_applications(host)

    try:
        application_and_versions_info = json.loads(response.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting applications and versions.  Exception: ["
            + str(jex)
            + "]"
        )
        sys.exit(2)

    application_id = ""

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

    # check ""
    if application_id == "":
        # we didn't find one of the ids, so return a failure
        print(
            "Failed to find id for application name ["
            + application_name
            + "], id ["
            + application_id
            + "]"
        )
        sys.exit(2)

    if not print_json:
        print(
            "Mapped name to id: application name ["
            + application_name
            + "], id ["
            + application_id
            + "]"
        )

    return application_id
