import json
import sys

from stripe.http_client import requests

from application import get_app_id_from_name
from controller.application_controller import ApplicationController
from controller.container_image_controller import ContainerImageController


def update_container_image(application_name, version_name, container_image, container_tag, host, token, print_json, container_connection):
    # when update_container is called, the container config will be updated

    # check we have application_name and version_name (required)
    if application_name == "" or version_name == "":
        print(
            "Error, for --update_container both --application_name and --version_name are required."
        )
        sys.exit(2)

    # check we have container_image and container_tag (required)
    if container_image == "" or container_tag == "":
        print(
            "Error, for --update_container both --container_image and --container_tag are required."
        )
        sys.exit(2)

    # map application_name to an id
    application = get_app_id_from_name(host, application_name, token, print_json)

    # attempt to get the version id for the passed version name. This will return either the ID if it exists, or "" if it doesn't
    version = run_check_for_existing_version(
        host, application_name, version_name, token, print_json
    )

    connection_id = ""

    # check if a connection was specified, if so, get the corresponding id
    if container_connection != "":
        connection_id = run_map_connection_name_to_id(
            host, container_connection, token, print_json
        )
    else:
        connection_id = "null"

    # update the container config
    run_update_container_config(
        host,
        application,
        version,
        container_image,
        container_tag,
        connection_id,
        token,
        print_json,
    )

def run_check_for_existing_version(
    host, application_name, version_name, print_json
):

    applications_response = ApplicationController.get_applications(host)

    try:
        application_and_versions_info = json.loads(applications_response.text)
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


def run_update_container_config(
    host,
    application,
    version,
    container_image,
    container_tag,
    connection_id,
    print_json,
):

    if connection_id == "null":
        payload = (
            '{"name":"'
            + container_image
            + '","tag":"'
            + container_tag
            + '","connectionId":'
            + connection_id
            + "}"
        )
    else:
        payload = (
            '{"name":"'
            + container_image
            + '","tag":"'
            + container_tag
            + '","connectionId":"'
            + connection_id
            + '"}'
        )

    payload_json = json.loads(payload)

    ContainerImageController.update_container_image(host, application, version, payload_json)

    if not print_json:
        print("Updated container configuration")


def run_map_connection_name_to_id(host, connection_name, token, print_json):

    s = requests.Session()

    s.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )

    GetConnectionsURL = host + "SecureDesigner/api/v1/connections/"

    try:
        StatusResponse = s.request("Get", GetConnectionsURL)
    except requests.exceptions.RequestException as err:
        print("Exception getting connections\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:
        # Something went wrong, maybe server not up, maybe auth wrong
        print(
            "Non 200 status code returned when getting connections.  Code ["
            + str(StatusResponse.status_code)
            + "]"
        )
        sys.exit(2)

    connections_info = {}

    try:
        connections_info = json.loads(StatusResponse.text)
    except json.JSONDecodeError as jex:
        print(
            "Invalid JSON when extracting connections.  Exception: [" + str(jex) + "]"
        )
        sys.exit(2)

    connection_id = ""

    for connection_config in connections_info:

        if "toolName" in connection_config:

            if connection_config["toolName"] == connection_name:
                # We have found the connection, record the GUID
                connection_id = connection_config["id"]
                if not print_json:
                    print(
                        "Connection ID found for ["
                        + connection_name
                        + "]: "
                        + connection_id
                    )

    # check ""
    if connection_id == "":
        # we didn't find one of the ids, so return a failure
        print(
            "Failed to find id for connection name ["
            + connection_name
            + "], id ["
            + connection_id
            + "]"
        )
        sys.exit(2)

    if not print_json:
        print(
            "Mapped connection name to id: connection name ["
            + connection_name
            + "], id ["
            + connection_id
            + "]"
        )

    return connection_id