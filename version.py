import json
import sys

from controller.version_controller import VersionController


def create_version(
        host,
        application,
        version_name,
        print_json,
        sast_git,
        sast_username,
        sast_token,
        tools_to_add,
):
    payload = __build_payload_json(version_name, sast_git, tools_to_add, sast_username, sast_token)
    return __create_version(host, application, payload, print_json, version_name)


def get_version(host, application, version):
    response = VersionController.get_version(host, application, version)

    try:
        version_info = json.loads(response.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    return version_info


def update_version(
        host, application, version, version_data, tools_to_add
):
    payload_json = version_data
    payload_json["tools"] = tools_to_add
    VersionController.update_version(host, application, version, payload_json)


def __build_payload_json(version_name: str, sast_git: str, tools_to_add, sast_username: str = None, sast_token: str = None):
    payload = (
            '{"name":"'
            + version_name
            + '","forceCookies":false,"roles":[],"webPageList":[],"tools":[],"reports":[],"actions":[],"scmConfiguration":{"useUpload":false,"authenticationType":"USER_PASS","address":"'
            + sast_git
            + '"}}'
    )
    if (sast_username is not None):
        payload += '","identity":"' + sast_username + '","secret":"' + sast_token
    payload += '"}}'
    payload_json = json.loads(payload)
    payload_json["tools"] = tools_to_add
    return payload_json


def __create_version(host, application, payload, print_json, version_name):
    response = VersionController.create_version(host, application, payload)

    try:
        new_version_info = json.loads(response.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    version_id = ""

    if "id" in new_version_info:
        version_id = new_version_info["id"]

        if not print_json:
            print(
                "New version created: name ["
                + version_name
                + "], id ["
                + version_id
                + "]"
            )

    else:
        print("Error, no version id returned when creating new version")
        exit(2)

    return version_id
