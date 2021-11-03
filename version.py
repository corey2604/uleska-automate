import json
import sys

from controller.version_controller import VersionController


def create_version(
        host : str,
        application : str,
        version_name : str,
        print_json : bool,
        sast_git : str,
        sast_username : str,
        sast_token : str,
        tools_to_add : list,
) -> str:
    """Create a new version
    Parameters:
        host (str): Address of the uleksa instance
        application (str): The id of the application to attach the new version to
        version_name (str): The name of the version to create
        print_json (bool): If true puts the JSON output to standard output
        sast_git (str): Git address of the source code
        sast_username (str): Git username of the source code
        sast_token (str): Git token or password of the source code
        tools_to_add (list): Tools to run when scanning this version 

    Returns:
        str: The id of the version just made in UUID format
    """
    payload = __build_payload_json(version_name, sast_git, tools_to_add, sast_username, sast_token)
    return __create_version(host, application, payload, print_json, version_name)


def get_version(host : str, application : str, version : str) -> dict:
    """Finds a version
    Parameters:
        host (str): Address of the uleksa instance
        application (str): The id of the application
        version (str): The id of the version

    Returns:
        dict: The Version in a dictionary 
    """
    response = VersionController.get_version(host, application, version)

    try:
        version_info = json.loads(response.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when adding new version.  Exception: [" + str(jex) + "]")
        sys.exit(2)

    return version_info


def update_version(
        host : str, application : str, version : str, version_data : dict, tools_to_add : list
) -> None:
    """Updates a version
    Parameters:
        host (str): Address of the uleksa instance
        application (str): The id of the application
        version (str): The id of the version
        version_data (dict): Data that will be updated
        tools_to_add (list): Tools to run when scanning this version
    """
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
