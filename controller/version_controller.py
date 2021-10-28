import requests

from controller.application_controller import ApplicationEndpoint
from session import get_session


class VersionController:
    @staticmethod
    def create_version(host: str, application_id: str, container_image):
        try:
            url = VersionEndpoint.versions_url(
                host, application_id
            )
            session = get_session()
            response = session.post(url, json=container_image)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating version:\n" + str(err))
            raise err

    @staticmethod
    def get_version(host: str, application_id: str, version_id: str):
        try:
            url = VersionEndpoint.version_url(
                host, application_id, version_id
            )
            session = get_session()
            response = session.get(url)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating version:\n" + str(err))
            raise err

    @staticmethod
    def update_version(host: str, application_id: str, version_id: str, payload_json):
        try:
            url = VersionEndpoint.version_url(
                host, application_id, version_id
            )
            session = get_session()
            response = session.put(url, payload_json)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating version:\n" + str(err))
            raise err


class VersionEndpoint:
    @staticmethod
    def versions_url(host, application_id):
        """Version URL
        e.g. GET /applications/[APP_ID]/versions/[VERSION_ID]

        Methods:
            - GET to get
            - POST to update
            - DELETE to delete
        """
        return (
                ApplicationEndpoint.applications_url(host)
                + "/"
                + str(application_id)
                + "/versions"
        )

    @staticmethod
    def version_url(host, application_id, version_id):
        """Version URL
        e.g. GET /applications/[APP_ID]/versions/[VERSION_ID]

        Methods:
            - GET to get
            - POST to update
            - DELETE to delete
        """
        return (
                ApplicationEndpoint.applications_url(host)
                + "/"
                + str(application_id)
                + "/versions/"
                + str(version_id)
        )
