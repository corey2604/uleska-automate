import requests

from session import get_session


class ApplicationController:
    @staticmethod
    def get_applications(host):
        url = ApplicationEndpoint.applications_url(host)
        session = get_session()
        try:
            response = session.get(url)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception getting applications:\n" + str(err))
            raise err


class ApplicationEndpoint:
    """Applications URL
    e.g. GET /applications

    Methods:
        - POST to create
        - GET to get all applications
    """

    @staticmethod
    def applications_url(host):
        return host + "/SecureDesigner/api/v1/applications"

    """Application URL
    e.g. GET /applications/[APP_ID]

    Methods:
        - PUT to update
        - GET to get
        - DELETE to delete
    """

    @staticmethod
    def application_url(host, application_id):
        return host + "/SecureDesigner/api/v1/applications" + str(application_id)
