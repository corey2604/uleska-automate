from stripe.http_client import requests

from controller.version_controller import VersionEndpoint
from session import get_session


class ScanController:
    @staticmethod
    def start_scan(host: str, application_id: str, version_id: str):
        try:
            url = ScanEndpoint.scan_url(
                host, application_id, version_id
            )
            session = get_session()
            response = session.get(url)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating container image:\n" + str(err))
            raise err


class ScanEndpoint:
    @staticmethod
    def scan_url(host: str, application_id: str, version_id: str):
        """Container Image URL
        e.g. POST /applications/[APP_ID]/versions/[VERSION_ID]/scan

        Methods:
            - POST to create/start a scan
        """
        return (
                VersionEndpoint.version_url(host, application_id, version_id)
                + "/scan"
        )