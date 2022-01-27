import requests

from api import uleska_api
from api.uleska_api import UleskaApi


def scan_with_toolkit(host: str, token: str, application_id: str, version_id: str, toolkit_id: str) -> requests.Response:
    api: UleskaApi = uleska_api.get_api(host, token)
    url: str = 'SecureDesigner/api/v1/applications/{}/versions/{}/scan/{}'.format(application_id, version_id, toolkit_id)
    return api.get(url)


def get_scans(host: str, token: str) -> requests.Response:
    api: UleskaApi = uleska_api.get_api(host, token)
    url: str = 'SecureDesigner/api/v1/scans'
    return api.get(url)