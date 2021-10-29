import requests

from session import get_session


class ToolController:
    @staticmethod
    def get_tools(host: str):
        try:
            url = ToolsEndpoint.tools_url(host)
            session = get_session()
            response = session.get(url)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating version:\n" + str(err))
            raise err


class ToolsEndpoint:
    @staticmethod
    def tools_url(host):
        """Tools URL
        e.g. GET /SecureDesigner/api/v1/tools

        Methods:
            - GET to get
        """
        return host + "SecureDesigner/api/v1/tools"
