from stripe.http_client import requests

from controller.version_controller import VersionEndpoint
from session import get_session


class ContainerImageController:
    @staticmethod
    def create_container_image(host: str, application_id: str, version_id: str, container_image):
        try:
            url = ContainerImageEndpoint.container_image_url(
                host, application_id, version_id
            )
            session = get_session()
            response = session.post(url, json=container_image)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating container image:\n" + str(err))
            raise err


    @staticmethod
    def update_container_image(host: str, application_id: str, version_id: str, container_image):
        try:
            url = ContainerImageEndpoint.container_image_url(
                host, application_id, version_id
            )
            session = get_session()
            response = session.put(url, json=container_image)
            response.raise_for_status()
            return response
        except requests.exceptions.HTTPError as err:
            print("Exception creating container image:\n" + str(err))
            raise err


class ContainerImageEndpoint:
    @staticmethod
    def container_image_url(host: str, application_id: str, version_id: str):
        """Container Image URL
        e.g. POST /applications/[APP_ID]/versions/[VERSION_ID]/container-image

        Methods:
            - POST to create a container image
            - PUT to update a container image
            - GET to return the container image for this version
        """
        return (
                VersionEndpoint.version_url(host, application_id, version_id)
                + "/container-image"
        )
