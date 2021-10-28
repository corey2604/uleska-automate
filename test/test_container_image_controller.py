import unittest

import requests
from mockito import unstub, when, mock, verify, ANY, patch

from controller.container_image_controller import ContainerImageController


class TestApplicationController(unittest.TestCase):
    def tearDown(self):
        unstub()

    def test_create_container_image(self):
        # given
        host = "https://test.uleska.com"
        application_id = "2fdf6f61-4cf1-4cfa-94ad-98d4605ed9f2"
        version_id = "2c40d179-ad77-429a-bdf2-3c747ee319be"
        versions_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions/" + version_id + "/container-image"
        mock_response = mock()
        container_image = {}
        when(requests.sessions.Session).post(host + versions_path, json=container_image).thenReturn(mock_response)
        when(mock_response).raise_for_status().thenReturn(200)

        # when
        result = ContainerImageController.create_container_image(host, application_id, version_id, container_image)

        # then
        self.assertEqual(mock_response, result)

    def test_create_container_image_handles_non_successful_response(self):
        # given
        host = "https://test.uleska.com"
        application_id = "2fdf6f61-4cf1-4cfa-94ad-98d4605ed9f2"
        version_id = "2c40d179-ad77-429a-bdf2-3c747ee319be"
        container_image = {}
        container_image_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions/" + version_id + "/container-image"
        when(requests.sessions.Session).post(host + container_image_path, json=container_image).thenRaise(
            requests.exceptions.HTTPError
        )

        # when - then
        self.assertRaises(
            requests.exceptions.HTTPError,
            lambda: ContainerImageController.create_container_image(host, application_id, version_id, container_image)
        )

    def test_update_container_image(self):
        # given
        host = "https://test.uleska.com"
        application_id = "2fdf6f61-4cf1-4cfa-94ad-98d4605ed9f2"
        version_id = "2c40d179-ad77-429a-bdf2-3c747ee319be"
        versions_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions/" + version_id + "/container-image"
        mock_response = mock()
        container_image = {}
        when(requests.sessions.Session).put(host + versions_path, json=container_image).thenReturn(mock_response)
        when(mock_response).raise_for_status().thenReturn(200)

        # when
        result = ContainerImageController.update_container_image(host, application_id, version_id, container_image)

        # then
        self.assertEqual(mock_response, result)

    def test_update_container_image_handles_non_successful_response(self):
        # given
        host = "https://test.uleska.com"
        application_id = "2fdf6f61-4cf1-4cfa-94ad-98d4605ed9f2"
        version_id = "2c40d179-ad77-429a-bdf2-3c747ee319be"
        container_image = {}
        container_image_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions/" + version_id + "/container-image"
        when(requests.sessions.Session).put(host + container_image_path, json=container_image).thenRaise(
            requests.exceptions.HTTPError
        )

        # when - then
        self.assertRaises(
            requests.exceptions.HTTPError,
            lambda: ContainerImageController.update_container_image(host, application_id, version_id, container_image)
        )