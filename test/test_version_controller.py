import unittest

import requests
from mockito import unstub, when, mock

from controller.version_controller import VersionController


class TestVersionController(unittest.TestCase):
    def tearDown(self):
        unstub()

    def test_create_version(self):
        # given
        host = "https://unittest.uleska.com"
        application_id = "c69b3759-2003-45b5-b4a3-55e549a405d2"
        versions_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions"
        mock_response = mock()
        container_image = {}
        when(requests.sessions.Session).post(host + versions_path, json=container_image).thenReturn(mock_response)
        when(mock_response).raise_for_status().thenReturn(200)

        # when
        result = VersionController.create_version(host, application_id, container_image)

        # then
        self.assertEqual(mock_response, result)

    def test_create_version_handles_non_successful_response(self):
        # given
        host = "https://unittest.uleska.com"
        application_id = "c69b3759-2003-45b5-b4a3-55e549a405d2"
        versions_path = "/SecureDesigner/api/v1/applications/" + application_id + "/versions"
        container_image = {}
        when(requests.sessions.Session).post(host + versions_path, json=container_image).thenRaise(
            requests.exceptions.HTTPError
        )

        # when
        self.assertRaises(
            requests.exceptions.HTTPError,
            lambda: VersionController.create_version(host, application_id, container_image)
        )