import unittest

import requests
from mockito import unstub, when, mock

from controller.application_controller import ApplicationController


class TestApplicationController(unittest.TestCase):
    def tearDown(self):
        unstub()

    def test_get_applications(self):
        # given
        host = "https://test.uleska.com"
        applications_path = "/SecureDesigner/api/v1/applications"
        mock_response = mock()
        when(requests.sessions.Session).get(host + applications_path).thenReturn(mock_response)
        when(mock_response).raise_for_status().thenReturn(200)

        # when
        result = ApplicationController.get_applications(host)

        # then
        self.assertEqual(mock_response, result)

    def test_get_applications_handles_non_successful_response(self):
        # given
        host = "https://test.uleska.com"
        applications_path = "/SecureDesigner/api/v1/applications"
        when(requests.sessions.Session).get(host + applications_path).thenRaise(
            requests.exceptions.HTTPError
        )

        # when
        self.assertRaises(
            requests.exceptions.HTTPError,
            lambda: ApplicationController.get_applications(host)
        )