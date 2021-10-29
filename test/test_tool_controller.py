import unittest

import requests
from mockito import unstub, when, mock

from controller.tool_controller import ToolController


class TestToolController(unittest.TestCase):
    def tearDown(self):
        unstub()

    def test_get_tools(self):
        # given
        host = "https://unittest.uleska.com"
        tools_path = "SecureDesigner/api/v1/tools"
        mock_response = mock()
        when(requests.sessions.Session).get(host + tools_path).thenReturn(mock_response)
        when(mock_response).raise_for_status().thenReturn(200)

        # when
        result = ToolController.get_tools(host)

        # then
        self.assertEqual(mock_response, result)

    def test_create_version_handles_non_successful_response(self):
        # given
        host = "https://unittest.uleska.com"
        tools_path = "SecureDesigner/api/v1/tools"
        when(requests.sessions.Session).get(host + tools_path).thenRaise(
            requests.exceptions.HTTPError
        )

        # when
        self.assertRaises(
            requests.exceptions.HTTPError,
            lambda: ToolController.get_tools(host)
        )