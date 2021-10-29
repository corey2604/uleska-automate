import unittest

from application import get_app_id_from_name
from mockito import unstub, when, mock

from controller.application_controller import ApplicationController


class TestApplication(unittest.TestCase):

    def test_get_app_id_from_name(self):
        #given
        host = "https://test.uleska.com"
        application_id = "f158a79b-4521-47a7-891d-8d580b429704"
        application_name = "Test App"
        applications_response = mock()
        applications = "[{" + f"\"id\": \"{application_id}\", \"name\": \"{application_name}\"" + "}]"
        when(ApplicationController).get_applications(host).thenReturn(applications_response)
        when(applications_response).text().thenReturn(applications)

        # when
        result = get_app_id_from_name(host, application_name, False)

        # then
        self.assertEqual(application_id, result)


    def test_get_app_id_from_name_exits_if_no_apps_found(self):
        #given
        host = "https://test.uleska.com"
        application_name = "Test App"
        applications_response = mock()
        applications = "[]"
        when(ApplicationController).get_applications(host).thenReturn(applications_response)
        when(applications_response).text().thenReturn(applications)

        # when - then
        self.assertRaises(
            SystemExit,
            lambda: get_app_id_from_name(host, application_name, False)
        )

    def test_get_app_id_from_name_exits_if_no_app_with_matching_name_found(self):
        #given
        host = "https://test.uleska.com"
        application_id = "f158a79b-4521-47a7-891d-8d580b429704"
        application_name = "Test App"
        applications_response = mock()
        applications = "[{" + f"\"id\": \"{application_id}\", \"name\": \"{application_name}\"" + "}]"
        when(ApplicationController).get_applications(host).thenReturn(applications_response)
        when(applications_response).text().thenReturn(applications)


        # when - then
        wrong_application_name = "Wrong Name"
        self.assertRaises(
            SystemExit,
            lambda: get_app_id_from_name(host, wrong_application_name, False)
        )