from unittest import TestCase
from mockito import when, mock
from version2.version_api import get_version
from version2.version import Version
import uleska_api
import requests
from uuid import UUID
class VersionApiTest(TestCase):

    def test_get_version_returns_correct_version(self):
        # given
        app_id = UUID('{d051653a-0999-4dbb-b4c8-9c326abdac6d}')
        version_id = UUID('{bec2291f-92d2-48ce-8680-a36a89ee06c4}')
        
        expected = Version(id=str(version_id), name='Bob', schema='HTTPS', host='tomjshore.co.uk', port=443, createdDate='2021-09-27T11:32:45.898+0000')
        json = {
            'id': str(version_id),
            'createdDate': '2021-09-27T11:32:45.898+0000',
            'name': 'Bob',
            'schema': 'HTTPS',
            'host': 'tomjshore.co.uk',
            'port': 443
        }
        api = mock(spec=uleska_api.UleskaApi)
        response = mock(spec=requests.Response)
        when(uleska_api).get_api().thenReturn(api)
        when(api).get('/SecureDesigner/api/v1/applications/d051653a-0999-4dbb-b4c8-9c326abdac6d/versions/bec2291f-92d2-48ce-8680-a36a89ee06c4').thenReturn(response)
        when(response).json().thenReturn(json)

        # when
        result = get_version(app_id, version_id)

        # then
        self.assertEquals(expected, result)