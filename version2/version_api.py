from version2.version import Version
import uleska_api
from uuid import UUID

def get_version(app_id : UUID, version_id : UUID ) -> Version:
    api = uleska_api.get_api()
    
    url = '/SecureDesigner/api/v1/applications/{}/versions/{}'.format(app_id, version_id)

    response = api.get(url)
    version = response.json()
    return Version(**version)