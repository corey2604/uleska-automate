import requests

__session__ = requests.Session()

def make_session(token : str) -> requests.Session:
    """Makes a new Resquests Session with correct authorization

    Parameters:
    token (str): api token

    Returns:
    obj: A request session
    """
    __session__.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )


def get_session() -> requests.Session:
    """Gets the current request session with correct authorization"""
    return __session__