import requests

__session__ = requests.Session()

def make_session(token):
    __session__.headers.update(
        {
            "Content-Type": "application/json",
            "cache-control": "no-cache",
            "Authorization": "" + token,
        }
    )


def get_session():
    return __session__