from session import get_session


def run_scan(host, application, version, token, print_json):

    if not print_json:
        print("Running non-blocking scan")

    s = get_session()

    ##### Kick off a scan
    ScanURL = (
        host
        + APPLICATION_PATH
        + application
        + "/versions/"
        + version
        + "/scan"
    )

    # Run scan
    if not print_json:
        print("Kicking off the scan")

    try:
        StatusResponse = s.request("Get", ScanURL)
    except requests.exceptions.RequestException as err:
        print("Exception running scan\n" + str(err))
        sys.exit(2)

    if StatusResponse.status_code != 200:

        # If you kick off a scan for a version when one is already running, it'll return 400 with a body saying "Scan already running"
        if (
            StatusResponse.status_code == 400
            and StatusResponse.text == "Scan already running"
        ):
            if not print_json:
                print("Got a 'Scan already running' response, nothing to do here")
        else:
            # Something went wrong, maybe server not up, maybe auth wrong
            print(
                "Non 200 status code returned when running scan.  Code ["
                + str(StatusResponse.status_code)
                + "]"
            )
            sys.exit(2)

    if not print_json:
        print("Scan running, this is non-blocking mode so now exiting.")