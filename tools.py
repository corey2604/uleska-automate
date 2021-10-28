import json
import sys

from controller.tools_controller import ToolsController


def get_tools_body(host, tools):
    # check the tools to use (these may be being updated)
    tools_list = tools.split(",")

    # get list of tools & details from the system as JSON
    system_tools = __get_system_tools(host)

    # TODO - right now we don't check that
    #  a) if any tool supplied by user in tools_list doesn't match the system tools list
    #  b) we report on that (error to the user) or how to handle it

    # create a store for the tools we're going to add
    tools_to_add = []

    # build the tools body up so we can submit with our version creation/update
    # iterate through the system_tools_list we got and extract matching info
    for tool in system_tools:

        if tool["title"] in tools_list:
            # tool.remove('icon') # we don't use this

            this_tool = {}
            this_tool["toolName"] = tool["name"]

            orig_string = json.dumps(tool)

            this_tool["toolJson"] = orig_string

            tools_to_add.append(this_tool)

        # What to do if a tool is supplied that is not in the list? TODO


def __get_system_tools(host: str):
    response = ToolsController.get_tools(host)
    try:
        return json.loads(response.text)
    except json.JSONDecodeError as jex:
        print("Invalid JSON when getting tools.  Exception: [" + str(jex) + "]")
        sys.exit(2)