#!/usr/bin/python

import requests
import sys
import json

def main():

    apiHook = apiKey = None
    for arg in sys.argv:
        if arg.startswith("--eventtype="):
            event = arg[len("--eventtype="):]
        elif arg.startswith("--api-key="):
            apiKey = arg[len("--api-key="):]
        elif arg.startswith("--api-hook="):
            apiHook = arg[len("--api-hook="):]
        else:
            details = arg.split("\t", 3)

    if apiHook is None or apiKey is None:
        sys.stderr.write("You must provide --api-key and --api-hook arguments")
        sys.exit(1)

    level = details[0]
    config = details[1] if len(details) >= 2 else ""
    trigger = details[2] if len(details) >= 3 else ""
    message = details[3] if len(details) >= 4 else ""

    payload = { "event": event, "level": level, "config": config } 

    if "/" in trigger:
        payload["additional"] = trigger
        extra = message.split("\t", 1)
        if len(extra) == 2:
            trigger = extra[0]
            message = extra[1]

    payload["trigger"] = trigger
    payload["message"] = message

    print "St2 Payload: {}".format(payload)

    uri="https://stackstorm/api/v1/webhooks/vadc_hook"
    headers = { "St2-Api-Key": apiKey, "Content-Type": "application/json" }
    res = requests.post(apiHook, headers=headers, data=json.dumps(payload), verify=False)
    print "(St2 Response: {}: {}".format(res.status_code, res.text)

if __name__ == "__main__":
    main()
