#! /usr/bin/python

from st2actions.runners.pythonrunner import Action
from lib.vadc import Vtm


class VtmAddWebhookAction(Action):

    def run(self, vtm, name, api_hook, api_key, event):

        arguments = [{"name": "api-hook", "description": "St2 API Webhook", "value": api_hook},
            {"name": "api-key", "description": "St2 API Token", "value": api_key}]

        program = "/opt/stackstorm/packs/vadc/files/st2-trigger.py"

        vtm = Vtm(self.config, self.logger, vtm)
        vtm.upload_action_program("st2-trigger.py", program)
        vtm.add_action_program(name, "st2-trigger.py", arguments)
        if event is not None:
            vtm.add_event_type_action(event, name)
        return (True, None)
