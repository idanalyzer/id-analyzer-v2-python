from idanalyzer2 import *
import traceback
import json

try:
    w = Webhook('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    w.throwApiException(True)

    logs = w.listWebhook(limit=20)
    with open('listWebhook.json', 'w') as f:
        f.write(json.dumps(logs, indent=4))

    # w.resendWebhook("<webhookId>")
    # w.deleteWebhook("<webhookId>")
except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])
