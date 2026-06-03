from idanalyzer2 import *
import traceback
import json

try:
    acc = Account('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    acc.throwApiException(True)

    resp = acc.getAccount()
    with open('myAccount.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])
