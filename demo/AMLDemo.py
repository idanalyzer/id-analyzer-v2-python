from idanalyzer2 import *
import traceback
import json

try:
    a = AML('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    a.throwApiException(True)

    resp = a.search(name="John Smith", country="US")
    with open('amlSearch.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))

    respV3 = a.searchV3(text="John Smith", limit=10, page=1)
    with open('amlSearchV3.json', 'w') as f:
        f.write(json.dumps(respV3, indent=4))
except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])
