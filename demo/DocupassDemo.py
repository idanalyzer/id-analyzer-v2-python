from idanalyzer2 import *
import traceback
import json

try:
    d = Docupass('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    d.throwApiException(True)
    doc = d.createDocupass("bbd8436953ef426e98d078953f258835")
    with open('createDocupass.json', 'w') as outfile:
        json.dump(doc, outfile)
    resp = d.listDocupass()
    with open('listDocupass.json', 'w') as outfile:
        json.dump(resp, outfile)
    resp = d.deleteDocupass(doc['reference'])
    with open('deleteDocupass.json', 'w') as outfile:
        json.dump(resp, outfile)
except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])
