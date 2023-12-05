from idanalyzer2 import *
import traceback
import json

try:
    c = Contract('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    c.throwApiException(True)
    temp = c.createTemplate("tempName", "<p>%{fullName}</p>")
    with open('createTemplate.json', 'w') as f:
        f.write(json.dumps(temp, indent=4))
    tempId = temp['templateId']
    resp = c.updateTemplate(tempId, "oldTemp", "<p>%{fullName}</p><p>Hello!!</p>")
    with open('updateTemplate.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = c.getTemplate(tempId)
    with open('getTemplate.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = c.listTemplate()
    with open('listTemplate.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = c.generate(tempId, "PDF", "", {
        'fullName': "Tian",
    })
    with open('generate.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = c.deleteTemplate(tempId)
    with open('deleteTemplate.json', 'w') as f:
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
