
# ID Analyzer Python SDK
This is a python SDK library for [ID Analyzer Identity Verification APIs](https://www.idanalyzer.com), though all the APIs can be called with without the SDK using simple HTTP requests as outlined in the [documentation](https://id-analyzer-v2.readme.io), you can use this SDK to accelerate server-side development.

We strongly discourage users to connect to ID Analyzer API endpoint directly from client-side applications that will be distributed to end user, such as mobile app, or in-browser JavaScript. Your API key could be easily compromised, and if you are storing your customer's information inside Vault they could use your API key to fetch all your user details. Therefore, the best practice is always to implement a client side connection to your server, and call our APIs from the server-side.

## Installation
Install through PIP

```shell
pip install idanalyzer
```

## Scanner
This category supports all scanning-related functions specifically used to initiate a new identity document scan & ID face verification transaction by uploading based64-encoded images.
![Sample ID](https://www.idanalyzer.com/img/sampleid1.jpg)
```python
from idanalyzer2 import *
import traceback
import json


try:
    profile = Profile(Profile.SECURITY_MEDIUM)
    s = Scanner('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    s.throwApiException(True)
    resp = s.quickScan('05.png', "", True)
    with open('quickScan.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    s.setProfile(profile)
    resp = s.scan("05.png")
    with open('scan.json', 'w') as f:
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


```

## Biometric
There are two primary functions within this class. The first one is verifyFace and the second is verifyLiveness.
```python
from idanalyzer2 import *
import traceback
import json

try:
    profile = Profile(Profile.SECURITY_MEDIUM)
    b = Biometric('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    b.throwApiException(True)
    b.setProfile(profile)
    resp = b.verifyFace('05.png', '05.png')
    with open('verifyFace.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = b.verifyLiveness('05.png', '05.png')
    with open('verifyLiveness.json', 'w') as f:
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
```

## Contract
All contract-related feature sets are available in Contract class. There are three primary functions in this class.
```python
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

```

## Docupass
This category supports all rapid user verification based on the ids and the face images provided.
![DocuPass Screen](https://www.idanalyzer.com/img/docupassliveflow.jpg)
```python
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

```

## Transaction
This function enables the developer to retrieve a single transaction record based on the provided transactionId.
```python
from idanalyzer2 import *
import traceback
import json

try:
    t = Transaction('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    t.throwApiException(True)
    tid = "da3124d09173474cabc86f3a648c9084"
    resp = t.getTransaction(tid)
    with open('getTransaction.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = t.listTransaction()
    with open('listTransaction.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = t.updateTransaction(tid, "review")
    with open('updateTransaction.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))
    resp = t.deleteTransaction(tid)
    with open('deleteTransaction.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))

    t.saveImage("fb2079b309c116b025408b2b79f90b9c196b02a27827ba98ea1ddc2af63f111c", "test.jpg")
    t.saveFile("testsign_3smMjY66x4y7CVPNrbBRGyKoePrlW8oi.pdf", "test.pdf")
    t.exportTransaction("./test.zip", [
        "305e9fcb7b7a48dbab7c87d3a752b5e1",
    ], "json")

except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])

```

## Api Document
[ID Analyzer Document](https://id-analyzer-v2.readme.io/docs/python)

## Demo
Check out **/demo** folder for more Python demos.

## SDK Reference
Check out [ID Analyzer Python Reference](https://idanalyzer.github.io/id-analyzer-nodejs/)
