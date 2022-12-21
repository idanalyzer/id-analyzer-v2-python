
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
from idanalyzer import *
import traceback

try:
    profile = Profile(Profile.SECURITY_MEDIUM)
    s = Scanner('OlZBrUWs4F60McKKKpuLKNY01XX7sm6B')
    s.throwApiException(True)
    print(s.quickScan('05.jpg', "", True))
    s.setProfile(profile)
    print(s.scan("05.jpg"))
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
from idanalyzer import *
import traceback

try:
    profile = Profile(Profile.SECURITY_MEDIUM)
    b = Biometric('OlZBrUWs4F60McKKKpuLKNY01XX7sm6B')
    b.throwApiException(True)
    b.setProfile(profile)
    print(b.verifyFace('05.jpg', '05.jpg'))
    print(b.verifyLiveness('05.jpg', '05.jpg'))
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
from idanalyzer import *
import traceback

try:
    c = Contract('OlZBrUWs4F60McKKKpuLKNY01XX7sm6B')
    c.throwApiException(True)
    temp = c.createTemplate("tempName", "<p>%{fullName}</p>")
    tempId = temp['templateId']
    print(temp)

    print(c.updateTemplate(tempId, "oldTemp", "<p>%{fullName}</p><p>Hello!!</p>"))
    print(c.getTemplate(tempId))
    print(c.listTemplate())
    print(c.generate(tempId, "PDF", "", {
        'fullName': "Tian",
    }))
    print(c.deleteTemplate(tempId))
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
from idanalyzer import *
import traceback

try:
    d = Docupass('OlZBrUWs4F60McKKKpuLKNY01XX7sm6B')
    d.throwApiException(True)
    doc = d.createDocupass("bbd8436953ef426e98d078953f258835")
    print(doc)
    print(d.listDocupass())
    print(d.deleteDocupass(doc['reference']))
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
from idanalyzer import *
import traceback

try:
    t = Transaction('OlZBrUWs4F60McKKKpuLKNY01XX7sm6B')
    t.throwApiException(True)
    tid = "8bec6f4d4a284c3691869a7c5e62b25b"
    print(t.getTransaction(tid))
    print(t.listTransaction())
    print(t.updateTransaction(tid, "review"))
    print(t.deleteTransaction(tid))
    t.saveImage("79ec3533af600c463869c199fa162b56e41f7e2f293fc7f4ba8aca1e562acc58", "test.jpg")
    t.saveFile("testsign_3smMjY66x4y7CVPNrbBRGyKoePrlW8oi.pdf", "test.pdf")
    t.exportTransaction("./test.zip", [
        "fd8f0fce40304210ba3911d2624cd521",
        "11223691b21a444bbd1491e621f0afa4"
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
