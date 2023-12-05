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

