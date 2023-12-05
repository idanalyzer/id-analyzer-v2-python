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