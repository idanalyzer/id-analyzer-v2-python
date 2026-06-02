from idanalyzer2 import *
import traceback
import json

try:
    p = ProfileAPI('CBoQpSfkRcPvUhstucIPfiGNLPVuwB23')
    p.throwApiException(True)

    cfg = Profile(Profile.SECURITY_MEDIUM)
    cfg.decisionTrigger(1, 1)

    created = p.createProfile("My Onboarding Profile", cfg)
    with open('createProfile.json', 'w') as f:
        f.write(json.dumps(created, indent=4))
    profileId = created['profileId']

    p.updateProfile(profileId, "My Onboarding Profile (v2)", cfg)
    resp = p.getProfile(profileId)
    with open('getProfile.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))

    resp = p.listProfile()
    with open('listProfile.json', 'w') as f:
        f.write(json.dumps(resp, indent=4))

    p.exportProfile(profileId)
    p.deleteProfile(profileId)
except APIError as e:
    print(traceback.format_exc())
    print(e.args[0])
except InvalidArgumentException as e:
    print(traceback.format_exc())
    print(e.args[0])
except Exception as e:
    print(traceback.format_exc())
    print(e.args[0])
