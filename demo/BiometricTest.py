from IdFort import *
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
