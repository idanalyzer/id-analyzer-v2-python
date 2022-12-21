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
