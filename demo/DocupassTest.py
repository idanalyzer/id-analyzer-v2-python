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
