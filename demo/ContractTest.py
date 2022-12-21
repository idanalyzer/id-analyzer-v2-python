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
