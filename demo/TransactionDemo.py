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
