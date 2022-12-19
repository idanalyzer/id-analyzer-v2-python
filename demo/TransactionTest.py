from IdFort import *
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
