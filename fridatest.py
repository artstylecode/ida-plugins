from fridahelper import FridaHelper


class StalkerTraceGenAction():
    description = "trace generate3"
    traceHookList = []
    def __init__(self):
        self.TopDescription = "stalker trace4"
        self.fridaHelper = FridaHelper()
    def activate(self, ctx):
        off_addr = "0xd8ebd8"
        with open("trace.js", "r") as f:
            script = f.read()
       
        print("开始调用trace脚本")
        self.fridaHelper.start(script, self.on_trace_message)
    def on_trace_hook_message(self, message, data):
        payload = message['payload']
        print(payload)
        with open("trace-hook.log", "w") as f:
            f.write(payload)
    def on_trace_message(self, message, data):
        payload = message['payload']
        
        if(payload['type'] == 'unfollow'):
            print("start deal trace hook")
            print("payload", payload)
            hooList = payload['hookList']
            for item in hooList:
                self.traceHookList.append({'offset':item['addr'], 'func_name':item['func_name'], 'paramNum':5})
            print("hookList:", self.traceHookList)

StalkerTraceGenAction().activate(None)