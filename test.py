import sys

with open("D:\\project\\reserve\\ida-plugins\\test.js", "r", encoding="utf8") as f:
    js_code = f.read()

import frida

#设备找不到异常
class DeviceNotFoundError(Exception):...
#未找到任何前台程序
class DeviceNoneFrontApplicationRunError(Exception):...
#附加进程失败
class AttachApplicationError(Exception):...

class FridaHelper():
    # 附加模式
    mode = "attach"
    # 当mode为attach时pid不能为0
    pid = 0
    # 当mode为spawn是package不能为空
    package_name = None
    device: frida.core.Device = None
    session: frida.core.Session = None
    script = None

    def __init__(self, mode="attach", pid=0, package_name=None) -> None:
        self.mode = mode
        self.pid = pid
        self.package_name = package_name

    def start(self, scriptStr, onMessage):
        self.stop()
        self.device = frida.get_usb_device()
        if self.device == None:
            raise DeviceNotFoundError("未连接任何设备！")
        if (self.mode == "attach"):
            if (self.pid == 0):
                app = self.device.get_frontmost_application()
                if (app == None):
                    raise DeviceNoneFrontApplicationRunError("设备未运行任何app或frida server未运行")
                self.pid = app.pid

        elif (self.mode == "spawn"):
            self.pid = self.device.spawn(self.package_name)
        # if self.session != None:
        #     self.session.detach()
        #     self.script.unload()
        self.session = self.device.attach(self.pid)

        if (self.session == None):
            raise AttachApplicationError("附加进程失败")
        self.script = self.session.create_script(scriptStr)
        self.script.on("message", onMessage)
        self.script.load()
       

    def stop(self):
        if self.session:
            self.session.detach()

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        print("list:", helper.script.exports_sync.getCallInfoList())
        if(payload['type'] == "callInfo"):
            on_trace_call_log(payload['list'])
        elif (payload['type'] == "callSummaryInfo"):
            on_trace_summary_log(payload['list'])
    else:
        print(message)
def on_trace_call_log(list):
    print(list)
def on_trace_summary_log(list):
    print(list)
helper = FridaHelper()
helper.start(js_code, on_message)


