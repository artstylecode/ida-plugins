#插件效果：获取so所有函数的地址与名称的映射关系，生成选中函数的stalker追踪代码，调用frida运行脚本，根据stalker的结果生成批量hook代码
import idautils
import idc
import os
import idaapi
import json
import ida_name
from action import IDAFridaMenuAction,action_manager
from fridahelper import FridaHelper
func_addr = []
func_name = []
hook_list = []
stalker_default_template = """
var func_addr = [func_addr]
var func_name = [func_name]
var so_name = "[filename]"
function traceTarget() {
    let module = Process.findModuleByName(so_name)
    if (module) {
        let hook_addr = module.base.add([hook_off])

        if (hook_addr) {
            Interceptor.attach(hook_addr, {
                onEnter(args) {
                    console.log(`----------------start trace ${so_name}!${func_name}-------------`)
                    this.tid = Process.getCurrentThreadId();
                    Stalker.follow(this.threadId, {
                        events: {
                            call: true,
                            ret: false,
                            exec: false,
                            block: false,
                            compile: false,
                        },
                        onReceive: function (events) {
                            let all_events = Stalker.parse(events)
                            let call_info = []
                            console.log(`envent length:${all_events.length}`)
                            for (let i = 0; i < all_events.length; i++) {
                                let event = all_events[i]
                                let event_type = event[0]
                                let call_from_addr = event[1]
                                let call_from_module = Process.findModuleByAddress(call_from_addr)
                                let call_to_addr = event[2]
                                let call_to_module = Process.findModuleByAddress(call_to_addr);
                                let num = event[3]
                                if (call_from_module && call_to_module && call_from_module.name == "libwework_framework.so" && call_to_module.name == "libwework_framework.so") {
                                    let call_from_off_addr = call_from_addr.sub(call_from_module.base)
                                    let call_to_off_addr = call_to_addr.sub(call_to_module.base)
                                    call_info.push({
                                        'from': {
                                            'module': call_from_module,
                                            'off_addr': call_from_off_addr
                                        },
                                        'to': {
                                            'module': call_to_module,
                                            'off_addr': call_to_off_addr
                                        }
                                    })
                                    console.log(`nativeLoginGetCaptcha stalker event info type:${event_type} from_addr:${call_from_module.name}!${call_from_off_addr} to_addr:${call_to_module.name}!${call_to_off_addr}`);
                                }

                            }
                            //发送日志
                            send({
                                'type': 'callInfo',
                                'list': call_info
                            })
                        },
                        onCallSummary(summary) {
                            let callSummaryInfo = [];
                            console.log("-------------onCallSummary----------------")
                            for (const addr in summary) {

                                let module = Process.findModuleByAddress(addr)
                                if (module && module.name == "libwework_framework.so") {
                                    let off_addr = ptr(addr).sub(module.base);
                                    callSummaryInfo.push({
                                        'addr': off_addr
                                    })
                                    console.log(`key:${module.name}!${off_addr}`);
                                }

                            }
                            //发送日志
                            send({
                                'type': 'callSummaryInfo',
                                'list': callSummaryInfo
                            })
                        }
                    })
                }, onLeave(ret) {
                    Stalker.unfollow(this.tid);
                }
            })
        }
    }
}
"""
batch_hook_template = """

(function () {
    let hook_list = [hooklist]
    // @ts-ignore
    function print_arg(addr) {
        try {
            var module = Process.findRangeByAddress(addr);
            if (module != null) return "\\n"+hexdump(addr) + "\\n";
            return ptr(addr) + "\\n";
        } catch (e) {
            return addr + "\\n";
        }
    }

    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum, func_name) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method: "+func_name+" offset: [filename]!" + ptr(funcPtr).sub(module.base) + "\\n");
                    for (let i = 0; i < paramsNum; i++) {
                        this.params.push(args[i]);
                        this.logs=this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
                    }
                }, onLeave: function (retval) {
                    for (let i = 0; i < paramsNum; i++) {
                        this.logs=this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
                    }
                    this.logs=this.logs.concat("retval onLeave: " + print_arg(retval) + "\\n");
                    console.log("new")
                    send(this.logs);
                }
            });
        } catch (e) {
            send(e);
        }
    } 
    for(let i = 0;i < hook_list.length;i++){
        let hookinfo = hook_list[i]
        // @ts-ignore
        hook_native_addr(Module.findBaseAddress("[filename]").add(hookinfo.offset), hookinfo.paramNum, hookinfo.func_name);
    }
    
})();

"""





# s = generate_stub(batch_hook_template, {
#      "filename": os.path.basename(idaapi.get_input_file_path()),
#      "hooklist":json.dumps(hook_list)
# })

class Configuration():
     isCModule = False
     def __init__(self) -> None:
          pass


config = Configuration()

class ScriptGenerator:
    config: Configuration = None
    def __init__(self, configuration: Configuration) -> None:
         self.config = configuration
         self.filename = os.path.basename(idaapi.get_input_file_path())
    @staticmethod
    def get_idb_filename():
        return os.path.basename(idaapi.get_input_file_path())
    def get_function_name(self,
                          ea):  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
        """
        Get the real function name
        """
        # Try to demangle
        function_name = idc.demangle_name(idc.get_func_name(ea), idc.get_inf_attr(idc.INF_SHORT_DN))

        # if function_name:
        #    function_name = function_name.split("(")[0]

        # Function name is not mangled
        if not function_name:
            function_name = idc.get_func_name(ea)

        if not function_name:
            function_name = idc.get_name(ea, ida_name.GN_VISIBLE)

        # If we still have no function name, make one up. Format is - 'UNKN_FNC_4120000'
        if not function_name:
            function_name = "UNKN_FNC_%s" % hex(ea)

        return function_name
    @staticmethod
    def get_idb_path():
        return os.path.dirname(idaapi.get_input_file_path())
    #根据地址获取函数名称
    def get_function_name(self,
                          ea):  # https://hex-rays.com/products/ida/support/ida74_idapython_no_bc695_porting_guide.shtml
        """
        Get the real function name
        """
        # Try to demangle
        function_name = idc.demangle_name(idc.get_func_name(ea), idc.get_inf_attr(idc.INF_SHORT_DN))

        # if function_name:
        #    function_name = function_name.split("(")[0]

        # Function name is not mangled
        if not function_name:
            function_name = idc.get_func_name(ea)

        if not function_name:
            function_name = idc.get_name(ea, ida_name.GN_VISIBLE)

        # If we still have no function name, make one up. Format is - 'UNKN_FNC_4120000'
        if not function_name:
            function_name = "UNKN_FNC_%s" % hex(ea)

        return function_name
    #根据模板与字典信息生成脚本
    def generate_stub(self,template, repdata: dict):
        s = template
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s
    def generate_batch_trace_scripts(self, hook_list):
        s = self.generate_stub(batch_hook_template, {
            "filename": self.filename,
            "hooklist": json.dumps(hook_list)
        })
        with open("trace-hook.log", "w") as f:
            f.write(s)
        return s
    #根据so函数信息生成指定函数的stalker trace脚本
    def generate_stalker_scripts(self,addr):
        s = self.generate_stub(stalker_default_template, {
        "filename": os.path.basename(idaapi.get_input_file_path()),
        "func_addr":json.dumps(func_addr),
        "func_name":json.dumps(func_name),
        "hook_off":str(hex(addr))
        })
        with open("trace.js", "w") as f:
            f.write(s)
        return s





#add(hookinfo.offset), hookinfo.paramNum, hookinfo.func_name)

class StalkerTraceGenAction(IDAFridaMenuAction):
    description = "trace generate3"
    scriptGen:ScriptGenerator = None
    traceHookList = []
    def __init__(self):
        super(StalkerTraceGenAction, self).__init__()
        self.TopDescription = "stalker trace"
        self.imagebase = idaapi.get_imagebase()
        self.scriptGen = ScriptGenerator(config)
        self.fridaHelper = FridaHelper()
    def activate(self, ctx):
        print("开始生成stalker trace脚本")
        if ctx.form_type==idaapi.BWN_FUNCS:
            hook_addr_list = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection] #from "idaapi.getn_func(idx - 1)" to "idaapi.getn_func(idx)"
        else:
            hook_addr_list=[idaapi.get_func(idaapi.get_screen_ea()).start_ea]
        print(ctx.chooser_selection)
        off_addr = hook_addr_list[0]-self.imagebase
        print("func_name:{} offset addr:{}".format(self.scriptGen.get_function_name(hook_addr_list[0]),hook_addr_list[0]-self.imagebase))
        script = self.scriptGen.generate_stalker_scripts(off_addr)
       
        print("开始调用trace脚本")
        self.fridaHelper.start(script, self.on_trace_message)
    def on_trace_hook_message(self, message, data):
        payload = message['payload']
        print(payload)
        with open("trace-hook.log", "w") as f:
            f.write(payload)
    def on_trace_message(self, message, data):
        payload = message['payload']
        
        if(payload['type'] == 'callSummaryInfo'):
            print("start deal trace hook")
            print("payload", payload)
            hooList = payload['list']
            for item in hooList:
                dec_func = idaapi.decompile(item['addr'])
                func_name = self.scriptGen.get_function_name(item['addr'])
                self.traceHookList.append({'offset':item['addr'], 'func_name':func_name, 'paramNum':dec_func.type.get_nargs()})
            print("hookList:", self.traceHookList)
            #生成trace脚本
            trace_hook_script = self.scriptGen.generate_batch_trace_scripts(self.traceHookList)
            print(trace_hook_script)
            #调用trace脚本
            #self.fridaHelper.start(trace_hook_script, self.on_trace_hook_message)
        else:
            dec_func = idaapi.decompile(payload['addr'])
            ##获取trace结果
            
        
        

def test():
    print("test")
action_manager.register(StalkerTraceGenAction())

# generate_stalker_scripts()