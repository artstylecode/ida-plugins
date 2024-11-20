import ida_name
import idaapi
import frida
import os
import json
import idc
import datetime


default_template = """

(function () {

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
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    this.params = [];
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method: [funcname] offset: " + ptr(funcPtr).sub(module.base) + "\\n");
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
    // @ts-ignore
    hook_native_addr(Module.findBaseAddress("[filename]").add([offset]), [nargs]);
})();

"""


###################
# from: https://github.com/igogo-x86/HexRaysPyTools
class ActionManager(object):
    def __init__(self):
        self.__actions = []

    def register(self, action):
        self.__actions.append(action)
        idaapi.register_action(
            idaapi.action_desc_t(action.name, action.description, action, action.hotkey)
        )

    def initialize(self):
        pass

    def finalize(self):
        for action in self.__actions:
            idaapi.unregister_action(action.name)


action_manager = ActionManager()


class Action(idaapi.action_handler_t):
    """
    Convenience wrapper with name property allowing to be registered in IDA using ActionManager
    """
    description = None
    hotkey = None

    def __init__(self):
        super(Action, self).__init__()

    @property
    def name(self):
        return "FridaIDALazy:" + type(self).__name__

    def activate(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

    def update(self, ctx):
        # type: (idaapi.action_activation_ctx_t) -> None
        raise NotImplementedError

class IDAFridaMenuAction(Action):
    TopDescription = "FridaIDALazy"

    def __init__(self):
        super(IDAFridaMenuAction, self).__init__()

    def activate(self, ctx) -> None:
        raise NotImplemented

    def update(self, ctx) -> None:
        if ctx.form_type == idaapi.BWN_FUNCS or ctx.form_type==idaapi.BWN_PSEUDOCODE or ctx.form_type==idaapi.BWN_DISASM:
            idaapi.attach_action_to_popup(ctx.widget, None, self.name, self.TopDescription + "/")
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

#配置类
class Configuration():
    template = None
    def __init__(self) -> None:
        self.load()
        if self.template == None:
            self.template = default_template
    def store(self):
        try:
            data = {"frida_cmd": self.frida_cmd, "template": self.template}
            open("IDAFridaLazy.json", "w").write(json.dumps(data))
        except Exception as e:
            print(e)

    def load(self):
        try:
            data = json.loads(open("IDAFridaLazy.json", "r").read())
            #self.frida_cmd = data["frida_cmd"]
            self.template = data["template"]
        except Exception as e:
            print(e)

global_config:Configuration = Configuration()
#脚本生成帮助类
class ScriptGenerator:
    def __init__(self, configuration: Configuration) -> None:
        self.conf = configuration
        self.imagebase = idaapi.get_imagebase()

    @staticmethod
    def get_idb_filename():
        return os.path.basename(idaapi.get_input_file_path())

    @staticmethod
    def get_idb_path():
        return os.path.dirname(idaapi.get_input_file_path())

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

    def generate_stub(self, repdata: dict):
        s = self.conf.template
        for key, v in repdata.items():
            s = s.replace("[%s]" % key, v)
        return s

    def generate_for_funcs(self, func_addr_list) -> str:
        stubs = []
        for func_addr in func_addr_list:
            dec_func = idaapi.decompile(func_addr)
            repdata = {
                "filename": self.get_idb_filename(),
                "funcname": self.get_function_name(func_addr),
                "offset": hex(func_addr - self.imagebase),
                "nargs": hex(dec_func.type.get_nargs())
            }
            stubs.append(self.generate_stub(repdata))
        return "\n".join(stubs)
class Global():
    session: frida.core.Session = None
    def __init__(self) -> None:
        pass
gl = Global()
#生成并运行hook脚本
class StopFridaScript(IDAFridaMenuAction): 
    description = "stop hook"
    def __init__(self):
        super(StopFridaScript, self).__init__()
       
       
    def activate(self, ctx):
       gl.session.detach()
       print("stop hook")
        

idb_path = os.path.dirname(idaapi.get_input_file_path())   
#生成并运行hook脚本
class RunGeneratedScript(IDAFridaMenuAction):
    description = "start hook"
    
    out_file = None
    log_file = None
    generator:ScriptGenerator = ScriptGenerator(global_config)
    def __init__(self):
        super(RunGeneratedScript, self).__init__()
       
        self.device: frida.core.Device = frida.get_usb_device()
        print("device:", self.device)
       
       
    def read_frida_js_source(self):
        with open(self.out_file, "r") as f:
            return f.read()
    def activate(self, ctx):
       
        if ctx.form_type==idaapi.BWN_FUNCS:
            hook_addr_list = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection] #from "idaapi.getn_func(idx - 1)" to "idaapi.getn_func(idx)"
        else:
            hook_addr_list=[idaapi.get_func(idaapi.get_screen_ea()).start_ea]
        self.func_name = self.generator.get_function_name(hook_addr_list[0])
        script = self.generator.generate_for_funcs(hook_addr_list)
        print("start hook")
        pid = self.device.get_frontmost_application().pid
        if gl.session !=None:
            gl.session.detach()
        gl.session = self.device.attach(pid)
        
        script = gl.session.create_script(script)
        script.on('message', self.on_message)
        script.load()
    def on_message(self,message, data):
        date = datetime.datetime.now()
        formatted_date = date.strftime("%Y%m%d%H%M%S")
        log_file = os.path.join(idb_path, "{}_{}.log".format(self.func_name, formatted_date))
        #print("{}{}\n".format(message, data))
        content = "{}\n".format(message['payload'])
        print(content)
        
        with open(log_file, "w+") as f:
            f.write(content) 

print("IDAFridLazy!")

action_manager.register(RunGeneratedScript())
action_manager.register(StopFridaScript())