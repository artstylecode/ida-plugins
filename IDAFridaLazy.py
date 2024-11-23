import ida_name
import idaapi
import frida
import os
import json
import idc
import datetime
from PyQt5 import uic
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import  QApplication


default_print_info = """
function print_func_info(args, paramsNum,stage, _this, retval){
        if(stage == "onEnter"){
            _this.params = [];
            for (let i = 0; i < paramsNum; i++) {
                _this.params.push(args[i]);
                _this.logs=_this.logs.concat("this.args" + i + " onEnter: " + print_arg(args[i]));
            }
        }else if(stage == "onLeave"){
            for (let i = 0; i < paramsNum; i++) {
                _this.logs=_this.logs.concat("this.args" + i + " onLeave: " + print_arg(this.params[i]));
            }
            _this.logs=_this.logs.concat("retval onLeave: " + print_arg(ptr(retval).add(0x10).readPointer()) + "\\n");
        }
    }
"""

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
    [print_func_info]
    // @ts-ignore
    function hook_native_addr(funcPtr, paramsNum) {
        var module = Process.findModuleByAddress(funcPtr);
        try {
            Interceptor.attach(funcPtr, {
                onEnter: function (args) {
                    this.logs = "";
                    // @ts-ignore
                    this.logs=this.logs.concat("So: " + module.name + "  Method: [funcname] offset: " + ptr(funcPtr).sub(module.base) + "\\n");
                    print_func_info(args, paramsNum, "onEnter", this, null)
                }, onLeave: function (retval) {
                    print_func_info(this.params, paramsNum, "onEnter", this, retval)
                    if([isPrintStack]){
                        this.logs=this.logs.concat('[funcname] called from:' +Thread.backtrace(this.context, Backtracer.ACCURATE)
                        .map(DebugSymbol.fromAddress).join("\\n") + '\\n');
                    }
                    send(this.logs)
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
        return self.TopDescription + ":" + type(self).__name__

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
        #self.load()
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

    def generate_for_funcs(self, func_addr_list, paramNum=None, isPrintStack:bool=False) -> str:
        stubs = []
        for func_addr in func_addr_list:
            if(paramNum == None or paramNum == 0):
                dec_func = idaapi.decompile(func_addr)
                paramNum = dec_func.type.get_nargs()
            repdata = {
                "filename": self.get_idb_filename(),
                "funcname": self.get_function_name(func_addr),
                "offset": hex(func_addr - self.imagebase),
                "nargs": hex(paramNum),
                "isPrintStack":str(isPrintStack).lower(),
                "print_func_info":default_print_info
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
    TopDescription = "FridaIDALazy"
    def __init__(self):
        super(StopFridaScript, self).__init__()
       
       
    def activate(self, ctx):
       gl.session.detach()
       print("stop hook")
        

idb_path = os.path.dirname(idaapi.get_input_file_path()) 

class HookConfigurationUi():
    generator:ScriptGenerator = ScriptGenerator(global_config)
    hook_addr_list = None
    func_name = None
    origin_key_event = None
    def __init__(self, params_num, hook_addr_list, func_name):
        self.device: frida.core.Device = frida.get_usb_device()
        cwdPath = os.environ['IDA_PLUGINS']
        self.ui = uic.loadUi("{}{}hook.ui".format(cwdPath, os.sep))
        self.ui.edit_hook_num.setText(str(params_num))
        self.ui.te_print_args.setPlainText(default_print_info)
        self.hook_addr_list = hook_addr_list
        self.func_name = func_name
        self.origin_key_event = self.ui.te_print_args.keyPressEvent
        self.ui.te_print_args.keyPressEvent = self.keyPressEvent
        self.ui.btn_hook.clicked.connect(self.btn_hook_click)
    def keyPressEvent(self, event):
        # 检查是否是 Ctrl+V 或者 Command+V（MacOS）
        if event.key() == Qt.Key_V and (event.modifiers() & Qt.ControlModifier or
                                        event.modifiers() & Qt.MetaModifier):
            clipboard = QApplication.clipboard()
            pasted_text = clipboard.text()
            print("Pasted text:", pasted_text)
            self.ui.te_print_args.setPlainText(pasted_text)
            # 在这里处理粘贴的文本
            # ...
        else:
            self.origin_key_event(event)
    def isChecked(self, cb) -> bool:
        return cb.checkState()==2
    def onPaste(self):
        clipboard = QApplication.clipboard()
        text = clipboard.text()
        self.plainTextEdit.setPlainText(text)
    def btn_hook_click(self):
        hook_num = int(self.ui.edit_hook_num.text())
        isPrintStack:bool = self.ui.cb_print_stack.checkState()==2
        default_print_info = self.ui.te_print_args.toPlainText()
        print("default_print_info", default_print_info)
        script = self.generator.generate_for_funcs(self.hook_addr_list, hook_num,isPrintStack )
        if(self.isChecked(self.ui.cb_is_save_script)):
            with open("{}.js".format(self.func_name), "w") as f:
                f.write(script)
        pid = self.device.get_frontmost_application().pid
        if gl.session:
            gl.session.detach()
        gl.session = self.device.attach(pid)
        
        script = gl.session.create_script(script)
        script.on('message', self.on_message)
        script.load()
        self.ui.close()
    def on_message(self,message, data):
        if(message['type'] == 'send'):
            date = datetime.datetime.now()
            formatted_date = date.strftime("%Y%m%d%H%M%S")
            log_file = os.path.join(idb_path, "{}_{}.log".format(self.func_name, formatted_date))
            print("{}{}\n".format(message, data))
            content = "{}\n".format(message['payload'])
            print(content)
            
            with open(log_file, "w+") as f:
                f.write(content) 
        
#生成并运行hook脚本
class RunGeneratedScript(IDAFridaMenuAction):
    TopDescription = "FridaIDALazy"

    description = "start hook"
    
    out_file = None
    log_file = None
    generator:ScriptGenerator = ScriptGenerator(global_config)
    def __init__(self):
        super(RunGeneratedScript, self).__init__()
       
       
       
    def read_frida_js_source(self):
        with open(self.out_file, "r") as f:
            return f.read()
    def activate(self, ctx):
        if ctx.form_type==idaapi.BWN_FUNCS:
            hook_addr_list = [idaapi.getn_func(idx).start_ea for idx in ctx.chooser_selection] #from "idaapi.getn_func(idx - 1)" to "idaapi.getn_func(idx)"
        else:
            hook_addr_list=[idaapi.get_func(idaapi.get_screen_ea()).start_ea]
        self.func_name = self.generator.get_function_name(hook_addr_list[0])
        dec_func = idaapi.decompile(hook_addr_list[0])
        dialog = HookConfigurationUi(dec_func.type.get_nargs(), hook_addr_list, self.func_name)
        dialog.ui.show()
        dialog.ui.exec_()

       
        
    

print("IDAFridLazy!")

action_manager.register(RunGeneratedScript())
action_manager.register(StopFridaScript())