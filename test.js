var call_info = []
function main () {
    let module = Process.getModuleByName("libwhatsapp.so")
    let hook_addr = module.base.add(0x80A9CC)

    Interceptor.attach(hook_addr, {
        onEnter(args) {
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
                    call_info = []
                    console.log(`envent length:${all_events.length}`)
                    for (let i = 0; i < all_events.length; i++) {
                        let event = all_events[i]
                        let event_type = event[0]
                        let call_from_addr = event[1]
                        let call_from_module = Process.findModuleByAddress(call_from_addr)
                        let call_to_addr = event[2]
                        let call_to_module = Process.findModuleByAddress(call_to_addr);
                        let num = event[3]
                        if (call_from_module && call_to_module && call_from_module.name == "libwhatsapp.so" && call_to_module.name == "libwhatsapp.so") {
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
                    // send({
                    //     'type': 'callSummaryInfo',
                    //     'list': callSummaryInfo
                    // })
                }
            })
        }, onLeave(ret) {
            Stalker.unfollow(this.tid);
             //发送日志
             send({
                'type': 'callInfo',
                'list': []
            })
        }
    })



}

main();

rpc.exports = {
    hello:async function () {
      return 'Hello';
    },
    getCallInfoList: function () {
      return call_info;
    }
  };


