


(function () {

   let hook_addr = Module.findExportByName("libwework_framework.so", "Java_com_tencent_wework_foundation_logic_GrandProfileService_nativeLoginGetCaptcha")
   Interceptor.attach(hook_addr, {
      onEnter(args) {
         this.tid = Process.getCurrentThreadId();
         Stalker.follow(this.threadId, {
            events: {
               /**
                * Whether to generate events for CALL/BLR instructions.
                */
               call: true,

               /**
                * Whether to generate events for RET instructions.
                */
               ret: false,

               /**
                * Whether to generate events for all instructions.
                *
                * Not recommended as it's potentially a lot of data.
                */
               exec: false,

               /**
                * Whether to generate an event whenever a basic block is executed.
                *
                * Useful to record a coarse execution trace.
                */
               block: false,

               /**
                * Whether to generate an event whenever a basic block is compiled.
                *
                * Useful for coverage.
                */
               compile: false,
            },
            onReceive: function (events) {
               let all_events = Stalker.parse(events)
               //console.log(`envent length:${all_events.length}`)
               for (let i = 0; i < all_events.length; i++) {
                  let event = all_events[i]
                  let event_type = event[0]
                  let call_from_addr = event[1]
                  let call_from_module = Process.findModuleByAddress(call_from_addr)
                  let call_to_addr = event[2]
                  let call_to_module = Process.findModuleByAddress(call_to_addr);
                  let num = event[3]
                  if (call_from_module && call_to_module&&call_from_module.name == "libwework_framework.so"&&call_to_module.name == "libwework_framework.so") {
                     let call_from_off_addr = call_from_addr.sub(call_from_module.base)
                     let call_to_off_addr = call_to_addr.sub(call_to_module.base)
                     //console.log(`nativeLoginGetCaptcha stalker event info type:${event_type} from_addr:${call_from_module.name}!${call_from_off_addr} to_addr:${call_to_module.name}!${call_to_off_addr}`);
                  }

               }
            },
            onCallSummary(summary){
               //console.log("-------------onCallSummary----------------")
               let callSummaryInfo = []
               for (const addr in summary) {
                 
                     const call_num = summary[addr];
                     let module = Process.findModuleByAddress(addr)
                     if(module&&module.name=="libwework_framework.so"){
                        let off_addr = ptr(addr).sub(module.base)
                        //console.log(`key:${module.name}!${ptr(addr).sub(module.base)}`);
                        callSummaryInfo.push(off_addr)
                     }
                        
               }
               console.log(JSON.stringify(callSummaryInfo))
            }
         })
      }, onLeave(ret) {
         Stalker.unfollow(this.tid);
      }
   })
})();

