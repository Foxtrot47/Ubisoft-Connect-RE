// Trace the real game's early exit: who calls ExitProcess and what it opens.
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join("\n    ");
  } catch (e) { return "(no stack)"; }
}

function addr(mod, fn) {
  try { var m = Process.getModuleByName(mod); return m.findExportByName(fn); }
  catch (e) { return null; }
}
["ExitProcess", "RtlExitUserProcess"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn) || addr("ntdll.dll", fn);
  if (!a) { log("init", "no " + fn); return; }
  Interceptor.attach(a, {
    onEnter: function (args) {
      log("EXIT", fn + " code=" + args[0] + "\n    " + bt(this.context));
    }
  });
});

var kt = addr("kernel32.dll", "TerminateProcess");
Interceptor.attach(kt, {
  onEnter: function (args) { log("EXIT", "TerminateProcess code=" + args[1] + "\n    " + bt(this.context)); }
});

var cf = addr("kernel32.dll", "CreateFileW");
Interceptor.attach(cf, {
  onEnter: function (args) {
    try {
      var p = args[0].readUtf16String();
      if (p && p.indexOf("\\pipe\\") >= 0) this.p = p;
    } catch (e) {}
  },
  onLeave: function (ret) {
    if (this.p) log("PIPE", this.p + " ret=" + ret);
  }
});

["NtTerminateProcess", "NtTerminateJobObject", "ZwTerminateProcess"].forEach(function (fn) {
  var a = addr("ntdll.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      log("NT", fn + " a0=" + args[0] + " a1=" + args[1] + " | " + bt(this.context));
    }
  });
});
Process.setExceptionHandler(function (d) {
  var where = "?";
  try {
    var a = d.address;
    var m = Process.findModuleByAddress(a);
    where = m ? (m.name + "+0x" + a.sub(m.base).toString(16)) : a.toString();
  } catch (e) {}
  var mem = "";
  try { mem = " mem=" + d.memory.operation + " " + d.memory.address + " size=" + d.memory.size; } catch (e) {}
  log("CRASH", d.type + " at " + where + mem + " | " + bt(d.context));
  try {
    var c = d.context;
    log("REGS", ["rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15"]
      .map(function (r) { return r + "=" + c[r]; }).join(" "));
  } catch (e) {}
  return false;
});
log("init", "exit trace ready");
