// What terminates the game from the parent launcher's side?
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }
function addr(mod, fn) {
  try { var m = Process.getModuleByName(mod); return m.findExportByName(fn); }
  catch (e) { return null; }
}
function bt(ctx) {
  try {
    return Thread.backtrace(ctx, Backtracer.ACCURATE)
      .map(function (a) { return DebugSymbol.fromAddress(a).toString(); }).join("\n    ");
  } catch (e) { return "(no stack)"; }
}

["TerminateProcess", "ExitProcess"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn);
  if (!a) { log("init", "no " + fn); return; }
  Interceptor.attach(a, {
    onEnter: function (args) {
      var extra = fn === "TerminateProcess" ? ("hProcess=" + args[0] + " exit=" + args[1]) : ("exit=" + args[0]);
      log("KILL", fn + " " + extra + "\n    " + bt(this.context));
    }
  });
});
var nt = addr("ntdll.dll", "NtTerminateProcess");
if (nt) Interceptor.attach(nt, {
  onEnter: function (args) {
    log("NTKILL", "hProcess=" + args[0] + " exit=" + args[1] + "\n    " + bt(this.context));
  }
});

var cp = addr("kernel32.dll", "CreateProcessW");
if (cp) Interceptor.attach(cp, {
  onLeave: function (ret) { log("SPAWN", "ret=" + ret); }
});
["WaitForSingleObject", "WaitForSingleObjectEx", "WaitForMultipleObjects"].forEach(function (fn) {
  var a = addr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      this.fn = fn; this.h = args[0]; this.ms = args[1];
      log("WAIT", fn + " h=" + args[0] + " ms=" + args[1]);
    },
    onLeave: function (ret) { log("WAIT", this.fn + " h=" + this.h + " -> " + ret); }
  });
});
log("init", "parent trace ready");
