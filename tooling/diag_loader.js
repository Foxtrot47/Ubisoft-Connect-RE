// Diagnose why ChildofLight.exe exits at startup when the launcher folder is gone.
// Hooks: LoadLibraryW/A, CreateFileW/A (pipe + dll probing), RegOpenKeyExW.

function getAddr(mod, exp) {
  try {
    var m = Process.getModuleByName(mod);
    return m ? m.findExportByName(exp) : null;
  } catch (e) { return null; }
}
function log(tag, msg) { try { send({ tag: tag, msg: msg }); } catch (e) {} }

["LoadLibraryW", "LoadLibraryA", "LoadLibraryExW"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, { onEnter: function (args) {
    try {
      var p = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
      if (/uplay|ubiorbit|GameLauncher|upc/i.test(p)) log("LOADLIB", fn + " " + p);
    } catch (e) {}
  }, onLeave: function (ret) {
    if (this.last) log("LOADLIB", "  -> " + ret);
  }});
});

["CreateFileW", "CreateFileA"].forEach(function (fn) {
  var a = getAddr("kernel32.dll", fn);
  if (!a) return;
  Interceptor.attach(a, {
    onEnter: function (args) {
      try {
        this.p = fn.slice(-1) === "W" ? args[0].readUtf16String() : args[0].readAnsiString();
      } catch (e) { this.p = null; }
    },
    onLeave: function (ret) {
      if (this.p && /uplay|pipe|GameLauncher|upc|Ubisoft/i.test(this.p)) {
        log("OPEN", this.p + "  -> " + ret);
      }
    }
  });
});

var reg = getAddr("advapi32.dll", "RegOpenKeyExW");
if (reg) Interceptor.attach(reg, { onEnter: function (args) {
  try {
    var sub = args[1].readUtf16String();
    if (/ubisoft|uplay/i.test(sub)) log("REG", "RegOpenKeyExW " + sub);
  } catch (e) {}
}});

log("init", "diagnostic hooks ready");
