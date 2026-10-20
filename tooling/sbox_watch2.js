// Watch the AES S-box page, re-arming after every hit, and report unique callers.
function sym(a) {
  try { var m = Process.findModuleByAddress(a); return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString(); }
  catch (e) { return "?"; }
}
var range = { base: Process.getModuleByName("upc.exe").base.add(0x145b000), size: 0x1000 };
var seen = {}, count = 0, hits = 0;
function arm() {
  MemoryAccessMonitor.enable(range, {
    onAccess: function (d) {
      count++;
      var f = sym(d.from);
      if (!seen[f]) { seen[f] = 1; hits++; send({ tag: "SBOX", msg: d.operation + " " + f + " addr=" + d.address }); }
      arm();
    }
  });
}
arm();
setInterval(function () { send({ tag: "STAT", msg: "accesses=" + count + " unique=" + hits }); }, 5000);
send({ tag: "INIT", msg: "monitor armed on " + range.base });
