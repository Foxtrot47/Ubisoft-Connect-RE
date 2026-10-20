// Watch the AES S-box page and log the code that touches it.
function sym(a) {
  try { var m = Process.findModuleByAddress(a); return m ? m.name + "+0x" + a.sub(m.base).toString(16) : a.toString(); }
  catch (e) { return "?"; }
}
var base = Process.getModuleByName("upc.exe").base.add(0x145b000);
var seen = {};
MemoryAccessMonitor.enable({ base: base, size: 0x1000 }, {
  onAccess: function (d) {
    var f = sym(d.from);
    if (seen[f]) return;
    seen[f] = 1;
    send({ tag: "SBOX", msg: d.operation + " from=" + f + " at=" + d.address });
  }
});
send({ tag: "INIT", msg: "monitor on " + base });
