// Bounded exception metadata only. No I/O/crypto hooks, memory dumps or patches.
'use strict';
let reports = 0;
function location(address) {
  const module = Process.findModuleByAddress(address);
  return module ? {module: module.name, offset: String(address.sub(module.base))}
                : {address: String(address)};
}
Process.setExceptionHandler(details => {
  if (details.type !== 'access-violation' || reports >= 32) return false;
  reports++;
  let backtrace = [];
  let instruction = '';
  try { backtrace = Thread.backtrace(details.context, Backtracer.ACCURATE).map(location); } catch (_) {}
  try { instruction = Instruction.parse(details.address).toString(); } catch (_) {}
  send({kind: 'exception', pid: Process.id, ordinal: reports, type: details.type,
        location: location(details.address), memory: details.memory, instruction, backtrace});
  // Preserve Windows/game exception handling. Observed exceptions can be handled
  // internally; an exception record alone does not establish a fatal crash.
  return false;
});
let exits = 0;
const hooked = new Set();
for (const [library, name] of [['kernel32.dll', 'ExitProcess'],
    ['ntdll.dll', 'RtlExitUserProcess'], ['ntdll.dll', 'NtTerminateProcess']]) {
  const module = Process.findModuleByName(library);
  const address = module && module.findExportByName(name);
  if (!address || hooked.has(String(address))) continue;
  hooked.add(String(address));
  Interceptor.attach(address, {onEnter(args) {
    if (exits++ >= 8) return;
    let backtrace = [];
    try { backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE).map(location); } catch (_) {}
    const code = name === 'NtTerminateProcess' ? args[1] : args[0];
    send({kind: 'exit-call', api: name, code: String(code), pid: Process.id, backtrace});
  }});
}
send({kind: 'observer-ready', pid: Process.id});
