#!/bin/python
###############################################
# File Name : go_de_obfuscate.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-11-02 16:17:17 CST
###############################################

import idautils, idc

FLARE_EMU_IS_OK = False
try:
    import flare_emu
    class GoFlareEmu(flare_emu.EmuHelper):
        def __init__(self, *args, **kwarg):
            self.traceInst   = None
            self._hook_addrs = {}
            flare_emu.EmuHelper.__init__(self, *args, **kwarg)

        def hookAddr(self, address, callback):
            self._hook_addrs[address] = callback

        def traceEveryInst(self, callback):
            self.traceInst = callback

        def emulateRange(self, *args, **kwarg):
            # self.resetEmulatorMemory()
            # self.reloadBinary()
            def uc_inst_hook(uc, address, tp, userData):
                if self.traceInst:
                    self.traceInst(address)
                if address in self._hook_addrs:
                    self._hook_addrs[address] (address, userData)
            if self.traceInst or len(self._hook_addrs) > 0:
                kwarg['instructionHook'] = uc_inst_hook
            flare_emu.EmuHelper.emulateRange(self, *args, **kwarg)

    FLARE_EMU_IS_OK = True
except Exception as e:
    print(str(e))
    print("Missing flare_emu (https://github.com/mandiant/flare-emu)")

def slicebyteto_string(calladdr, ptr, size, userData):
    eh=userData['EmuHelper']
    bts = eh.getEmuBytes(ptr, size)
    try:
        bts = bts.decode()
        destr = "de-obf(str:%d): \"%s\"" % (size, bts)
    except Exception as e:
        destr = "de-obf(bytes:%d): \"%s\"" % (size, str(bts[:20]))
    print(hex(calladdr), hex(size), str(bts))
    idc.set_cmt(calladdr, destr, 0)
    eh.stopEmulation(userData)
    start = idc.get_func_attr(calladdr, FUNCATTR_START)
    for caller in idautils.XrefsTo(start, 0):
        idc.set_cmt(caller.frm, destr, 0)
    # print(hex(calladdr), bts.decode())

def call_hook(address, argv, funcName, userData):
    if(funcName == "runtime_slicebytetostring"):
        slicebyteto_string(address, argv[1], argv[2], userData)

def trace_inst(address):
    print("trace ", hex(address))

def de_obfuscate_string(addr, endAddr = None):
    try:
        eh = GoFlareEmu()
        # eh.traceEveryInst(trace_inst)
        eh.emulateRange(addr, endAddr=endAddr , callHook = call_hook)
        # print(eh.getEmuState())
    except Exception as e:
        print(str(e))

def try_de_obfuscate_strings(bytes_to_slice_ea):
    try:
        eh = GoFlareEmu()
        if not FLARE_EMU_IS_OK:
            print("Please install flare_emu first  [https://github.com/mandiant/flare-emu]\n")
            print(" $ pip install unicorn")
            return
        for func in idautils.XrefsTo(bytes_to_slice_ea, 0):
            funcname = idc.get_func_name(func.frm)
            slist = funcname.split('.')
            if len(slist) <= 0 or not slist[::-1][0].startswith('func'):
                continue
            idc.jumpto(func.frm)
            start = idc.get_func_attr(func.frm, FUNCATTR_START)
            de_obfuscate_string(start)
            #eh.emulateRange(start, callHook = call_hook)
    except Exception as e:
        print(str(e))

if __name__=='__main__':
    print("Only support gobfuscate [https://github.com/unixpickle/gobfuscate].")
    bytes_to_slice_ea = (idc.get_name_ea_simple("runtime.slicebytetostring"))
    print(bytes_to_slice_ea)
    # try_de_obfuscate_strings(bytes_to_slice_ea)
    # pass
