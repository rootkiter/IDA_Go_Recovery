#!/bin/python
###############################################
# File Name : go_helper.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-07-22 19:34:15 CST
###############################################

import idaapi
idaapi.require("go_util")
import sys

def valid_name(btsname):
    # transbts = b'[]{}()*-./\\&'
    transbts = b'[]{}()*-/\\&'
    btrans=bytes.maketrans(transbts, len(transbts)*b"_")
    return btsname.translate(btrans)

def set_function_name(addr, funcname):
    origin_name = idc.get_func_name(addr)
    if origin_name == None or len(origin_name) == 0:
        # print("reprocess ",hex(addr), funcname)
        idc.del_items(addr)
        idc.auto_wait()
        idc.create_insn(addr)
        idc.auto_wait()
        idc.add_func(addr)
    elif not origin_name.startswith("sub_"):
        return
    idc.set_name(addr, valid_name(funcname))

def set_var_name(addr, typename):
    idc.set_name(addr, typename)

def recovery_function_by_clzhandle(clzhandle):
    for i,funcaddr, funcname in clzhandle.iterator_function():
        try:
            fname = funcname.decode()
        except Exception as e:
            continue
        set_function_name(funcaddr, funcname.decode())
    for type_addr in clzhandle.iterator_type_struct():
        ok, addr, typestr = clzhandle.try_parse_type_struct(type_addr)
        if ok:
            set_var_name(addr, "_type_%s" % typestr)
    print("go version ", clzhandle.go_version())

def GoRecovery(ver):
    ok, clz = go_util.get_recovery_handle(ver)
    if not ok:
        errmsg = clz
        print(errmsg)
        return False
    recovery_function_by_clzhandle(clz)
    return True

def try_recovery_function_names():
    ok, versions, clzhandle = go_util.try_guess_go_functions()
    if not ok:
        gopclntab_addr, magic = clzhandle
        print("Magic number matching failed [", hex(gopclntab_addr), ":", hex(magic),"]")
        print("You can manually specify a version number, for example:")

        for ver in versions:
            print("   GoRecovery(\"%s\")" % (ver))
        return
    recovery_function_by_clzhandle(clzhandle)


'''
    ## 测试样例
    95199e8f1ab987cd8179a60834644663 Go1.2  x86-64 LSB
    f90b11eca708a111813e4799fb5e8818 Go1.16 x86-64 LSB
    b02920aa7a042c5bcd6900416579b7eb Go1.18 ARM32  LSB
    33f0114e1cb7c2c38a3e92058d1b58d6 Go1.18 MIPS32 MSB
'''

if __name__=='__main__':
    try_recovery_function_names()


