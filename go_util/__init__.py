#!/bin/python
###############################################
# File Name : go_parser/util/__init__.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-07-25 12:41:58 CST
###############################################

import idaapi, idc
from . import ida_utils

def get_processer_dict():
    clzdict = {}
    idaapi.require("go_util.pclntab")
    for clzname in dir(pclntab):
        clz = getattr(pclntab, clzname)
        if not hasattr(clz, "MAGIC") or clz.MAGIC == 0:
            continue
        clzdict[clz.GOVER] = clz
        # print("CLZ:", clz.GOVER, clz.LEVEL, clz.MAGIC)
    return clzdict

def get_pclntab_info():
    gopclntab  = ida_utils.get_segm_by_name([".gopclntab", "__gopclntab"])
    itablink = ida_utils.get_segm_by_name([".itablink", "__itablink"])
    if gopclntab == None or \
            gopclntab.start_ea == idc.BADADDR or \
            itablink.start_ea == idc.BADADDR:
        return False, None
    return True, (gopclntab, itablink)

def get_recovery_handle(ver):
    clz_dict = get_processer_dict()
    if ver not in list(clz_dict):
        return False, "Didn't get match version"
    clz = clz_dict[ver]
    ok, pclntab_info = get_pclntab_info()
    if not ok:
        return False, "Didn't get_pclntab"
    gopclntab, itablink = pclntab_info
    handle = clz(gopclntab, itablink)
    return True, handle

def try_guess_go_functions():
    ok, pclntab_info = get_pclntab_info ()
    if not ok:
        return False, None
    gopclntab, itablink = pclntab_info

    # from . import pclntab
    magic = 0x00
    handles_dict = get_processer_dict()

    for v, clz in handles_dict.items():
        handle = clz(gopclntab, itablink)
        ok, magic = handle.matched_go_version()
        if ok:
            return True, [], handle
    verlist = [(x, handles_dict[x].LEVEL) for x in list(handles_dict)]
    verlist.sort(key=lambda x:x[1], reverse=True)
    return False, [x[0] for x in verlist], (gopclntab.start_ea, magic)
