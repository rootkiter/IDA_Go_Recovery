#!/bin/python
###############################################
# File Name : go_parser/util/__init__.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-07-25 12:41:58 CST
###############################################

import idaapi, idc
from . import ida_utils
def try_guess_go_functions():
    gopclntab  = ida_utils.get_segm_by_name([".gopclntab", "__gopclntab"])
    itablink = ida_utils.get_segm_by_name([".itablink", "__itablink"])
    if gopclntab == None or \
            gopclntab.start_ea == idc.BADADDR or \
            itablink.start_ea == idc.BADADDR:
        return False, None
    # from . import pclntab
    idaapi.require("go_util.pclntab")
    for clzname in dir(pclntab):
        clz = getattr(pclntab, clzname)
        if not hasattr(clz, "MAGIC") or clz.MAGIC == 0:
            continue
        handle = clz(gopclntab, itablink)
        if handle.matched_go_version():
            return True, handle
    return False, None
