#!/bin/python
###############################################
# File Name : go_parser/go_util/ida_utils.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-07-27 12:13:25 CST
###############################################

import idc, idaapi

def idc_createdata(ea, dataflag, size, common):
    idc.create_data(ea, dataflag, size, idaapi.BADADDR)
    idc.set_cmt(ea, common, 0)

def MakeU8(ea, common):
    # idc.create_byte(ea)
    # idc.set_cmt(ea, common, 0)
    idc_createdata(ea, idc.FF_BYTE, 1, common)

def MakeU16(ea, common):
    idc_createdata(ea, idc.FF_WORD, 2, common)

def MakeU32(ea, common):
    idc_createdata(ea, idc.FF_DWORD, 4, common)

def MakeU64(ea, common):
    idc_createdata(ea, idc.FF_QWORD, 8, common)

def MakeUcpubits(ea, common):
    if idaapi.get_inf_structure().is_64bit():
        MakeU64(ea, common)
    else:
        MakeU32(ea, common)

def MakeUptr(ea, common):
    MakeUcpubits(ea, common)

def get_segm_by_name(seglist):
    for segname in seglist:
        seg = idaapi.get_segm_by_name(segname)
        if seg != None and idc.BADADDR not in (seg.start_ea, seg.end_ea):
            return seg
    return None

