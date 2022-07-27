#!/bin/python
###############################################
# File Name : go_parser/go_util/pclntab.py
#    Author : rootkiter
#    E-mail : rootkiter@rootkiter.com
#   Created : 2022-07-25 12:44:49 CST
###############################################

import struct
import idaapi, idc, idautils
# idaapi.require("go_util.ida_utils")
# idaapi.require("ida_utils")
from . import ida_utils

kindmap = {
    1 : "Bool",
    2 : "Int",
    3 : "Int8",
    4 : "Int16",
    5 : "Int32",
    6 : "Int64",
    7 : "Uint",
    8 : "Uint8",
    9 : "Uint16",
    10: "Uint32",
    11: "Uint64",
    12: "Uintptr",
    13: "Float32",
    14: "Float64",
    15: "Complex64",
    16: "Complex128",
    17: "Array",
    18: "Chan",
    19: "Func",
    20: "Interface",
    21: "Map",
    22: "Ptr",
    23: "Slice",
    24: "String",
    25: "Struct",
    26: "UnsafePointer",

    0             : "",
    1 << 5        : "DirectIface",
    1 << 6        : "GCProg",
    (1 << 5) - 1  : "Mask",
}



class pclntab_struct_abs:
    MAGIC=0x00
    GOVER="0"
    def __init__(self, pclntab, itablink):
        self.pclntab      = pclntab.start_ea
        self.itablink     = itablink.start_ea
        self.itablink_end = itablink.end_ea
        self.rodata       = 0 # idaapi.get_segm_by_name(".rodata")
        rodata = ida_utils.get_segm_by_name([".rodata", "__rodata"])
        if rodata.start_ea != idc.BADADDR:
            self.rodata = rodata.start_ea

    @property
    def ptrsize(self):
        return idc.get_wide_byte(self.pclntab + 7)

    @property
    def fmt(self):
        fmt  = ">"  if idaapi.cvar.inf.is_be() else "<"
        fmt += "8I" if self.ptrsize == 4 else '8Q'
        return fmt

    def matched_go_version(self):
        if idc.get_wide_dword(self.pclntab) == self.MAGIC:
            return True
        return False

    def go_version(self):
        return self.GOVER

    def try_parse_type_struct(self, addr):
        sizeoff    = addr
        if idc.get_wide_dword(sizeoff) <= 0:
            return False, None, None
        ptrdata_off = sizeoff + self.ptrsize
        hash_off    = ptrdata_off + self.ptrsize
        tflag_off   = hash_off + 4 # hash is dword for every cpu
        align_off   = tflag_off + 1
        field_align_off = align_off + 1
        if idc.get_wide_byte(align_off) != idc.get_wide_byte(field_align_off):
            return False, None, None
        if idc.get_wide_byte(align_off) not in (1, 2, 4, 8):
            return False, None, None
        kind_off     = field_align_off +1
        alg_off      = kind_off + 1
        gcdata_off   = alg_off + self.ptrsize
        name_off     = gcdata_off + self.ptrsize
        size = idc.get_wide_dword(sizeoff)
        kind = idc.get_wide_byte(kind_off)
        if kind&0x1f not in kindmap:
            return False, None, None
        basetype = kindmap[kind&0x1f]
        if kind&0xe0 not in kindmap:
            return False, None, None
        leadtype = kindmap[kind&0xe0]
        typestr = basetype
        if len(leadtype) > 0:
            typestr = "%s_%s" % (leadtype, basetype)

        # common set
        ida_utils.MakeUcpubits(sizeoff, "size")
        ida_utils.MakeUcpubits(ptrdata_off, "")
        ida_utils.MakeU32(hash_off, "hash")
        ida_utils.MakeU8 (kind_off, "kind:%s" % typestr)
        ida_utils.MakeUptr(alg_off, "")
        ida_utils.MakeUptr(gcdata_off, "")
        noff = idc.get_wide_dword(name_off)
        if self.rodata == None:
            ida_utils.MakeU32(name_off, "name_off "+hex(noff))
        else:
            nameaddr = noff + self.rodata
            if idc.get_wide_byte(nameaddr + 1) != 0:
                namestr = idc.get_strlit_contents(nameaddr + 2)
            else:
                namestr = idc.get_strlit_contents(nameaddr + 3)
            if namestr == None:
                ida_utils.MakeU32(name_off, "name @ "+hex(nameaddr))
            else:
                ida_utils.MakeU32(name_off, "[%s]name : %s" % (
                    hex(nameaddr),namestr.decode().strip()
                ))

        typestr = "%s_%s" % (typestr, hex(addr).replace("0x", ""))

        # struct check
        if basetype == "Struct":
            field_off = name_off + 8+self.ptrsize
            field_num_off = field_off + self.ptrsize
            field_count = idc.get_wide_dword(field_num_off)
            field_base = idc.get_wide_dword(field_off)

            ida_utils.MakeUptr(field_off, "%d fields [%s]" % (
                field_count, hex(field_base)
            ))
            for i in range(0, field_count):
                member_base = field_base + i * (3 * self.ptrsize)
                m_name    = member_base
                m_type    = member_base + self.ptrsize
                m_offwhat = m_type + self.ptrsize

                m_name_addr = idc.get_wide_dword(m_name)
                if idc.get_wide_byte(m_name_addr + 1) != 0:
                    m_nstr = idc.get_strlit_contents(m_name_addr + 2)
                else:
                    m_nstr = idc.get_strlit_contents(m_name_addr + 3)
                m_offset = idc.get_wide_dword(m_offwhat) >> 1
                ida_utils.MakeUptr(m_name, (m_nstr.decode()))
                ida_utils.MakeUptr(m_type, "")
                ida_utils.MakeUptr(m_offwhat, "%s" % (hex(m_offset)))

        return True, addr, typestr

    def iterator_type_struct(self):
        itered = {}
        for addr in self._iterator_type_by_itablink():
            if addr not in itered:
                itered[addr] = True
                yield addr
        for addr in self._iterator_type_from_rodata():
            yield addr

    def _iterator_type_from_rodata(self):
        segobj = ida_utils.get_segm_by_name(['.rodata', "__rodata"])
        if segobj.start_ea != idc.BADADDR:
            for ea in range(segobj.start_ea, segobj.end_ea):
                if len(idc.get_name(ea)) > 0:
                    ok, _, _ = self.try_parse_type_struct(ea)
                    if ok:
                        yield ea

    def _iterator_type_by_itablink(self):
        itab_size = int((self.itablink_end - self.itablink)/ self.ptrsize)
        if itab_size <= 0:
            return
        for i in range(itab_size):
            offset = self.itablink + i*self.ptrsize
            type_pair = idc.get_wide_dword(offset)
            type1_addr = idc.get_wide_dword(type_pair)
            type2_addr = idc.get_wide_dword(type_pair+self.ptrsize)
            yield type1_addr
            yield type2_addr


    def iterator_function(self):
        pass

class pclntab_struct_GO_116(pclntab_struct_abs):
    # src/debug/gosym/pclntab.go
    MAGIC = 0xFFFFFFFA
    GOVER = 'Go1.16'

    def iterator_function(self):
        funcCnt = idc.get_wide_dword(self.pclntab+8)
        nametab_off = self.pclntab +8+ (self.ptrsize * 2) # function num / files num
        nametab  = idc.get_wide_dword(nametab_off)
        functab_off = nametab_off + (self.ptrsize * 4) # funcnametab/ cu_offset/ filetab/ pctab / functab
        functab  = idc.get_wide_dword(functab_off)

        print(hex(nametab), hex(functab), hex(functab+self.pclntab))
        nametab += self.pclntab
        functab += self.pclntab
        for i in range(funcCnt):
            itemoff = functab + (i*2) * self.ptrsize
            # funcaddr = idc.get_wide_dword(itemoff)
            func_entry = idc.get_wide_dword(itemoff+self.ptrsize)
            struct_funcinfo = func_entry + functab
            funcaddr   = idc.get_wide_dword(struct_funcinfo)
            nameoffset = idc.get_wide_dword(struct_funcinfo+self.ptrsize)
            nameaddr = nametab + nameoffset
            namestr = (idc.get_strlit_contents(nameaddr))
            yield (i, funcaddr, namestr)

class pclntab_struct_GO_12(pclntab_struct_abs):
    # refer : golang.org/s/go12symtab
    MAGIC = 0xFFFFFFFB
    GOVER = 'Go1.2'

    def iterator_function(self):
        funcCnt = idc.get_wide_dword(self.pclntab+8)
        baseAdr = self.pclntab + 8 + self.ptrsize
        for i in range(funcCnt):
            itemoff = (i * 2) * self.ptrsize
            funcaddr = idc.get_wide_dword(baseAdr + itemoff)
            nameoff  = idc.get_wide_dword(baseAdr + itemoff + self.ptrsize)
            nameoff  = idc.get_wide_dword(self.pclntab + nameoff + self.ptrsize)

            namestr = (idc.get_strlit_contents(nameoff + self.pclntab))
            yield ( i, funcaddr, namestr)
        pass

class pclntab_struct_GO_118(pclntab_struct_abs):
    # refer : src/debug/gosym/pclntab.go
    MAGIC = 0xFFFFFFF0
    GOVER = 'Go1.18'

    def iterator_function(self):
        '''
        [4] 0xfffffffb
        [2] 0x00 0x00
        [1] 0x01
        [1] 0x08
        [8] N (size of function symbol table)
        '''
        strucbuf = idc.get_bytes(self.pclntab + 8, 8 * self.ptrsize)
        bufInfo = struct.unpack(self.fmt, strucbuf)

        funcCnt  = bufInfo[0]
        funcOff  = bufInfo[7]
        nameOff  = bufInfo[3]
        funcInit = bufInfo[2]
        nameSize = bufInfo[4] - bufInfo[3]

        nameBase = self.pclntab + nameOff
        funcBase = self.pclntab + funcOff

        for i in range(funcCnt):
            pc = funcBase + 4
            itemoff = funcBase + (i * 2) * 4
            fdr = idc.get_wide_dword(itemoff)
            off = idc.get_wide_dword(itemoff + 4)
            fin = idc.get_wide_dword(pc + off)
            funcaddr = fdr + funcInit
            namestr = (idc.get_strlit_contents(nameBase+fin))
            # if namestr == None:
            #     continue
            yield(i, funcaddr, namestr)
        pass
