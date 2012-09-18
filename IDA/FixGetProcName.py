# FixGetProcName IDApython script
#
# Author: ipfans
#
# Fix the dynamics funcation name called by GetProcAddress() API.

import idaapi,idautils,idc,re

p = re.compile("mov\s+(.*),\s+eax")

def fixGetProcAddr(ea):
    t_ea = ea
    push_count = 0
    while push_count < 2:
        while idc.GetDisasm(t_ea).find("push") == -1:
            t_ea = idc.PrevHead(t_ea, 0)
        t_ea = idc.PrevHead(t_ea, 0)
        push_count +=1
    t_ea = idc.NextHead(t_ea, idc.SegEnd(t_ea))
    func_name_ea = Dword(t_ea + 1)
    func_name = ""
    while idc.Byte(func_name_ea):
        func_name += "%c" % Byte(func_name_ea)
        func_name_ea += 1
    while not p.match(idc.GetDisasm(ea)):
        ea = idc.NextHead(ea, SegEnd(ea))
    if idc.GetDisasm(ea).find("dword_"):
        MakeNameEx(LocByName(p.match(idc.GetDisasm(ea)).groups(1)[0]), func_name, idc.SN_NOCHECK)

def imp_cb(ea, name, ord):
    if name:
        if name == "GetProcAddress":
            print "Found %s at 0x%08x"%(name, ea)
            for xref in XrefsTo(ea, 0):
                if XrefTypeName(xref.type) == "Code_Near_Call":
                    #print xref.type, XrefTypeName(xref.type),'from', hex(xref.frm), 'to', hex(xref.to)
                    fixGetProcAddr(xref.frm)
            print "Fixup Done!"
    return True

nimps = idaapi.get_import_module_qty()
print "Found %d import(s)..."%nimps

for i in xrange(0, nimps):
    name = idaapi.get_import_module_name(i)
    if name:
        if name.lower() == "kernel32":
            print "kernel32.dll found!"
            idaapi.enum_import_names(i, imp_cb)