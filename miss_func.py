import idaapi
import idc

def rebuild_functions_from_prologues():
    segm = idaapi.get_segm_by_name("__text")
    seg_start = segm.startEA
    seg_end = segm.endEA
    print ("Segment Address : 0x%08x-0x%08x"%(seg_start, seg_end))
    cursor = seg_start
    while cursor < seg_end:
        #print ("Cursor Offset : 0x%08x"%cursor)
        #cursor = idaapi.find_not_func(cursor, 0x1)
        #print Byte(cursor)
        if (Byte(cursor) == 0x55 and Byte(cursor+1) == 0x48 and Byte(cursor+2) == 0x89):
            idc.MakeFunction(cursor)
        cursor += 1
rebuild_functions_from_prologues()
