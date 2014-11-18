
import json
import idc

'''
License : GPLv2
Author : n0fate (n0fate@n0fate.com), forensic.n0fate.com
Name : makecommsyscallref.py
Requirements : This script need to open symbol file. The symbol file is output of volafox 'dumpsym' option. volafox : code.google.com/p/volafox
Site : github.com/n0fate/idascript
It can comment a kernel symbol name considered as KASLR to callee address if symbol isn't identified for analyzing the KEXT dumped in memory
Dumped symbol template of volafox : dictionary {address(hex):name(string), address(hex):name(string), ...}
'''

FILENAME = AskFile(0, '*.*', 'open symbol file')

d2 = json.load(open(FILENAME))

for f in Functions():
    func = get_func(f)
    for head in Heads(func.startEA,func.endEA):
        if GetMnem(head) == "call":
            if(GetOpnd(head,0).startswith('near ptr')):
				try:
					funcname = str(d2[hex(GetOperandValue(head,0))])[1:]	# remove a prefix('_')
					print '%s: 0x%.8X (click here:%x)'%(funcname, GetOperandValue(head,0), head)
					idc.MakeComm(head, funcname)
				except KeyError:
					print 'Could not find function: 0x%.8X (click here:%x)'%(GetOperandValue(head,0), head)