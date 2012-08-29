# RunLogs.py
#---------------------------------------------------------------------
# Debug Log Plugins
#
# This script start the executable and steps to given EA to Log all
# registers.
#
# Author: H00p <cmd4shell@gmail.com>
#
#---------------------------------------------------------------------

from idaapi import *

def LogToFile(str):
    fh = open('D:\\runlogs.txt','wb+')
    print >> fh,str
    fh.close()

class MyDbgHook(DBG_Hooks):
    def dbg_bpt(self, tid, ea):
        print "Break point at 0x%x pid=%d" % (ea, tid)
        print "Starting logging..."
        self.logit = True
        return 0

    def dbg_step_over(self):
        if self.logit == True:
            print "Try to log..."
            LogToFile("0x%08X\tEAX=0x%08X,EBX=0x%08X,ECX=0x%08X,EDX=0x%08X,ESP=0x%08X,EBP=0x%08X,ESI=0x%08X,EDI=0x%08X "%(GetRegValue("EIP"),GetRegValue("EAX"),GetRegValue("EBX"),GetRegValue("ECX"),GetRegValue("EDX"),GetRegValue("ESP"),GetRegValue("EBP"),GetRegValue("ESI"),GetRegValue("EDI")))
            self.steps += 1
            if self.steps >= 100:
                self.logit = False
                
        request_step_over()
        

try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
except:
    pass

debughook = MyDbgHook()
debughook.hook()
debughook.steps = 0
debughook.logit = False
print "Installed hook"
