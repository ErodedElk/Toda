from Toda import patcher_x64
from Toda.Utils.hooking import *

a=patcher_x64.patcher("./test/demo")
a.run()
a.hook(0x0000000000001273,[printstr(b"testtoka1")])
a.finish()

"""
suage:

a=patcher_x64.patcher("./test/demo")
a.run()
a.hook(addr,[
    utils.printreg(?),
    utils.printstr(?),
    utils.hexdump(addr),
    utils.setreg(reg,value),
    utils.setmempory(addr,value),
])
a.finish()
"""
