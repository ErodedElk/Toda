from Toda import patcher_x64
from Toda.Utils.hooking import *

a=patcher_x64.patcher("./test/demo")
a.run()
a.hook(0x0000000000001273,[
                           setreg("rbx",0x666666)

                           ])
a.finish()

"""
suage:

a=patcher_x64.patcher("./test/demo")
a.run()
a.hook(addr,[
    utils.printreg(?),
    utils.printstr(?),
    utils.mhexdump(addr),
    utils.setreg(reg,value),
    utils.setmempory(addr,value),
])
a.finish()
"""