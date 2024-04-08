# Toda
一个简易的二进制插桩工具，主要用于跟踪代码执行流程以方便解决在CTF中遇到的复杂执行流。

## 用法

引入该包以后，通过 `patcher_x64.patcher` 建立项目，调用 `run` 方法进行初始化，并通过 `hook` 注入需要的代码，最后调用 `finish` 即可。完成补丁的文件将生成在目标文件相同目录下，添加了后缀名 `.patch` 。

```python
from Toda import patcher_x64
from Toda.Utils.hooking import *

a=patcher_x64.patcher("./test/demo")
a.run()
a.hook(0x0000000000001273,[printstr(b"testtoka1")])
a.finish()
```

## 相关功能
目前只针对 x64 平台开启 pie 保护后的程序进行插桩，相关功能完善中。
- raw_shellcode：直接注入任意 shellcode。
- printreg：打印寄存器值。
- printstr：打印字符串。
- mhexdump：以16进制打印内存。
- setreg：设置寄存器为特定值。
- setmempory：None
