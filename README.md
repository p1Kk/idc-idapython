# idc/idapython

## Rebuild Vxworks Symbol Table

- noe771.idc/ noe771_2.py\
Author: Ruben\
python3\
使用条件：**固件加载地址**、**符号表起始地址**、**结束地址**

- tlwr886.py\
Author: GalaxyLab\
python3\
使用条件：系统文件无符号表，存在单独的符号文件：**符号索引结构**、**符号表**

- ida_scripts\
Author: raycp\
create_ascii.py: 将ida中所有的ASCII字节数组转化为字符串\
function_count.py: 统计函数数量\
create_functions.py: 查找并创建函数。根据mips函数开头特点，进行ida函数修复，效果同按"C"\
create_code.py: 所有未识别的代码转化为函数
