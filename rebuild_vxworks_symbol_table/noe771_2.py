# source : https://blog.csdn.net/weixin_43815930/article/details/107646507
from idaapi import *
from idc import *
 
loadaddress = 0x10000 #加载地址
eaStart = 0x31eec4 + loadaddress#符号表起始地址
eaEnd = 0x348114 + loadaddress#符号表结束地址
 
ea = eaStart
eaEnd = eaEnd
while ea < eaEnd:
    create_strlit(Dword(ea), BADADDR)
    #获取名称字符串，Dword为双字类型一个字等于两个字节，双字则是四个字节
    sName = get_strlit_contents(Dword(ea))
    print sName
    #如果函数名不为空
    if sName:
    	#获取函数地址
        eaFunc = Dword(ea + 4)
        #重命名地址，将函数地址与函数名对应
        MakeName(eaFunc, sName)
        #分析指定地址代码区
        MakeCode(eaFunc)
        #设置函数始末地址
        MakeFunction(eaFunc, BADADDR)
    #每次叠加16字节，每条符号表记录占16个字节
    ea = ea + 16
