# Rename sub_xx function by the LOG function you provide
import idaapi  
import idautils  
import idc  
import ida_nalt  
import ida_hexrays  
import ida_bytes  
import ida_funcs
import re
# 1. 反编译后多个 `func_name(param0,            param1,            param2,            ...);` 字符串，顺序匹配至可以返回指定参数
# 2. 可能出现函数名在参数2/6/9等等不一定的位置，暂时不考虑这种情况
# 2.1 如果出现在2跑了一次后，再跑出现在3的参数，需要检查，是变量名如何处理，23处都是字符串如何检测？
# 3. 脚本需要继续细化 太冗杂
# 4. 可否加入图形化 通过右键log函数 一键展示并添加？
# 5. 真实函数名以`_`开头，修改`_`为`.`


def find_params_n(text, log_funcname, index):
    # ida decompiled format
    # func_name(param0, param1, param2, ...);
    pattern = re.compile(log_funcname+r'\s*\((.*?)\);', re.DOTALL)
    match = pattern.search(str(text))

    if match:
        params_str = match.group(1)
        params = re.split(r',\s*(?![^"]*"\s*,\s*[^"]*")', params_str)
        try:
            rename_func = re.sub(r'[^a-zA-Z0-9_]', '', params[index])       # 只保留字母数字及_
            if rename_func:
                return rename_func
                print(f"Rename func to {rename_func}")
            else:
                print(f"No character in params")
                return None
        except IndexError:
            print(f"Index error")
            return None
            
    else:
        print(f"Not found {log_funcname} caller")
        return None
  
def get_function_params_via_decompiler(ea, log_funcname, arg_index):
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-rays 反编译器不可用")
        return None

    # 获取指定地址的函数对象
    func = idaapi.get_func(ea)
    if func is None:
        print("未找到函数")
        return None

    # 反编译函数
    caller_text = ida_hexrays.decompile(func)
    if not caller_text:
        print("无法反编译函数")
        return None
    param = find_params_n(caller_text, log_funcname, arg_index)
    if param:
        return param
    else:
        return None
            
def rename_callers_based_on_arg(log_funcname, arg_index):  
    func_ea = idc.get_name_ea_simple(log_funcname) if isinstance(log_funcname, str) else log_funcname  
    if func_ea == idaapi.BADADDR:  
        print(f"Function {log_funcname} not found.")  
        return
      
    callers = []  
    for xref in idautils.XrefsTo(func_ea, 1):  
        try:
            caller_ea = xref.frm                                    # 调用点
            caller_func_name = idc.get_func_name(caller_ea)         # 调用函数名
            caller_func_addr = ida_funcs.get_func(caller_ea).start_ea# 调用函数地址
            if caller_func_name.startswith("sub_"):
                print("0x%x" % caller_ea) 
                arg = get_function_params_via_decompiler(caller_ea, log_funcname, arg_index)
                idc.set_name(caller_func_addr, arg, idc.SN_CHECK)
        except AttributeError:
            print("Sth wrong")

log_funcname = "smart_tty_print"
arg_index = 6                           # start from index 0
rename_callers_based_on_arg(log_funcname, arg_index)
