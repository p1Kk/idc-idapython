import idautils
import idc
import idaapi

symfile_path = 'C:\\Users\\28643\\Desktop\\C2E58'

# 符号起始
symbols_table_start = 8
# 字符串起始
strings_table_start = 0x9d80

with open(symfile_path, 'rb') as f:
    symfile_contents = f.read()

symbols_table = symfile_contents[symbols_table_start:strings_table_start]
strings_table = symfile_contents[strings_table_start:]

def get_strings_by_offset(offset):
    index = 0
    while True:
        if strings_table[offset+index] != 0:
            index += 1
        else:
            break
    return strings_table[offset:offset+index]

def get_symbols_metadata():
    symbols = []
    for offset in range(0, len(symbols_table), 8):
        # 一个符号的段落
        symbol_item = symbols_table[offset:offset+8]
        # 标志位
        flag = symbol_item[0]
        print(flag)
        # 符号偏移
        string_offset = int(symbol_item[1:4].hex(), 16)
        print(string_offset)
        # 根据符号偏移找到符号名
        string_name = get_strings_by_offset(string_offset).decode("utf-8")
        print(string_name)
        # 符号在文件内存中的地址
        target_address = int(symbol_item[4:].hex(), 16)
        print(target_address)
        # 列表
        symbols.append((flag, string_name, target_address))
    return symbols

def add_symbols(symbols_meta_data):
    # 对于列表symbols_meta_data中的数据
    for flag, string_name, target_address in symbols_meta_data:
        # 对目标地址进行重命名
        idc.set_name(target_address, str(string_name))
        if flag == '\x54':
            # 指定地址 字节转化为指令
            idc.MakeCode(target_address)
            # 指定地址转换成函数
            idc.MakeFunction(target_address)
            
if __name__ == "__main__":
    symbols_metadata = get_symbols_metadata()
    add_symbols(symbols_metadata)
    
