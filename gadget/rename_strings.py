# 将ida string中未自动命名的字符串重命名为"a"+string
# 遇到重复名结尾自动加"_"
import idaapi
import idc
import idautils
import sys
import re  
  
def get_alphanumeric_string(s):
    return ''.join([char for char in s if char.isalnum()])  

strings = idautils.Strings()
strings_name = []
for string in strings:
    ea = string.ea
    content = str(string)
    print("0x%x" % ea)
    # print(content)
    if all(c.isprintable() or c.isspace() for c in content):
        current_name = idaapi.get_name(ea)
        if not current_name or current_name == "":
            max_name_length = 100
            content = get_alphanumeric_string(content)
            truncated_content = "a"+content[:max_name_length]
            while truncated_content in strings_name:
                truncated_content += "_"
            idaapi.set_name(ea, truncated_content)
            strings_name.append(truncated_content)
        else:
            strings_name.append(current_name)
print("[+]END")
            
        