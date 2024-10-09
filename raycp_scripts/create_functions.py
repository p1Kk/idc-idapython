# Locates and creates functions in a binary file in IDA.
#
# Written for use against Linksys WRT54Gv8 firmware image.
# 04 July 2011
# Craig Heffner
# www.devttys0.com

ea = ScreenEA()
la = 0x802DDAC0
addui = "BD 27" # addui $sp, XX
lw = "\x35\x80" # lw $v0, XX
n = 0

print "\nStarting MIPSEL addui function search at: 0x%X" % ea

while ea is not BADADDR and ea < la:

    ea = FindBinary(ea, SEARCH_DOWN, addui)  
    ea -= 2
    
    if not isCode(GetFlags(ea)):
        
        pflags = GetFlags(ea-8)
        pbytes = GetManyBytes(ea-8, 2, False)
        
        if not isCode(pflags) and pbytes == lw:
            ea -= 8
            
        Jump(ea)
        
        if MakeFunction(ea):
            n += 1
            
    ea += 4 
    
print "Created %d new functions\n" % n
