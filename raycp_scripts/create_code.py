# Turns all unidentified code into functions in IDA.
#
# Written for use against Linksys WRT54Gv8 firmware image.
# 04 July 2011
# Craig Heffner
# www.devttys0.com

ea = ScreenEA()
la = 0x802DDAC0
n = 0

print "\nLooking for possible unreferenced functions starting at: 0x%X" % ea

while ea != BADADDR and ea < la:

    ea = NextAddr(ea)
    flags = GetFlags(ea)
    
    if not isCode(flags):
        if MakeFunction(ea):
            Jump(ea)
            n += 1
    
print "Created %d unreferenced functions\n" % n
            
