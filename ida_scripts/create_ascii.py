# Turns all ASCII byte arrays into strings in IDA.
#
# Written for use against Linksys WRT54Gv8 firmware image.
# 04 July 2011
# Craig Heffner
# www.devttys0.com

ea = ScreenEA()
n = 0

print "\nLooking for possible strings starting at: 0x%X\n" % ea

for s in Strings():
    if s.ea > ea:
        if MakeStr(s.ea, BADADDR):
            Jump(s.ea)
            n += 1
    
print "\nCreated %d new ASCII strings\n" % n
            
