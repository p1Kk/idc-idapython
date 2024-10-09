# Counts the number of defined functions in an IDA disassembly.
#
# Written for use against Linksys WRT54Gv8 firmware image.
# 04 July 2011
# Craig Heffner
# www.devttys0.com

ea = ScreenEA()
n = 0

for fea in Functions(SegStart(ea), SegEnd(ea)):
    n += 1

print "Number of defined functions: %d" % n
