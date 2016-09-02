# This program takes a C header/source as the input and produces
#
# with --keyword=enum: the list of all enums
# with --keyword=struct: the list of all structs
#
# the output styles:
#
# --enum    DBUS_POINTER_NAME1,
#           DBUS_POINTER_NAME2,
#           DBUS_POINTER_NAME3,
#
# --list    NAME1
#           NAME2
#           NAME3
#

from __future__ import absolute_import, division, print_function
import re
import sys

options = {}

def toprint(match, line):
    if verbatim:
        return line
    else:
        return pattern % match

for arg in sys.argv[1:]:
    if arg[0:2] == "--":
        mylist = arg[2:].split("=",1)
        command = mylist[0]
        if len(mylist) > 1:
            options[command] = mylist[1]
        else:
            options[command] = None

keyword = options.get("keyword", "struct")
pattern = options.get("pattern", "%s")
verbatim = "verbatim" in options

structregexp1 = re.compile(r"^(typedef\s+)?%s\s+\w+\s+(\w+)\s*;" % keyword)
structregexp2 = re.compile(r"^(typedef\s+)?%s" % keyword)
structregexp3 = re.compile(r"^}\s+(\w+)\s*;")

print("/* Generated by %s.  Do not edit! */" % sys.argv[0])

myinput = iter(sys.stdin)

for line in myinput:
    match = structregexp1.match(line)
    if match is not None:
        print(toprint(match.group(2), line))
        continue

    match = structregexp2.match(line)
    if match is not None:
        while True:
            if verbatim:
                print(line.rstrip())
            line = next(myinput)
            match = structregexp3.match(line)
            if match is not None:
                print(toprint(match.group(1), line))
                break
            if line[0] not in [" ", "\t", "{", "\n"]:
                if verbatim:
                    print(line)
                break
