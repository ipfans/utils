# IDA #

**IDA** is a set of analysis tools for IDA. mainly for idapython.

## dejunk.py ##

**dejunk.py** is used to dejunk during IDA analysis.

**How to use**

select code need to dejunk, then use this script.

**How to add rules**

The pattern is as follows:


{

    'pattern':[0xEB,0x02,'??','??'],
    'fillwith':[0x90, 0x90, 0x90, 0x90],

}

The pattern above will match EB 02 and the 2 bytes following as"wildcards". The sizes of pattern and fillwith should be the same to avoid issues when patching.

## fixobjc2.idc ##

**fixobjc2.idc** is a IDA Pro 6.0 script to fix ObjC ABI 2.0 for iPhoneOS binaries.

## AfxMsgMap.idc ##

**AfxMsgMap.idc** can help to identify the AfxMsgMap.

Usage:

-  Alt+F7 to Load Script  
-  Shift+P to search MsgMap
-  If not define, double-click address to identify. Alt+P to confirm.

## *rename.py ##

Help to identify the func names. For more details, find reference in files' header.