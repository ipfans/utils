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

## rename.py ##

Help to identify the func names. For more details, find reference in files' header.

## ios\_llvm\_fixer.idc ##

Apple is not standing still and in iOS 5 the default compiler is LLVM instead of GCC. It produces somewhat different code and IDA < 6.2 fail to resolve references which are now relative to PC.

Here is an example of code dissasembled with IDA :

__text:00001000 MOV R4, 0x12344    
__text:00001008 ADD R4, PC    

After executing this IDC script :

__text:00001000 MOV R4, 0x12344    
__text:00001008 ADD R4, PC ; off_13350    

(if the address is named, the name will appear instead of off_xxx)

The xref is also added so that when you type X on address 0x13350 you'll see where it is used.

## RunLogs.py ##

print registers during the IDA debugging. Log the following 100 lines.

## fixobjec.idc ##

**fixobjec.idc** an attempt to improve the original fixobjc.idc script by Willem Jan Hengeveld. For now it's only compatible with Mach-O 32bits binaries for Mac OS X. The Goal is to make it compatible with all Mac OS X and iOS binaries.

Original here: https://github.com/gdbinit/fixobjc

## logparser.py ##

Thanks to ZDI Team blog post ( http://dvlabs.tippingpoint.com/blog/2008/07/17/mindshare-hit-tracing-in-windbg ) and Matthew Graeber's working ( http://www.exploit-monday.com/2011/07/integrating-windbg-and-ida-for-improved.html )

## FixGetProcName.py ##

This script is help you to change the name with GetProcAddress API function.