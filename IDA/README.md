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