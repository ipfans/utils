# README #

Some useful plugins for IDA Pro.

## hrfpconst.plw ##

by jonwil@EXETOOLS  
Ref: [http://bbs.pediy.com/showthread.php?t=152965](http://bbs.pediy.com/showthread.php?t=152965)

If you have used the current leaked version of Hex-Rays to reverse engineer stuff using floating point, you may have found out that it doesn't always detect floating point constants in code correctly.

e.g. it will output lines like  
LODWORD(x) = y;  
where x is a floating point value and y is an integer.  
In reality it should be recognizing that y is a floating point and displaying it as such (and not displaying the LODWORD) but it does not.  
This issue may be fixed in newer Hex-Rays versions but those are not leaked.

## UniCodeString-6.0-d.plw ##

by obaby  
Ref: [http://bbs.pediy.com/showthread.php?t=149486](http://bbs.pediy.com/showthread.php?t=149486)

Auto comment a Unicode String in IDA Pro.