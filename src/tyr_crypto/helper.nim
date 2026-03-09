import strutils

proc isPositive*(str: string): bool =
    ## Returns true for positive sounding strings, false otherwise.
    let 
        conv_str: string = str.strip().toLowerAscii()
    if(conv_str == "yes" or 
        conv_str == "y" or
        conv_str == "+" or
        conv_str == "ja" or
        conv_str == "oui" or
        conv_str == "yarp" or
        conv_str == "ye" or
        conv_str == "yep"):
        return true
    else: 
        return false
