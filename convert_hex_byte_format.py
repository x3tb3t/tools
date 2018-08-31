#!/usr/bin/python2

'''
This tool handle the following format for input and output:
\\x41\\x41\\x41\\x41
\x41\x41\x41\x41
41 41 41 41
41414141
0x41414141
0x41 0x41 0x41 0x41

For multi-lines input, paste the hex string into hexInput.txt
'''

import argparse

def banner():

    print '''
        =========================================================================
        |                      convert_hex_byte_format.py                       |
        |                 Convert hex bytes in multiple format                  |
        |                                                                       |
        |               Author: Alexandre Basquin | x3tb3t | @x3tb3t            |
        |        Usage: convert_hex_byte_format.py [options] (-h or --help)     |
        =========================================================================
    '''

def main():
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input", help="Hex string (ex: \\x41\\x41\\x41\\x41, 41 41 41 41, 0x41414141 or 0x41 0x41 0x41 0x41)")
    parser.add_argument("-f", "--inputfile", help="Give input file name (ex: hexinput.txt")
    args = parser.parse_args()

    if (args.input == None and args.inputfile == None):
        banner()
        parser.print_help()
        return 0

    banner()

    # check if input file is provided
    if args.inputfile != None:
        with open(args.inputfile, 'r') as f:
            hexInput = f.read().replace('\n', '')
    else:
        # transform input as 41414141
        hexInput = args.input

    hexInput = hexInput.replace(' ', '').replace('\\x', '').replace('\\', '').replace('0x', '').replace('\"', '').replace('.', '').replace('\'', '').replace(';', '').replace(',', '')
    lenInputDec = len(hexInput) / 2
    lenInputHex = hex(lenInputDec)
    print 'Hex bytes (' + str(lenInputDec) + ' or ' + lenInputHex + ') :\n' + hexInput

    print '''
    Output format available:
    1: 41414141
    2: 41 41 41 41
    3: \\x41\\x41\\x41\\x41
    '''

    outputFormat = raw_input('Enter your choice :')

    if outputFormat == '1':
        outputString = hexInput
        print outputString
    elif outputFormat == '2':
        outputString = ' '.join(hexInput[i:i+2] for i in range(0, len(hexInput), 2))
        print outputString
    elif outputFormat == '3':
        outputString = '\\x'.join(hexInput[i:i+2] for i in range(-2, len(hexInput), 2))
        print outputString
    else:
        print 'Not supported output format'


if __name__ == '__main__':
    main()
