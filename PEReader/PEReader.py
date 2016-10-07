#!/usr/bin/python

import sys
import struct

PEHeaderFields = {
    'COFFHeader': {
        'Signature': {
            'offset': 0x0,
            'length': 0x4
        },
        'Machine': {
            'offset': 0x4,
            'length': 0x2
        },
        'NumberOfSections': {
            'offset': 0x6,
            'length': 0x2
        },
        'Timestamp': {
            'offset': 0x8,
            'length': 0x4
        },
        'PointerToSymbolTable': {
            'offset': 0xc,
            'length': 0x4
        },
        'NumberOfSymbolTable': {
            'offset': 0x10,
            'length': 0x4
        },
        'SizeOfOptionalHeader': {
            'offset': 0x14,
            'length': 0x2
        },
        'Characteristics': {
            'offset': 0x16,
            'length': 0x2
        }
    },
    'StandardCOFFFields': {
        'Magic': {
            'offset': 0x18,
            'length': 0x2
        },
        'MajorLinkerVersion': {
            'offset': 0x1a,
            'length': 0x1
        },
        'MinorLinkerVersion': {
            'offset': 0x1b,
            'length': 0x1
        },
        'SizeOfCode': {
            'offset': 0x1c,
            'length': 0x4
        },
        'SizeOfInitializedData': {
            'offset': 0x20,
            'length': 0x4
        },
        'SizeOfUninitializedData': {
            'offset': 0x24,
            'length': 0x4
        },
        'AddressOfEntryPoint': {
            'offset': 0x28,
            'length': 0x4
        },
        'BaseOfCode': {
            'offset': 0x2c,
            'length': 0x4
        },
        'BaseOfData': {
            'offset': 0x30,
            'length': 0x4
        }
    },
    'WindowsFields': {
        'ImageBase': {
            'offset': 0x34,
            'length': 0x4
        },
        'SectionAlignment': {
            'offset': 0x38,
            'length': 0x4
        },
        'FileAlignment': {
            'offset': 0x3c,
            'length': 0x4
        },
        'MajorOperatingSystemVersion': {
            'offset': 0x40,
            'length': 0x2
        },
        'MinorOperatingSystemVersion': {
            'offset': 0x42,
            'length': 0x2
        },
        'MajorImageVersion': {
            'offset': 0x44,
            'length': 0x2
        },
        'MinorImageVersion': {
            'offset': 0x46,
            'length': 0x2
        },
        'MajorSubsystemVersion': {
            'offset': 0x48,
            'length': 0x2
        },
        'MinorSubsystemVersion': {
            'offset': 0x4a,
            'length': 0x2
        },
        'Win32VersionValuw': {
            'offset': 0x4c,
            'length': 0x4
        },
        'SizeOfImage': {
            'offset': 0x50,
            'length': 0x4
        },
        'SizeOfHeaders': {
            'offset': 0x54,
            'length': 0x4
        },
        'Checksum': {
            'offset': 0x58,
            'length': 0x4
        },
        'Subsystem': {
            'offset': 0x5c,
            'length': 0x2
        },
        'DLLCharacteristics': {
            'offset': 0x5e,
            'length': 0x2
        },
        'SizeOfStackReserve': {
            'offset': 0x60,
            'length': 0x4
        },
        'SizeOfStackCommit': {
            'offset': 0x64,
            'length': 0x4
        },
        'SizeOfHeapReserve': {
            'offset': 0x68,
            'length': 0x4
        },
        'SizeOfHeapCommit': {
            'offset': 0x6c,
            'length': 0x4
        },
        'LoaderFlags': {
            'offset': 0x70,
            'length': 0x4
        },
        'NumberOfRVAAndSizes': {
            'offset': 0x74,
            'length': 0x4
        }
    },
    'DataDirectories': {
        'ExportTable': {
            'offset': 0x78,
            'length': 0x4
        },
        'SizeOfExportTable': {
            'offset': 0x7c,
            'length': 0x4
        },
        'ImportTable': {
            'offset': 0x80,
            'length': 0x4
        },
        'SizeOfImportTable': {
            'offset': 0x84,
            'length': 0x4
        },
        'ResourceTable': {
            'offset': 0x88,
            'length': 0x4
        },
        'SizeOfResourceTable': {
            'offset': 0x8c,
            'length': 0x4
        },
        'ExceptionTable': {
            'offset': 0x90,
            'length': 0x4
        },
        'SizeOfExceptionTable': {
            'offset': 0x94,
            'length': 0x4
        },
        'CertificateTable': {
            'offset': 0x98,
            'length': 0x4
        },
        'SizeOfCertificateTable': {
            'offset': 0x9c,
            'length': 0x4
        },
        'BaseRelocationTable': {
            'offset': 0xa0,
            'length': 0x4
        },
        'SizeOfBaseRelocationTable': {
            'offset': 0xa4,
            'length': 0x4
        },
        'Debug': {
            'offset': 0xa8,
            'length': 0x4
        },
        'SizeOfDebug': {
            'offset': 0xac,
            'length': 0x4
        },
        'ArchitectureData': {
            'offset': 0xb0,
            'length': 0x4
        },
        'SizeOfArchitectureData': {
            'offset': 0xb4,
            'length': 0x4
        },
        'GlobalPtr': {
            'offset': 0xb8,
            'length': 0x4
        },
        'GlobalPtrNullBytes': {
            'offset': 0xbc,
            'length': 0x4
        },
        'TLSTable': {
            'offset': 0xc0,
            'length': 0x4
        },
        'SizeOfTLSTable': {
            'offset': 0xc4,
            'length': 0x4
        },
        'LoadConfigTable': {
            'offset': 0xc8,
            'length': 0x4
        },
        'SizeOfLoadConfigTable': {
            'offset': 0xcc,
            'length': 0x4
        },
        'BoundImport': {
            'offset': 0xd0,
            'length': 0x4
        },
        'SizeOfBoundImport': {
            'offset': 0xd4,
            'length': 0x4
        },
        'ImportAddressTable': {
            'offset': 0xd8,
            'length': 0x4
        },
        'SizeOfImportAddressTable': {
            'offset': 0xdc,
            'length': 0x4
        },
        'DelayImportDescriptor': {
            'offset': 0xe0,
            'length': 0x4
        },
        'SizeOfDelayImportDescriptor': {
            'offset': 0xe4,
            'length': 0x4
        },
        'CLRRuntimeHeader': {
            'offset': 0xe8,
            'length': 0x4
        },
        'SizeOfCLRRuntimeHeader': {
            'offset': 0xec,
            'length': 0x4
        },
        'FinalNULLDWORD': {
            'offset': 0xf0,
            'length': 0x8
        }
    },
    'SectionTable': {
        'Name': {
            'offset': 0x0,
            'length': 0x8
        },
        'VirtualSize': {
            'offset': 0x8,
            'length': 0x4
        },
        'VirtualAddress': {
            'offset': 0xc,
            'length': 0x4
        },
        'SizeOfRawData': {
            'offset': 0x10,
            'length': 0x4
        },
        'PointerToRawData': {
            'offset': 0x14,
            'length': 0x4
        },
        'PointerToRelocations': {
            'offset': 0x18,
            'length': 0x4
        },
        'PointerToLineNumbers': {
            'offset': 0x1c,
            'length': 0x4
        },
        'NumberOfRelocations': {
            'offset': 0x20,
            'length': 0x2
        },
        'NumberOfLineNumbers': {
            'offset': 0x22,
            'length': 0x2
        },
        'Characteristics': {
            'offset': 0x24,
            'length': 0x4
        }
    }
}

preHeaderInfo = ''
DOSHeader = ''
PEHeader = ''
Sections = {}

def main():
    if len(sys.argv) != 2:
        printUsage()
        sys.exit()

    fileName = sys.argv[1]

    PEHeaderFieldLength = getLengthOfHeaders('*')
    COFFHeaderFieldLength = getLengthOfHeaders('COFFHeader')
    StandardCOFFFieldsFieldLength = getLengthOfHeaders('StandardCOFFFields')
    WindowsFieldsFieldLength = getLengthOfHeaders('WindowsFields')
    DataDirectoriesFieldLength = getLengthOfHeaders('DataDirectories')
    SectionsFieldLength = getLengthOfHeaders('SectionTable')

    #print PEHeaderFieldLength, COFFHeaderFieldLength, StandardCOFFFieldsFieldLength, WindowsFieldsFieldLength, DataDirectoriesFieldLength, SectionsFieldLength

    global preHeaderInfo
    global DOSHeader
    global PEHeader
    COFFHeader = ''
    StandardCOFFFields = ''
    WindowsFields = ''
    DataDirectories = ''
    global Sections

    with open(fileName, 'rb') as f:
        preHeaderInfo = readUntil(f, 'MZ')
        DOSHeader = readUntil(f, 'PE')
        PEHeader = f.read(PEHeaderFieldLength)
        f.seek(0 - PEHeaderFieldLength, 1)
        COFFHeader = f.read(COFFHeaderFieldLength)
        StandardCOFFFields = f.read(StandardCOFFFieldsFieldLength)
        WindowsFields = f.read(WindowsFieldsFieldLength)
        DataDirectories = f.read(DataDirectoriesFieldLength)
        numberOfSections = getPEHeaderValue('COFFHeader', 'NumberOfSections')
        for s in range(getInt(numberOfSections)):
            sectionNameLength = PEHeaderFields['SectionTable']['Name']['length']
            name = f.read(sectionNameLength)
            Sections[name.strip('\0')] = name + f.read(SectionsFieldLength - sectionNameLength)
        f.close()

    print 'PreHeaderInfo:', preHeaderInfo
    print 'DOSHeader:', DOSHeader
    print 'PEHeader:', PEHeader
    
    print 'Possible Maximum of PEHeader 0x%X' % PEHeaderFieldLength
    print 'SizeOfOptionalHeader', '0x' + getPEHeaderValue('COFFHeader', 'SizeOfOptionalHeader').encode('hex')
    #print 'Signature', '0x' + getPEHeaderValue('COFFHeader', 'Signature').encode('hex')
    print 'NumberOfSections', '0x' + numberOfSections.encode('hex')
    print 'Magic', '0x' + getPEHeaderValue('StandardCOFFFields', 'Magic').encode('hex')
    print 'Timestamp', '0x' + getPEHeaderValue('COFFHeader', 'Timestamp').encode('hex')
    print 'Address of Entry Point Header: 0x%s' % getPEHeaderValue('StandardCOFFFields', 'AddressOfEntryPoint').encode('hex')
    print 'PointerToRawData of .text: 0x%s' % getSectionHeaderValue('.text', 'PointerToRawData').encode('hex')
    print 'VirtualAddresss of .text: 0x%s' % getSectionHeaderValue('.text', 'VirtualAddress').encode('hex')
    print 'Address of Raw Entry Point: 0x%X' % calculateRawEntryPointAddress()

    exeFile, nonRelocatable, dllFile = getCharacteristics()
    print 'Characteristics:\n\tIs EXE File: %s\n\tFile is Non-Relocatable (addresses are absolute, not RVA): %s\n\tIs DLL File: %s' % (exeFile, nonRelocatable, dllFile)

    canASLR, canDEP = getSecAttributes()
    print 'Security Attributes:\n\tCan ASLR: %s\n\tCan DEP: %s' % (canASLR, canDEP)

    print 'Sections:'
    for sectionName in Sections:
        print '%s\n\t%s' % (sectionName, Sections[sectionName].encode('hex'))
        if sectionName == '.text':
            printSectionInfo('.text')

def readUntil(f, seq):
    bYtes = ""
    b = f.read(1)
    while b != "":
        bYtes = bYtes + b
        #print bYtes[-len(seq):].encode('hex'), seq.encode('hex')
        if len(bYtes) >= len(seq) and bYtes[-len(seq):] == seq:
            bYtes = bYtes[:-2]
            f.seek(-2, 1) # seek -2 from current pointer (1)
            break
        else:
            b = f.read(1)

    return bYtes

def getPEHeaderValue(subHeader, field):
    global PEHeader
    h = PEHeaderFields[subHeader][field]
    return PEHeader[h['offset']:h['offset'] + h['length']][::-1] # reverse bytes

def getSectionHeaderValue(name, field):
    global Sections
    h = PEHeaderFields['SectionTable'][field]
    return Sections[name][h['offset']:h['offset'] + h['length']][::-1] # reverse bytes

def getLengthOfHeaders(which):
    length = 0
    for subHeaderFields in PEHeaderFields:
        #print subHeaderFields
        if subHeaderFields == which or (which == '*' and subHeaderFields != 'SectionTable'):
            for header in PEHeaderFields[subHeaderFields]:
                #print header
                length = length + PEHeaderFields[subHeaderFields][header]['length']

    return length

def getSecAttributes():
    DLLAttributes = getPEHeaderValue('WindowsFields', 'DLLCharacteristics')
    #print type(DLLAttributes), bytes(DLLAttributes), bytearray(DLLAttributes), DLLAttributes, DLLAttributes.encode('hex'), struct.unpack('H', DLLAttributes), struct.unpack('H', DLLAttributes)[0]
    canASLR = getInt(DLLAttributes) & 0x40 and True # '>H' for unsigned short, already big-endian
    canDEP = getInt(DLLAttributes) & 0x100 and True # '>H' for unsigned short, already big-endian
    return canASLR, canDEP

def getCharacteristics():
    characteristics = getPEHeaderValue('COFFHeader', 'Characteristics')
    #print type(characteristics), characteristics, characteristics.encode('hex'), struct.unpack('>H', characteristics), struct.unpack('>H', characteristics)[0]
    exeFile = getInt(characteristics) & 0x02 and True # '>H' for unsigned short, already big-endian
    nonRelocatable = getInt(characteristics) & 0x200 and True # '>H' for unsigned short, already big-endian
    dllFile = getInt(characteristics) & 0x2000 and True # '>H' for unsigned short, already big-endian
    return exeFile, nonRelocatable, dllFile

def calculateRawEntryPointAddress():
    # AddressOfEntryPoint + .text[PointerToRawData] - .text[VirtualAddress]
    return getInt(getPEHeaderValue('StandardCOFFFields', 'AddressOfEntryPoint')) + getInt(getSectionHeaderValue('.text', 'PointerToRawData')) - getInt(getSectionHeaderValue('.text', 'VirtualAddress'))

def printSectionInfo(name):
    global Sections
    data = Sections[name]
    for header in PEHeaderFields['SectionTable']:
        h = PEHeaderFields['SectionTable'][header]
        print '\t\t%s: %x' % (header, getInt(data[h['offset']:h['offset'] + h['length']][::-1]))


def getInt(binaryData):
    l = len(binaryData)
    if l == 1:
        f = 'B' # 'B' for unsigned char
    elif l == 2:
        f = 'H' # 'H' for unsigned short
    elif l == 4:
        f = 'I' # 'I' for unsigned int
    elif l == 8:
        f = 'Q' # 'Q' for unsigned long long
    else:
        print 'Error..binary data passed to getInt is too long or too short..'
        sys.exit()
    return struct.unpack('>' + f, binaryData)[0] # '>' because data already big-endian

def printUsage():
    print 'Usage is...\n$ PEReader.py binfile.exe'

if __name__ == '__main__':
    main()
