import struct
import pefile
import hashlib
from colorama import Fore,Style,init

"""
Author: Axel Dominguez-Cruz
"""


init(autoreset=True) # So we dont have to keep writing Style.RESET_ALL after every print

# As always when you deal with binary info you need to account for endianness
# Windows memory dumps are all little endian

# Input the filePath
filePath = input("Please Enter The Path of The Memory Dump: ")

# This function calculates the hash of the pe file in memory...it most likely doesnt match the original disk hash
def calcHash(data,offset,size):

    if(offset + size > len(data)):
        print(f"{Fore.YELLOW}    [!] Incomplete PE...hash may be incomplete.")
        pe_data = data[offset:]
        hash = hashlib.sha256(pe_data).hexdigest()
        return hash
    else:
        pe_data = data[offset:offset + size]
        hash = hashlib.sha256(pe_data).hexdigest()
        return hash


# Function to parse the PE File with the pefile library. Doing it manually has a lot of edge cases.
def parsePE(data,offset):
    # This might fail so we should account for that...
    try:
        # Parse the PE file from the MZ offset. fast_load allows us to parse only the headers (its quicker) 
        pe = pefile.PE(data=data[offset:], fast_load=True)
        # This loads data directories that we need for the export functionality
        try:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']])
        except Exception as e:
            print(f"{Fore.YELLOW}   [!] Failed to parse export table: {e}")
        return pe
    except pefile.PEFormatError:
        return None

# Ask if you want to dump the PEs to .bin files in your directory
dumpPE = input("Would you like to dump the PE? Y/N ")
dumpPEbool = False

if (dumpPE == "Y" or dumpPE == "y"):
    dumpPEbool = True



# We need to open the memory dump and read into it in chunks
with open(filePath, 'rb') as f:

    globalOffset = 0

    data = f.read()
    if not data:
        print(f"{Fore.RED}No Data Found! Exiting...")
        exit()

    for offset in range(0, len(data)):
        # Checks for the MZ bytes
        if(data[offset:offset+2] == b'MZ'):

            absoluteMZAddr = offset
            # find the PE header offset (e_lfanew) which is at offset+0x3c
            # First make some checks to make sure we can read the entire 4 bytes at e_lfanew
            if(offset + 0x3C + 4 > len(data)):
                continue
            
            # This gets the offset relative to the start of the file (Start of the file being MZ)
            e_lfanew = struct.unpack('<I', data[offset+0x3C : offset+0x3C+4])[0]
            # To calculate the Absolute Offset of the PE file
            pe_offset = offset + e_lfanew
            
            # This is the area in which the script can always improve by adding more functionaly and parsing.

            # Lets check to see if e_lfanew has a real value and is not being manipulated
            if(pe_offset +4 > len(data) or e_lfanew < 0x40):
                continue
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                # doesnt contain the header we are looking for
                continue

            peData = parsePE(data,offset)
            # If peData exists lets analyze closer
            if peData:
                imageBase = peData.OPTIONAL_HEADER.ImageBase
                # size of PE file
                sizeOfPE = peData.OPTIONAL_HEADER.SizeOfImage
                # Is it a DLL or just a regular executable? DLL has to go first since its also an executable image.
                fileType = peData.FILE_HEADER.Characteristics
                # There is definitely room for improvement here since there are more values we can find in the characteristics
                # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
                if(fileType & 0x2000):
                    fileTypeStr = "DLL File"
                elif(fileType & 0x0002):
                    fileTypeStr = "Executable Image"
                else:
                    fileTypeStr = "Unknown"
                exports = []
                # check if PE file has an export table and put them on the above list
                if hasattr(peData, 'DIRECTORY_ENTRY_EXPORT'):
                    for s in peData.DIRECTORY_ENTRY_EXPORT.symbols:
                        if s.name:
                            exports.append(s.name.decode(errors='ignore'))
                

                print(f"\n[+] PE found at 0x{absoluteMZAddr:X}")
                print(f"    ImageBase:  0x{imageBase:X}")
                if (imageBase < 0x100000):
                    # ImageBase being less then 0x100000 isnt common and might mean injection/manual mapping
                    print(f"    {Fore.RED}[!] Suspicious imageBase is loaded at a memory address less than 0x100000!")
                print(f"    Exports:    {exports}")
                print(f"    File Type: {fileTypeStr}")
                print(f"    Sha256 Hash:    {calcHash(data,absoluteMZAddr,sizeOfPE)}")

                # Dumps the PEs to local .bin files in the directory in which the script is run in.
                if(dumpPEbool):
                    with open(f"dump_{absoluteMZAddr:X}.bin", 'wb') as dump:
                        dump.write(data[absoluteMZAddr:absoluteMZAddr+sizeOfPE])
                
                
    globalOffset += len(data)
