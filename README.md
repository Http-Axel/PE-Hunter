# PE-Hunter

# What does PE-Hunter do?

This script parses a Windows memory dump for PE Files. It then parses the PE files and/or dumps them into your directory. The PE file information that the script tries to find are the following:
- ImageBase: The imageBase is an address in virtual memory where the executable should be loaded at. A very low address (lower than 0x100000) is suspicious and should be investigated. The Script will warn you if it finds an ImageBase loaded at an address lower than 0x100000.
- Exports: The functions that are exposed to other modules by the binary. This could potentially give valuable information if some of the functions are named suspiciously.
- File Type: Is the file a DLL or an executable
- Sha256 Hash: This is calculated by hashing the many PE Files found in the memory dump. There are limitations here though so please see the limitations section of the README.

# Design Process

- My goal for this project is to be able to parse memory dumps for PE files and using the pefile library we can get specific information from those PE files to see if any malicious indicators are there.
- All PE files start with a 64-byte **IMAGE_DOS_HEADER** that contains a magic number **MZ** followed by a pointer to the PE headers offset called **e_lfanew** which is 58 bytes after the first 2 that hold the magic number. 
	- The e_lfanew field specifies the file offset of the PE header. It's the logical file address for the New Executable header. This doesnt mean that the value given here is the absolute address in the memory dump. It means its relative to the start of the file which is where the MZ was found.
	- This field can be corrupted by malware and other things. We need to have basic checks like making sure that the fields value is over 0x40 (64 bytes) since the PE file is guaranteed to be 64 bytes due to the **IMAGE_DOS_HEADER** at the start.
- Scan memory dump for b'MZ' and then go to the offset+0x3c to find the **e_lfanew**. 
- Add the value of **e_lfanew** to our offset to find the PE header
- use pefile library to parse PE files fully. The reasoning for this is that PE files can be complex. There are 32-bit vs 64-bit, alignment issues, weird sections, and optional fields that make this complicated and honestly out of scope for what I'm trying to accomplish.
	- https://pefile.readthedocs.io/en/latest/modules/pefile.html
- Items of interest in our parse PE file:
	- PE Exports: Functions or symbols a DLL (sometimes EXE) makes available to other programs
	- Low ImageBase number: a low imagebase number is atypical for legitimate modules and may indicate manual mapping or code injection techniques, such as reflective DLL injection
	- SHA256 Hash: Take the hash of the PE File -> Needs more testing
	- File type: Use **FILE_HEADER.Characteristics** to find the file type
		- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
 
# Usage Guide

Usage is simple, just run the script and answer the 2 input prompts. The first prompt will ask you for the path to the memory dump you are trying to read and the second prompt asks if you want the PE files dumped into your directory. 

# Limitations

Please see the following limitations of the script:

- The sha256 hash that is taken from the PE files will most likely not match with the original file hash thats on-disk.
- Modifications would have to be made to the script to account for larger memory dumps. Since this script reads the entire file into a buffer it will crash if the file is massive. For this reason, I made sure to test locally on smaller dumps rather than full memory dumps since these are as large as your RAM count which is 32GB in my case... 

# Proof that PE Dumps work

![image](https://github.com/user-attachments/assets/a1f443ff-b567-48f4-880f-c69cd22a5f1d)

# What did I learn?

Creating this project made me aware of how complex these structures can be. Parsing the PE file was not that difficult due to the pefile library doing most of the work but finding those PE files within memory dumps took some effort. I gained a solid understanding of how PE Files are formatted and the different types of headers and information that are inside of this structure. 

The reason I created this project was to get a better understanding on how memory forensics for Windows works and I think this project was a really good start. This project has some very simple checks, for example, I make sure to check the PE files ImageBase to see if it's lower than 0x100000 since this could potentially mean [manual mapping techniques](https://github.com/buzzer-re/BulletTrain?utm_source=chatgpt.com) are being used.

One more thing I took away from this project is that I now have the knowledge and interest to pursue more specific malware checks against memory that I wouldn't have thought of before.

