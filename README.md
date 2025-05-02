# PE-Hunter

# Design Process

- My goal for this project is to be able to parse memory dumps for PE files and using the pefile library we can get specific information from those PE files to see if any malicious indicators are there.
- All PE files start with a 64-byte **IMAGE_DOS_HEADER** that contains a magic number **MZ** followed by a pointer to the PE headers offset called **e_lfanew** which is 58 bytes after the first 2 that hold the magic number. 
	- The e_lfanew field specifies the file offset of the PE header. Its the logical file address for the New Executable header. This doesnt mean that the value given here is the absolute address in the memory dump. It means its relative to the start of the file which is where the MZ was found.
	- This field can be corrupted by malware and other things. We need to have basic checks like making sure that the fields value is over 0x40 (64 bytes) since the PE file is guaranteed to be 64 bytes due to the **IMAGE_DOS_HEADER** at the start.
- Scan memory dump for b'MZ' and then go to the offset+0x3c to find the **e_lfanew**. 
- Add the value of **e_lfanew** to our offset to find the PE header
- use pefile library to parse PE files fully. The reasoning for this is because PE files can be complex. There are 32-bit vs 64-bit, alignment issues, weird sections and optional fields make this complicated and honestly out of scope for what im trying to accomplish.
	- https://pefile.readthedocs.io/en/latest/modules/pefile.html
- Items of interest in our parse PE file:
	- PE Exports: Functions or symbols a DLL (sometimes EXE) makes available to other programs
	- Low ImageBase number: a low imagebase number is atypical for legitimate modules and may indicate manual mapping or code injection techniques, such as reflective DLL injection
	- SHA256 Hash: Take the hash of the PE File -> Needs more testing
	- File type: Use **FILE_HEADER.Characteristics** to find the file type
		- https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header
