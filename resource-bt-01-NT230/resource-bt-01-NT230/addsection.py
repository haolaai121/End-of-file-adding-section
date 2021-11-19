import pefile
import mmap
import os
#define a function to quickly align our values
def align(val_to_align, alignment):
    return ((val_to_align + alignment - 1) / alignment) * alignment

def AddSection(exe_pathfile):
	try:
		pe = pefile.PE(exe_pathfile)
	except OSError as e:
		print(e)
	except pefile.PEFormatError as e:
		print("[-] PEFormatError: %s" % e.value)

    #get the number of section and the last section information
	number_of_section = pe.FILE_HEADER.NumberOfSections
	last_section = number_of_section - 1
	#file alignment number is 512
	file_alignment = pe.OPTIONAL_HEADER.FileAlignment
	#section alignment number is 4096
	section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
	#a section header has 40 bytes size, so we add 40 more bytes to create a new section
	new_section_offset = (pe.sections[number_of_section - 1].get_file_offset() + 40)

	# Look for valid values for the new section header
	raw_size = align(0x1000, file_alignment)
	virtual_size = align(0x1000, section_alignment)
	#we calculate the raw offset of the new section by adding the size of the last section on the disk with its offset 
	raw_offset = align(pe.sections[last_section].PointerToRawData + pe.sections[last_section].SizeOfRawData, file_alignment)
	#we calculate the virtual offset of the new section by adding the size of the last section in the memory with its relative address
	virtual_offset = align(pe.sections[last_section].VirtualAddress + pe.sections[last_section].Misc_VirtualSize, section_alignment)

	#give the characteristics for the new section
	#CODE | EXECUTE | READ | WRITE
	characteristics=0xE0000020 
	#Give the new section name, which must be equal to 8 bytes
	name = ".axc" + (4* '\x00')
	#create the new section
	pe.set_bytes_at_offset(new_section_offset, name)
	# Set the virtual size
	pe.set_dword_at_offset(new_section_offset + 8, virtual_size)
	# Set the virtual offset
	pe.set_dword_at_offset(new_section_offset + 12, virtual_offset)
	# Set the raw size
	pe.set_dword_at_offset(new_section_offset + 16, raw_size)
	# Set the raw offset
	pe.set_dword_at_offset(new_section_offset + 20, raw_offset)
	# Set the following fields to zero
	pe.set_bytes_at_offset(new_section_offset + 24, (12 * '\x00'))
	# Set the characteristics
	pe.set_dword_at_offset(new_section_offset + 36, characteristics)
	 # Set the virtual size
   


exe_file="putty.exe"
AddSection(exe_file)