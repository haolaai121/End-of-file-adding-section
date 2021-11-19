import pefile

# size is not optional, it is required to be calculated from the alignment
# the return value is a multiple of alignment
# - 1 is used in case that the value of size is a multiple of alignment
def align(size, alignment):
    return ((size + alignment - 1) // alignment) * alignment


def push_section(pe, rawsize, virtualsize=0):
    print("*" * 10 + " PUSH " + "*" * 10)
    try:
        if not type(rawsize) is int or not type(virtualsize) is int or rawsize <= 0 or rawsize <= 0:
            raise TypeError
    except TypeError:
        pass

    if not virtualsize:
        virtualsize = rawsize


    # STEP 0x01 - Add the New Section Header
    print("[*] STEP 0x01 - Add the New Section Header")


    # Get total of sections in PE file
    try:
        number_of_section = pe.FILE_HEADER.NumberOfSections
    except AttributeError:
        pass

    last_section = number_of_section - 1

    # Get memory alignment after being loaded into main memory
    file_alignment = pe.OPTIONAL_HEADER.FileAlignment
    # Get memory alignment of Pe file on disk
    section_alignment = pe.OPTIONAL_HEADER.SectionAlignment

    # get aligned section size that is valid to be put in main memory
    raw_size = align(rawsize, file_alignment)
    raw_offset = align((pe.sections[last_section].PointerToRawData +
                        pe.sections[last_section].SizeOfRawData),
                       file_alignment)

    # get aligned section size that is valid to be put on disk
    virtual_size = align(virtualsize, section_alignment)
    virtual_offset = align((pe.sections[last_section].VirtualAddress +
                            pe.sections[last_section].Misc_VirtualSize),
                           section_alignment)

    # this is a flag, show the actions which is offered by this section (0xE0000020 is readable, writable, executable)
    characteristics = 0xE0000020

    # Section name, mandatory size is 8 bytes
    name = b".axc" + (4 * b"\x00")

    # get offset of current last section header, then add 40 (size of each pe section header is 40 bytes)
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
    # size of Image equals to the "end" virtual address of the last section header
    pe.OPTIONAL_HEADER.SizeOfImage = virtual_size + virtual_offset
    print("\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage)



def pop_section(pe):
    print("*" * 10 + " POP " + "*" * 10)

    count = len(pe.sections)

    if not count:
        return

    # Remove the specified data from raw data of section on disk
    # by reassigning all data from other sections to the total data except the last one

    print("[*] STEP 0x01 - Delete specified raw data of the section")

    try:
        pe.__data__ = pe.__data__[:pe.sections[count - 1].PointerToRawData] + \
                      pe.__data__[(pe.sections[count - 1].PointerToRawData + \
                                   pe.sections[count - 1].SizeOfRawData):]

    except AttributeError:
        pass

    print("[*] STEP 0x02 - Adjust parameters")

    del pe.sections[count - 1]

    # total of section apparently is increased by 1
    pe.FILE_HEADER.NumberOfSections -= 1
    print("\t[+] Number of Sections = %s" % pe.FILE_HEADER.NumberOfSections)
    # size of Image equals to the "end" virtual address of the last section header
    pe.OPTIONAL_HEADER.SizeOfImage = pe.sections[count - 2].VirtualAddress + pe.sections[count - 2].Misc_VirtualSize
    print("\t[+] Size of Image = %d bytes" % pe.OPTIONAL_HEADER.SizeOfImage)




if __name__ == "__main__":
    in_path = "putty.exe"
    out_path_appended = "putty_appended.exe"
    out_path_subtracted = "putty_subtracted.exe"

    pe = pefile.PE(in_path)
    push_section(pe, 4096)
    pe.write(out_path_appended)

    pe = pefile.PE(in_path)
    pop_section(pe)
    pe.write(out_path_subtracted)