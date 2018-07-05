#include <memory>
#include <vector>
#include <iostream>
#include <fstream>

const uint32_t directory_count = 16;
const uint32_t section_name_size = 8;
const uint16_t x86 = 0x014C;
const uint16_t x64 = 0x8664;
const uint16_t dos_signature = 0x5A4D;

typedef struct {
    uint8_t e_magic[2];
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t e_lfanew;
} DosHeader;

typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t sizeof_optional_header;
    uint16_t characteristics;
} CoffHeader;

typedef struct {
    uint32_t virtual_address;
    uint32_t Size;
} DataDirectory;

typedef struct {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t sizeof_initialized_data;
    uint32_t sizeof_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    // extensions
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t sizeof_image;
    uint32_t sizeof_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t sizeof_stack_reserve;
    uint32_t sizeof_stack_commit;
    uint32_t sizeof_heap_reserve;
    uint32_t sizeof_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    DataDirectory data_directory[directory_count];
} OptionalHeaderX86;

typedef struct {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t sizeof_code;
    uint32_t sizeof_initialized_data;
    uint32_t sizeof_uninitialized_data;
    uint32_t address_of_entry_point;
    // extensions
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t sizeof_stack_reserve;
    uint64_t sizeof_stack_commit;
    uint64_t sizeof_heap_reserve;
    uint64_t sizeof_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    DataDirectory data_directory[directory_count];
} OptionalHeaderX64;

typedef struct {
    uint8_t name[section_name_size];
    union {
        uint32_t physical_address;
        uint32_t virtual_size;
    } Misc;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_line_numbers;
    uint16_t number_of_relocations;
    uint16_t number_of_line_numbers;
    uint32_t characteristics;
} SectionHeader;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "No file path provided." << std::endl;
        return 0;
    }

    std::ifstream file_stream(argv[1], std::ios::binary | std::ios::ate);

    if (!file_stream.is_open() || file_stream.fail()) {
        std::cout << "Could not open file." << std::endl;
        return 1;
    }

    std::vector<char> file_buffer;
    std::streamsize size = file_stream.tellg();

    if (size <= 0) {
        std::cout << "Could not get file size." << std::endl;
        return 1;
    }

    file_stream.seekg(0, std::ios::beg);
    file_buffer.resize((uint32_t) size);

    if (!file_stream.read(file_buffer.data(), size)) {
        std::cout << "Could not read file." << std::endl;
        return 1;
    }

    const auto *raw_buffer = file_buffer.data();
    auto dos_header = (DosHeader *) raw_buffer;

    uint16_t e_magic_short = ((uint16_t) dos_header->e_magic[1]) << 8;
    e_magic_short = e_magic_short | dos_header->e_magic[0];

    if (e_magic_short != dos_signature) {
        std::cout << "DOS header is corrupt." << std::endl;
        return 1;
    }

    // The 32 bit value is the NT signature (signature, then COFF header, finally optional header)
    auto coff_header = (CoffHeader *) &raw_buffer[dos_header->e_lfanew + sizeof(uint32_t)];
    // This points to the optional header
    uint32_t first_section_offset = dos_header->e_lfanew + sizeof(uint32_t) + sizeof(*coff_header);

    // Detect type of executable size and skip the optional header
    switch (coff_header->machine) {
        case (x86):
            std::cout << "Executable is x86." << std::endl;
            first_section_offset += sizeof(OptionalHeaderX86);
            break;
        case (x64):
            first_section_offset += sizeof(OptionalHeaderX64);
            std::cout << "Executable is x64." << std::endl;
            break;
        default:
            std::cout << "Unknown executable target architecture." << std::endl;
            return 1;
    }

    auto offset = first_section_offset + ((coff_header->number_of_sections - 1) * sizeof(SectionHeader));
    auto last_section = (SectionHeader *) &raw_buffer[offset];

    uint32_t image_size = last_section->pointer_to_raw_data + last_section->size_of_raw_data;
    uint64_t appended_data_size = file_buffer.size() - image_size;

    if (appended_data_size > 0) {
        std::cout << "Executable file has data appended to it." << std::endl;
    } else {
        std::cout << "Executable file does not have any data appended to it." << std::endl;
    }

    std::cout << "Executable file size: " << file_buffer.size() << " bytes." << std::endl
              << "Executable image size: " << image_size << " bytes." << std::endl
              << "Appended data size: " << appended_data_size << " bytes." << std::endl;

    return 0;
}
