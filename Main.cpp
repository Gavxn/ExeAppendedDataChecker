#include <memory>
#include <vector>
#include <iostream>
#include <fstream>

const uint32_t directory_count = 16;
const uint32_t section_name_size = 8;
const uint16_t ordinal_flag_x86 = 0x014C;
const uint16_t ordinal_flag_x64 = 0x8664;

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
    uint32_t signature;
    CoffHeader *coff_header;
    OptionalHeaderX86 *optional_header_x64;
} NtHeadersX64;

typedef struct {
    uint32_t signature;
    CoffHeader *coff_header;
    OptionalHeaderX64 *optional_header_x86;
} NtHeadersX86;

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

    if (!file_stream.is_open()) {
        std::cout << "Could not open file." << std::endl;
        return 1;
    }

    std::vector<char> file_buffer;
    std::streamsize size = file_stream.tellg();
    file_stream.seekg(0, std::ios::beg);

    if (size <= 0) {
        std::cout << "Could not get file size." << std::endl;
        return 1;
    }

    file_buffer.resize((uint32_t) size);

    if (!file_stream.read(file_buffer.data(), size)) {
        std::cout << "Could not get file size." << std::endl;
        return 1;
    }

    const auto *raw_buffer = file_buffer.data();

    // Portable Executable headers
    auto dos_header = (PIMAGE_DOS_HEADER) raw_buffer;
    auto nt_header = (PIMAGE_NT_HEADERS) &raw_buffer[dos_header->e_lfanew];
    auto file_header = (PIMAGE_FILE_HEADER) &nt_header->FileHeader;

    if (dos_header->e_magic != 0x5A4D) {
        std::cout << "DOS header is corrupt." << std::endl;
        return 1;
    }

    // Bit of a hack to allow x86 to
    // get size of x64 and vise-versa
    // x86 IMAGE_NT_HEADERS is 248 bytes
    // x64 IMAGE_NT_HEADERS is 264 bytes
    uint32_t mode_adjust = 0;

    // Detect type of executable size
    switch (file_header->Machine) {
        case (IMAGE_FILE_MACHINE_I386):
#if _X64
            mode_adjust = -16;
#endif
            std::cout << "Executable is x86." << std::endl;
            break;
        case (IMAGE_FILE_MACHINE_AMD64):
#if _X86
            mode_adjust = 16;
#endif
            std::cout << "Executable is x64." << std::endl;
            break;
        case (IMAGE_FILE_MACHINE_IA64):
            std::cout << "Cannot interpret IA-64 executables." << std::endl;
            return 1;
        default:
            std::cout << "Unknown executable target architecture." << std::endl;
            return 1;
    }

    // We need to get the offset for where the NT headers
    // begin and add their size to get the first section offset
    uint32_t first_section_offset = dos_header->e_lfanew + sizeof(IMAGE_NT_HEADERS) + mode_adjust;
    auto last_section = (PIMAGE_SECTION_HEADER) &raw_buffer[first_section_offset + (file_header->NumberOfSections - 1) *
                                                                                   sizeof(IMAGE_SECTION_HEADER)];

    uint32_t image_size = last_section->PointerToRawData + last_section->SizeOfRawData;
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