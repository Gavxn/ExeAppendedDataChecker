#include <memory>
#include <vector>
#include <iostream>
#include <fstream>
#include <windows.h>

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