#define WIN32_LEAN_AND_MEAN
#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include <windows.h>
#include <imagehlp.h>

std::string getError() {
    char *pBuffer = nullptr;
    DWORD dwSize = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr, GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<char*>(&pBuffer), 0, nullptr);

    if (dwSize > 0) {
        return std::string(pBuffer, dwSize);
        LocalFree(pBuffer);
    }

    return std::string("Unable to fetch error message");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cout << "Quitting: no file path provided." << std::endl;
        return 0;
    }

    HANDLE hExeFile = CreateFile(argv[1],
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        0, nullptr);

    if (hExeFile == INVALID_HANDLE_VALUE) {
        std::cout << "Error: cannot open file. " << getError() << std::endl;
        return 1;
    }

    DWORD dwFileSize = GetFileSize(hExeFile, nullptr);

    if (dwFileSize == INVALID_FILE_SIZE) {
        std::cout << "Error: cannot retrieve file size. " << getError() << std::endl;
        return 1;
    }

    if (SetFilePointer(hExeFile, 0, nullptr, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
        std::cout << "Error: cannot move file pointer. " << getError() << std::endl;
        return 1;
    }

    std::vector<char> fileBuffer(dwFileSize);

    if (!ReadFile(hExeFile, fileBuffer.data(), sizeof(char) * dwFileSize, nullptr, nullptr)) {
        std::cout << "Error: cannot read file. " << getError() << std::endl;
        return 1;
    }

    char *pFileBuffer = fileBuffer.data();

    // Portable Executable headers
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)&pFileBuffer[pDosHeader->e_lfanew];
    PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)&pNtHeader->FileHeader;

    // Bit of a hack to allow x86 to
    // get size of x64 and vise-versa
    // x86 IMAGE_NT_HEADERS is 248 bytes
    // x64 IMAGE_NT_HEADERS is 264 bytes
    DWORD dwExpanded = 0;

    // Detect type of executable size
    switch (pFileHeader->Machine) {
    case(IMAGE_FILE_MACHINE_I386):
#if _X64
        dwExpanded = -16;
#endif
        std::cout << "Executable is x86." << std::endl;
        break;
    case(IMAGE_FILE_MACHINE_AMD64):
#if _X86
        dwExpanded = 16;
#endif
        std::cout << "Executable is x64." << std::endl;
        break;
    case(IMAGE_FILE_MACHINE_IA64):
        std::cout << "Quitting: Cannot interpret IA-64 executables." << std::endl;
        return 0;
    }

    // We need to get the offset for where the NT headers
    // begin and add their size to get the first section offset
    DWORD dwFirstSectionOffset = pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + dwExpanded;
    PIMAGE_SECTION_HEADER pLastSection = (PIMAGE_SECTION_HEADER)&pFileBuffer[dwFirstSectionOffset + (pFileHeader->NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER)];

    DWORD dwImageSize = pLastSection->PointerToRawData + pLastSection->SizeOfRawData;
    DWORD dwAppendedDataSize = dwFileSize - dwImageSize;

    if (dwAppendedDataSize > 0) {
        std::cout << "Executable file has data appended to it." << std::endl;
    } else {
        std::cout << "Executable file does not have any data appended to it." << std::endl;
    }

    std::cout << "Executable file size: " << dwFileSize << " bytes." << std::endl;
    std::cout << "Executable image size: " << dwImageSize << " bytes." << std::endl;
    std::cout << "Appended data size: " << dwAppendedDataSize << " bytes." << std::endl;

    return 0;
}