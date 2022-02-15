#include <stdio.h>
#include <string.h>
#include <windows.h>

#include "lib/aes.h"
#include "lib/b64.h"

#define DEBUG 1

PVOID readFile(char *filename) {
    HANDLE hFile;
    PVOID fileContent = NULL;
    SIZE_T sizeBuffer = 0;
    DWORD dwSuccess = 0, dwRead = 0;

    hFile = CreateFileA((LPCSTR)filename, // file to open
        GENERIC_READ,                     // open for reading
        FILE_SHARE_READ,                  // share for reading
        NULL,                             // default security
        OPEN_EXISTING,                    // existing file only
        FILE_ATTRIBUTE_NORMAL,            // normal file
        NULL);                            // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", (char*)filename);
        return NULL;
    }

    sizeBuffer = GetFileSize(hFile, NULL);
    if (sizeBuffer == 0) {
        printf("[-] Error on getting file size\n");
        return NULL;
    }

    fileContent = VirtualAlloc(0, sizeBuffer, MEM_COMMIT, PAGE_READWRITE);
    if (fileContent == NULL) {
        printf("[-] Cannot allocate memory; wrong sizeBuffer?\n");
        return NULL;
    }

    dwSuccess = ReadFile(hFile, fileContent, (DWORD)sizeBuffer, &dwRead, NULL);
    if (dwSuccess == 0) {
        printf("[-] Failed to read file content.\n");
        return NULL;
    }

    CloseHandle(hFile);
    return fileContent;
}

SIZE_T readFileSize(char *filename) {
    HANDLE hFile;
    SIZE_T fileSize = 0;

    hFile = CreateFileA((LPCSTR)filename, // file to open
        GENERIC_READ,                     // open for reading
        FILE_SHARE_READ,                  // share for reading
        NULL,                             // default security
        OPEN_EXISTING,                    // existing file only
        FILE_ATTRIBUTE_NORMAL,            // normal file
        NULL);                            // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to open file: %s\n", (char*)filename);
        return 0;
    }

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == 0) {
        printf("[-] Error on getting file size\n");
        return 0;
    }

    CloseHandle(hFile);
    return fileSize;
}

void writeFile(char *filename, uint8_t *content, size_t bufferSize) {
    HANDLE hFile;
    DWORD dwBytesWritten = 0;
    BOOL bErrorFlag = FALSE;

    hFile = CreateFileA((LPCSTR)filename, // name of the file
        GENERIC_WRITE,                    // open for writing
        0,                                // do not share
        NULL,                             // default security
        CREATE_ALWAYS,                    // always override file
        FILE_ATTRIBUTE_NORMAL,            // normal file
        NULL);                            // no attr. template

    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[-] Failed to access: %s\n", (char*)filename);
        return;
    }

    bErrorFlag = WriteFile(
        hFile,           // open file handle
        content,         // start of data to write
        (DWORD)bufferSize,      // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);           // no overlapped structure

    if (FALSE == bErrorFlag) {
        printf("[-] Unable to write into file.\n");
    }

    CloseHandle(hFile);
    printf("[*] %s file created.\n", filename);
}


int main(int argc, char** argv[]) {
    struct AES_ctx ctx;
    unsigned char key[] = "\xde\xad\xbe\xef\xca\xfe\xba\xbe\xde\xad\xbe\xef\xca\xfe\xba\xbe";
    unsigned char iv[] = "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff";
    char outputName[] = "output.bin";

    if (argc != 2) {
        printf("USAGE: %s inputfile.bin", (char *)argv[0]);
        return 1;
    }

    char *filename = (char *)argv[1];

    // Read the file: content and size
    PVOID fileContent = readFile(filename);
    size_t payloadSize = readFileSize(filename);

#ifdef DEBUG
    printf("INPUT:\n\tSIZE: %zd\n\tCONTENT: %s\n", payloadSize, (char *)fileContent);
#endif // DEBUG

    // Encode the content of the file in base64
    unsigned char *plainPayload_b64 = b64_encode(fileContent, payloadSize);
    size_t plainPayloadSize_b64 = strlen(plainPayload_b64);
    
    // Encrypt the base64
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CTR_xcrypt_buffer(&ctx, (uint8_t *)plainPayload_b64, plainPayloadSize_b64);

    // Encode the encrypted string into base64
    unsigned char* encryptedPayload_b64 = b64_encode(plainPayload_b64, plainPayloadSize_b64);

#ifdef DEBUG
    printf("\nOUTPUT\n\tSIZE: %zd\n\tOUTPUT: %s\n", strlen(encryptedPayload_b64), encryptedPayload_b64);
#endif // DEBUG

    // Save the base64 to a file
    writeFile(outputName, encryptedPayload_b64, strlen(encryptedPayload_b64));

    return 0;
}