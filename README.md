# AESEncryptor

Windows C/C++ tool to encrypt files content (i.e. shellcodes) using AES CTR.

This tool is written with the purpose to avoid AV/EDR detection when dropping shellcodes in the target.

The usage of AES CTR is not for special security purposes but only because the algorithm CTR does not change the length of the message during the encryption/decryption. The same if for b64 encoding/decoding: because its easier to manage strings with ASCII chars during an engagement.

## Dependencies

The project uses two dependencies:

- [tiny-AES-c](https://github.com/kokke/tiny-AES-c): implements the AES algorithms
- [b64.c](https://github.com/littlstar/b64.c): implements base64 encoding algorithms

## Build and usage

Open the solution to Visual Studio (tested only on Visual Studio 2019 Community Edition) and compile the EXE in Release mode for your target architecture (x64, x86).

Then start the encryptor with the input file as parameter: `.\AESEncryptor.exe 'popcalc64.bin'`. The output is called `output.bin` and is in the same folder of the executable.

## Notes

- Remember to change your IV and key before compiling
- To use the encrypted message/shellcode you need to perform these steps: `output.bin` -> b64 decode -> AES decryption -> b64 decode
  - This means that if you use a loader to inject the shellcode you need to change it to AES-decrypt and b64-decode the input

## Why?

* To learn some specific C APIs in Windows
* To avoid dealing with POSIX/non-POSIX statements to create a cross-platform program
