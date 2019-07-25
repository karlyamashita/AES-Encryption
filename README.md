# AES-Encryption
A command line program that Encrypts/Decrypts Intel Hex 16 files.

The AES encryption section is based off Kokke's aes.c/h files https://github.com/kokke/tiny-AES-c and converted to C# for Visual Studio 2017

I've currently only have 128bit encryption enabled and tested. I have not tested 192 or 256bit so those sections are commented out. 

This is a quick and dirty instruction. When i have time i'll write a more percise instruction.
1. I've used Keil IDE to compile a project and after a build ran a batch file "runcmd.bat". So in options under "User" you'll have to add the path to the batch file. Modify the rumcmd.bat for your project paths. 
2. You can add a revision file to your project "revision.h" so the encrypted file will add a revision number to the file name you provide. if you don't add a revisin file then the file name will be as what name you input.
3. I've included a default 128bit (GUID) key in the program but you can change it to your own GUID. Or in the batch file you can add a GUID and it'll replace the default embedded GUID on the fly.


In the future i'll put the source code for:
1. The PC firmware updater which is a program to transfer encrypted hex file over USB to target microcontroller which in this case was for a STM32F105.
2. The universal bootloader for the STM32F105 which decrypts the encrypted hex file and loads it in program space which will embed the product name in the bootloader section. I'll include a simple project which shows how to add a product name and revision which gets embedded in the hex file. So the bootloader and PC updater will verify the encrypted hex file is correct for that product. 
