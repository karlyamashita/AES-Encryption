@echo off
set Keil_Project_Path="C:\Users\Karl\Documents\_STM32_Projects"
set fromelf_path="C:\Keil_v5\ARM\ARMCC\bin"

cd %Keil_Project_Path%
@echo on

Aes_Encryption.exe C:\Users\Karl\Documents\_STM32_Projects\AMP-CH5\MDK-ARM\AMP-CH5\AMP-CH5.hex C:\Users\Karl\Documents\_STM32_Projects\AMP-CH5\hex_files\AMP-CH5.crx C:\Users\Karl\Documents\_STM32_Projects\AMP-CH5\Inc\revision.h