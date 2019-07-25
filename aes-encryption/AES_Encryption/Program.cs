using System;
using System.IO;
using System.Collections.Generic;
using System.Text;

/*
args[0] = input file
args[1] = output file
args[2] = revision file
args[3] = 128 bit key
*/

namespace AES_Encryption
{
    class Program
    {
        static void Main(string[] args)
        {
            string inputFile = string.Empty;
            string outputFile = string.Empty;
            string firmwareRevisionFilename = string.Empty;
            string key = string.Empty;

            if (args.Length != 0)
            {
                if (args[0] == "-h" || args[0] == "-H")
                {
                    ShowHelp();
                }
                else if (args.Length >= 2)// has to be minimum of 2 args, input and output file.
                {
                    inputFile = args[0];
                    outputFile = args[1];
                    if (args.Length == 3) // revision file available
                    {
                        firmwareRevisionFilename = args[2];
                    }
                    else
                    {
                        firmwareRevisionFilename = "";
                    }
                    if(args.Length == 4) // 128 bit key available
                    {
                        key = args[3];
                    }

                    if (args[0].Contains(".crx")) {// is a encrypted file so let's decrypt it.
                        DecryptionRoutine decryption = new DecryptionRoutine();
                        decryption.DecryptFile(inputFile, outputFile, key);
                    }
                    else
                    {
                        EncryptionRoutine encryption = new EncryptionRoutine();
                        encryption.EncryptFile(inputFile, outputFile, firmwareRevisionFilename, key);
                    }                      
                }
                else
                {
                    ShowHelp();
                }
            }
            else
            {
                //    EncryptionRoutine encryption = new EncryptionRoutine(); // debug
                //    encryption.EncryptFile("project_1.hex", "Encrypted_project_1.crx", "", "A4DDE216-6351-4A4D-B1AB-0E5D2CE2D7B7"); // debug

                //    DecryptionRoutine decryption = new DecryptionRoutine(); // debug
                //    decryption.DecryptFile("Encrypted_project_2.crx", "Decrypted_project_2.hex", "A4DDE216-6351-4A4D-B1AB-0E5D2CE2D7B7"); // debug

                Console.WriteLine("Please enter filenames as follows: {source_file_name.hex} {destination_file_name.crx} {revision_file(optional)} {128bit GUID(optional)}");
            }
        }

        static private void ShowHelp()
        {
            Console.WriteLine("- AES encryption. Copyright (c) 2017-2018 Karl Yamashita Engineering. Contact:karlyamashita@gmail.com. ver 2.0.0");
            Console.WriteLine("- Please enter filenames as follows: {source_file_name.hex} {destination_file_name.crx} {revision_file(optional)} {128bit GUID(optional)}");
            Console.WriteLine("- If no 128 bit GUID is provided, then a pre-generated GUID provided by the developer is used."); 
            Console.WriteLine("- The revision file if used should have on a line by itself <VERSION>V1.0.0 where <VERSION> is the keyword and any text trailing it is used in the filename.");
        }
    }

    class EncryptionRoutine
    {
        public void EncryptFile(string inputFilename, string outputFilename, string firmwareRevisionFilename, string newKey)
        {
            Aes aes = new Aes();

            if (!File.Exists(inputFilename))
            {
                Console.WriteLine("{0} {1}", inputFilename, " file does not exist!");
                return;
            }
            if (File.Exists(outputFilename))
            {
                File.Delete(outputFilename);
            }

            if (firmwareRevisionFilename != "")
            {
                string revisionName = "";
                revisionName = GetVersionNumberFromFile(firmwareRevisionFilename);
                if(outputFilename.Contains(".crx"))
                {
                    outputFilename = outputFilename.Insert(outputFilename.IndexOf(".crx"), "_" + revisionName + "_");
                } else
                {
                    Console.WriteLine("The output file name extension is not valid. The extension should end in \".crx\"");
                    return;
                }
                
            }        

            FileStream fsOut = File.Create(outputFilename);
            FileStream fsIn = File.OpenRead(inputFilename);
            StreamReader sr = new StreamReader(fsIn);
            ulong fileSize = (ulong)fsIn.Length;

            // todo: final filesize. Needs to be in increments of 16 bytes.
            ulong finalRemainder = (16 - (fileSize % 16) ); // find how many bytes left then subtract from 16 to get value to add to current file size.
            fileSize += finalRemainder; // add how many bytes to current file size
            UInt16 lastKeys = (UInt16) (fileSize); // now get the low 2 byte value from fize size.

            // Create your own 128 bit key. This should be the same key as the decryption key
            uint[] key = new uint[16] { 0xA4, 0xDD, 0xE2, 0x16, 0x63, 0x51, 0x4A, 0x4D, 0xB1, 0xAB, 0x0E, 0x5D, 0x2C, 0xE2, 0xD7, 0xB7 }; // new guid (A4DDE216-6351-4A4D-B1AB-0E5D2CE2D7B7)        

            if (!newKey.Equals(""))// if a GUID was included then replace default GUID. Also I do not have error checking implemeted so an invalid GUID will more than likely cause a crash.
            {
                newKey = newKey.Replace("-", ""); // some GUId may have dashes, so this will remove them.
                byte[] aKey = StrToByteArray(newKey);
                Array.Copy(aKey, key, key.Length);
            }

            // changing last two bytes of key depending on file size. Doing this will make the encryption key random for each hex file.
            key[14] = (uint)lastKeys >> 8;
            key[15] = (uint)lastKeys & 0xff; 

            string getLine = string.Empty;
            string temp_line = string.Empty;

            AES_ctx ctx = new AES_ctx();
            aes.AES_init_ctx(ref ctx, ref key);

            char[] charArray = new char[fileSize];
            //read all chars from file into array
            for (ulong i = 0; i < fileSize; i++)
            {
                charArray[i] = (char)sr.Read();
            }

            uint[] tempArray = new uint[16]; // new array

            ulong charCounter = 0;
            while (charCounter < fileSize)
            {
                Array.Clear(tempArray, 0, tempArray.Length);
                Array.Copy(charArray, (int)charCounter, tempArray, 0, 16);

                aes.AES_ECB_encrypt(ref ctx, ref tempArray);

                byte[] byteArray = new byte[16];
                uint k = 0;
                for (int j = 0; j < 4 ; j++)
                {
                    for (uint i = 0; i < 4 ; i++, k++)
                    {
                        byteArray[k] = (byte)aes.state_t.state_t[j, i];
                    }
                }

                // write to the new file
                fsOut.Write(byteArray, 0, byteArray.Length);
                charCounter += 16;
            }

            fsIn.Close();
            fsOut.Close();
            Console.WriteLine(Path.GetFileName(inputFilename) + " has been encrypted successfully! New filename: " + Path.GetFileName(outputFilename));
        }

        private string GetVersionNumberFromFile(string filename)
        {
            string versionNumber = string.Empty;
            string errorString = "Revision file does not exist so a revision number will not be attached to file name.";

            if (!File.Exists(filename))
            {
                Console.WriteLine("{0} {1}", filename, errorString);
                return versionNumber;
            }

            FileStream fsIn = File.OpenRead(filename);
            StreamReader sr = new StreamReader(fsIn);

            string temp_line = string.Empty;
            string keyword = "<VERSION>";
            int lineNumber = 0;
            int indexStart, indexLength = 0;

            while (!sr.EndOfStream)
            {
                temp_line = sr.ReadLine();
                lineNumber += 1;
                temp_line = temp_line.Trim();
                temp_line = temp_line.Replace(" ", string.Empty);
                if (temp_line.Contains(keyword))
                {
                    Console.WriteLine("Found... " + temp_line);
                    indexStart = temp_line.LastIndexOf(keyword) + keyword.Length;
                    indexLength = temp_line.Length - keyword.Length;
                    try
                    {
                        versionNumber = temp_line.Substring(indexStart, indexLength);
                    }
                    catch (IndexOutOfRangeException e)
                    {
                        Console.WriteLine("error: " + e);
                    }
                }
            }

            return versionNumber;
        }

        public static byte[] StrToByteArray(string str)
        {
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            for (int i = 0; i < str.Length; i += 2)
                hexres.Add(hexindex[str.Substring(i, 2)]);

            return hexres.ToArray();
        }
    }

    class DecryptionRoutine
    {
        public void DecryptFile(string inputFilename, string outputFilename, string newKey)
        {
            Aes aes = new Aes();

            if (!File.Exists(inputFilename))
            {
                Console.WriteLine("{0} {1}", inputFilename, " file does not exist!");
                return;
            }
            if (File.Exists(outputFilename))
            {
                File.Delete(outputFilename);
            }

            FileStream fsOut = File.Create(outputFilename);
            FileStream fsIn = File.OpenRead(inputFilename);
            StreamReader sr = new StreamReader(fsIn);
            ulong fileSize = (ulong)fsIn.Length;

            string myFile = string.Empty;

            // Create your own 128 bit key. This should be the same as the encryption key
            uint[] key = new uint[16] { 0xA4, 0xDD, 0xE2, 0x16, 0x63, 0x51, 0x4A, 0x4D, 0xB1, 0xAB, 0x0E, 0x5D, 0x2C, 0xE2, 0xD7, 0xB7 }; // new guid (A4DDE216-6351-4A4D-B1AB-0E5D2CE2D7B7)

            if (!newKey.Equals(""))
            {
                newKey = newKey.Replace("-", "");
                byte[] aKey = StrToByteArray(newKey);
                Array.Copy(aKey, key, key.Length);
            }

            UInt16 lastKeys = (UInt16)(fileSize);
            key[14] = (uint)lastKeys >> 8;
            key[15] = (uint)lastKeys & 0xff; // changing last two bytes of key depending on file size.

            //aes.Phex(ref key, 0);

            byte[] fileBytes = new byte[fsIn.Length];
            int numBytesToRead = (int)fsIn.Length;

            int numBytesRead = 0;
            while (numBytesToRead > 0)
            {
                // Read may return anything from 0 to numBytesToRead.
                int n = fsIn.Read(fileBytes, numBytesRead, numBytesToRead);

                // Break when the end of the file is reached.
                if (n == 0)
                    break;

                numBytesRead += n;
                numBytesToRead -= n;
            }
            numBytesToRead = fileBytes.Length; // reload size

            fsIn.Close(); // done with file

            AES_ctx ctx = new AES_ctx();
            aes.AES_init_ctx(ref ctx, ref key);

            numBytesRead = 0;
            while (numBytesRead < numBytesToRead)
            {
                uint[] tempArray = new uint[16]; // new temp array

                Array.Copy(fileBytes, numBytesRead, tempArray, 0, 16); // copy 16 bytes at a time
                aes.AES_ECB_decrypt(ref ctx, ref tempArray); // decrypt 16 bytes

                byte[] byteArray = new byte[16];
                Array.Clear(byteArray, 0, byteArray.Length); 
                uint k = 0;
                for (int j = 0; j < 4 ; j++)
                {
                    for (uint i = 0; i < 4 ; i++, k++)
                    {
                        byteArray[k] = (byte)((char)aes.state_t.state_t[j, i]);
                    }
                }
                myFile += Encoding.Default.GetString(byteArray); // keep adding to string
                numBytesRead += 16; // inc the read pointer
            }

            byte myByte = 0;
            numBytesRead = 0; // the counter for the file size
            foreach (char c in myFile)
            {
                myByte = (byte) Convert.ToByte(c);

                if (myByte <= 127) // check if ascii char 0-127
                {
                    fsOut.WriteByte(myByte); // write whole string to file
                    numBytesRead += 1;
                }

                if (numBytesRead == numBytesToRead) break;
            }

            Console.WriteLine("The filesize: " + numBytesRead); // this is what we need to do for the Firmware updater app to send to bootloader.

            fsOut.Close();// close file
            Console.WriteLine(Path.GetFileName(inputFilename) + " has been decrypted successfully! New filename: " + Path.GetFileName(outputFilename));
        }

        public static byte[] StrToByteArray(string str)
        {
            Dictionary<string, byte> hexindex = new Dictionary<string, byte>();
            for (int i = 0; i <= 255; i++)
                hexindex.Add(i.ToString("X2"), (byte)i);

            List<byte> hexres = new List<byte>();
            for (int i = 0; i < str.Length; i += 2)
                hexres.Add(hexindex[str.Substring(i, 2)]);

            return hexres.ToArray();
        }
    }
}

