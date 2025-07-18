using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;

namespace Arc4Decryptor
{
    internal class Program
    {
        private static void Main(string[] args)
        {
            string encryptedFilePath = "M010_StationStopModesEncrypted.L5X";
            string keyFilePath = "sk.dat";
            string saltDictionaryPath = "salts.json";
            string keywordDictionaryPath = "keywords.json";
            string outputLog = "decryption_results.log";
            int dropBytes = 768;
            bool useSalts = false;

            //Convert from normal string to bytes
            var baseKey = Encoding.UTF8.GetBytes("Stana7");
            //var baseKey = Convert.From("Stana7");
            List<string> salts = [];
            // ... existing code ...
        }
        
        private static byte[] ARC4DecryptWithDrop(byte[] data, byte[] key, int drop)
        {
            using var rc4 = new RC4Managed();
            rc4.Key = key;
            
            // Create the decryptor once and reuse it
            using var decryptor = rc4.CreateDecryptor();
            
            // Drop the first 'drop' bytes by decrypting a dummy buffer
            if (drop > 0)
            {
                byte[] dropBuffer = new byte[drop];
                // Use TransformBlock instead of TransformFinalBlock to avoid finalizing the transform
                decryptor.TransformBlock(dropBuffer, 0, drop, dropBuffer, 0);
            }
            
            // Now decrypt the actual data
            return decryptor.TransformFinalBlock(data, 0, data.Length);
        }
    }
    
    // ... rest of the existing code ...
}