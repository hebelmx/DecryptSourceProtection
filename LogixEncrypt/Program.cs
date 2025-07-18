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
            var keywords = JsonConvert.DeserializeObject<List<string>>(File.ReadAllText(keywordDictionaryPath));
            var encryptedString = """
                                  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
                                  """;
            //convert string to bytes

            var encryptedData = Encoding.UTF8.GetBytes(encryptedString);

            var logEntries = new List<string>();

            if (useSalts)
            {
                salts = JsonConvert.DeserializeObject<List<string>>(File.ReadAllText(saltDictionaryPath));
                logEntries.Add($"Using salts from {saltDictionaryPath}");
            }
            else
            {
                salts = [""];
                logEntries.Add("Not using salts, using base key only.");
            }
            foreach (var salt in salts)
            {
                string candidate = baseKey + salt;
                byte[] key = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(candidate));
                byte[] decrypted = ARC4DecryptWithDrop(encryptedData, key, dropBytes);
                string content = Encoding.UTF8.GetString(decrypted);

                var found = keywords.Where(k => content.Contains(k)).ToList();
                if (found.Count > 0)
                {
                    logEntries.Add($"Key: {candidate} | Keywords Found: {string.Join(", ", found)}");
                }
            }

            File.WriteAllLines(outputLog, logEntries);
            Console.WriteLine("Decryption attempts complete. Results logged.");
        }

        private static string ExtractBaseKey(string path)
        {
            var lines = File.ReadAllLines(path).Where(l => !l.TrimStart().StartsWith("<"));
            return lines.FirstOrDefault(l => !string.IsNullOrWhiteSpace(l))?.Trim() ?? throw new Exception("No key found.");
        }

        private static byte[] ARC4DecryptWithDrop(byte[] data, byte[] key, int drop)
        {
            using var rc4 = new RC4Managed();
            rc4.Key = key;
            byte[] dropBuffer = new byte[drop];
            return rc4.CreateDecryptor().TransformFinalBlock(data, 0, data.Length);
        }
    }

    public class RC4Managed : SymmetricAlgorithm
    {
        public RC4Managed()
        {
            KeySizeValue = 2048;
            BlockSizeValue = 8;
            Mode = CipherMode.ECB;
            Padding = PaddingMode.None;
            LegalKeySizesValue = new KeySizes[] { new KeySizes(40, 2048, 8) }; // Initialization of LegalKeySizesValue
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) => new RC4Transform(rgbKey);

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) => new RC4Transform(rgbKey);

        public override void GenerateIV() => IVValue = new byte[0];

        public override void GenerateKey() => KeyValue = new byte[32];

        private class RC4Transform : ICryptoTransform
        {
            private readonly byte[] S = new byte[256];
            private int i, j;

            public RC4Transform(byte[] key)
            {
                for (int k = 0; k < 256; k++) S[k] = (byte)k;
                for (int k = 0, m = 0; k < 256; k++)
                {
                    m = (m + S[k] + key[k % key.Length]) & 255;
                    (S[k], S[m]) = (S[m], S[k]);
                }
                i = j = 0;
            }

            public bool CanReuseTransform => true;
            public bool CanTransformMultipleBlocks => true;
            public int InputBlockSize => 1;
            public int OutputBlockSize => 1;

            public void Dispose()
            { }

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount,
                                      byte[] outputBuffer, int outputOffset)
            {
                for (int k = 0; k < inputCount; k++)
                {
                    i = (i + 1) & 255;
                    j = (j + S[i]) & 255;
                    (S[i], S[j]) = (S[j], S[i]);
                    byte rnd = S[(S[i] + S[j]) & 255];
                    outputBuffer[outputOffset + k] = (byte)(inputBuffer[inputOffset + k] ^ rnd);
                }
                return inputCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] result = new byte[inputCount];
                TransformBlock(inputBuffer, inputOffset, inputCount, result, 0);
                return result;
            }
        }
    }
}