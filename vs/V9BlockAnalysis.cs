using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("🔍 V9 ENCRYPTION BLOCK ANALYSIS");
        Console.WriteLine("=" + new string('=', 50));
        
        var basePath = "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/";
        var files = new[]
        {
            "S025_SkidIndexInVDL.L5X",      // Known working
            "S005_STP1Advance.L5X",        // Target
            "S010_STP1Return.L5X",         // Target
            "S015_STP2Advance.L5X",        // Target
            "S020_STP2Return.L5X",         // Target
            "S025_SkidIndexOut_Clear.L5X"  // Target
        };

        Console.WriteLine("📊 ANALYZING ENCRYPTED BLOCKS TO CRACK THE CODE");
        Console.WriteLine();

        foreach (var fileName in files)
        {
            var filePath = Path.Combine(basePath, fileName);
            if (!File.Exists(filePath)) continue;

            Console.WriteLine($"📄 {fileName}");
            Console.WriteLine("-" + new string('-', 40));

            try
            {
                var content = File.ReadAllText(filePath);
                
                // Extract encrypted data
                var encodedMatch = Regex.Match(content, @"<EncodedData[^>]*>(.*?)</EncodedData>", RegexOptions.Singleline);
                if (!encodedMatch.Success)
                {
                    Console.WriteLine("❌ No EncodedData found");
                    continue;
                }

                var encodedContent = encodedMatch.Groups[1].Value;
                encodedContent = Regex.Replace(encodedContent, @"<!\[CDATA\[(.*?)\]\]>", "$1", RegexOptions.Singleline);
                
                // Extract routine name
                var routineMatch = Regex.Match(content, @"<Routine[^>]*Name=""([^""]*)"">", RegexOptions.Singleline);
                var routineName = routineMatch.Success ? routineMatch.Groups[1].Value : "Unknown";

                Console.WriteLine($"🏷️  Routine: {routineName}");
                Console.WriteLine($"📏 Encoded Length: {encodedContent.Length:N0}");

                // Clean and decode Base64
                var cleanedBase64 = CleanBase64String(encodedContent);
                Console.WriteLine($"🧹 Cleaned Length: {cleanedBase64.Length:N0}");

                try
                {
                    var encryptedBytes = Convert.FromBase64String(cleanedBase64);
                    Console.WriteLine($"📦 Encrypted Bytes: {encryptedBytes.Length:N0}");
                    
                    // Analyze the encrypted block
                    AnalyzeEncryptedBlock(encryptedBytes, routineName);
                    
                    // Try routine name-based salting manually
                    TestRoutineNameSalting(encryptedBytes, routineName);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"❌ Base64 decode error: {ex.Message}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 File analysis error: {ex.Message}");
            }
            
            Console.WriteLine();
        }
    }

    static void AnalyzeEncryptedBlock(byte[] encryptedBytes, string routineName)
    {
        Console.WriteLine($"🔍 Block Analysis:");
        
        // First 16 bytes (potential IV or header)
        var firstBytes = encryptedBytes.Take(16).ToArray();
        Console.WriteLine($"   First 16 bytes: {Convert.ToHexString(firstBytes)}");
        
        // Last 16 bytes (potential padding or footer)
        var lastBytes = encryptedBytes.Skip(Math.Max(0, encryptedBytes.Length - 16)).ToArray();
        Console.WriteLine($"   Last 16 bytes: {Convert.ToHexString(lastBytes)}");
        
        // Entropy calculation
        var entropy = CalculateEntropy(encryptedBytes);
        Console.WriteLine($"   Entropy: {entropy:F2}/8.0 (higher = more encrypted)");
        
        // Check for patterns
        var hasRepeatingPatterns = HasRepeatingPatterns(encryptedBytes);
        Console.WriteLine($"   Repeating patterns: {hasRepeatingPatterns}");
        
        // Block size analysis
        var blockSize = encryptedBytes.Length % 16;
        Console.WriteLine($"   Block alignment: {blockSize} (0=AES aligned)");
    }

    static void TestRoutineNameSalting(byte[] encryptedBytes, string routineName)
    {
        Console.WriteLine($"🧂 Testing routine name salting for '{routineName}':");
        
        var key = "Stana7";
        var saltVariations = new[]
        {
            routineName,                                                    // Direct
            routineName.ToUpper(),                                         // Uppercase
            routineName.ToLower(),                                         // Lowercase
            Regex.Replace(routineName, @"[^a-zA-Z]", ""),                  // Letters only
            routineName.Contains("_") ? routineName.Split('_')[0] : routineName,  // Prefix
            routineName.Contains("_") ? routineName.Split('_').Last() : routineName  // Suffix
        };

        foreach (var salt in saltVariations)
        {
            // Test different hash combinations
            var combinations = new[]
            {
                ("MD5", MD5.HashData(Encoding.UTF8.GetBytes(key + salt))),
                ("SHA1", SHA1.HashData(Encoding.UTF8.GetBytes(key + salt))),
                ("SHA256", SHA256.HashData(Encoding.UTF8.GetBytes(key + salt))),
                ("SHA256-reverse", SHA256.HashData(Encoding.UTF8.GetBytes(salt + key))),
                ("SHA256-separated", SHA256.HashData(Encoding.UTF8.GetBytes(key + "|" + salt)))
            };

            foreach (var (hashName, hashedKey) in combinations)
            {
                // Try AES decryption
                var result = TryAESDecrypt(encryptedBytes, hashedKey);
                if (result.Success)
                {
                    Console.WriteLine($"   🎯 POTENTIAL MATCH: {hashName}({key} + {salt})");
                    Console.WriteLine($"   📝 Decrypted length: {result.Content.Length}");
                    if (result.Content.Contains("<") && result.Content.Contains(">"))
                    {
                        Console.WriteLine($"   ✅ CONTAINS XML - REAL BREAKTHROUGH!");
                        Console.WriteLine($"   🔍 First 100 chars: {result.Content.Substring(0, Math.Min(100, result.Content.Length))}");
                        return; // Found it!
                    }
                }
            }
        }
        
        Console.WriteLine($"   ❌ No matches found for routine name salting");
    }

    static (bool Success, string Content) TryAESDecrypt(byte[] encryptedBytes, byte[] key)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            
            // Adjust key to 32 bytes for AES-256
            var keyBytes = new byte[32];
            Array.Copy(key, keyBytes, Math.Min(key.Length, 32));
            aes.Key = keyBytes;
            
            using var decryptor = aes.CreateDecryptor();
            var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    static string CleanBase64String(string base64String)
    {
        if (string.IsNullOrEmpty(base64String))
            return base64String;

        var cleaned = base64String
            .Replace("\r", "")
            .Replace("\n", "")
            .Replace("\t", "")
            .Replace(" ", "")
            .Trim();

        var validBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var result = new StringBuilder(cleaned.Length);
        
        foreach (char c in cleaned)
        {
            if (validBase64Chars.Contains(c))
            {
                result.Append(c);
            }
        }

        cleaned = result.ToString().TrimEnd('=');
        
        int paddingCount = 4 - (cleaned.Length % 4);
        if (paddingCount != 4)
        {
            cleaned += new string('=', paddingCount);
        }

        return cleaned;
    }

    static double CalculateEntropy(byte[] data)
    {
        var frequencies = new int[256];
        foreach (var b in data)
        {
            frequencies[b]++;
        }
        
        double entropy = 0;
        foreach (var frequency in frequencies)
        {
            if (frequency > 0)
            {
                var probability = (double)frequency / data.Length;
                entropy -= probability * Math.Log2(probability);
            }
        }
        
        return entropy;
    }

    static bool HasRepeatingPatterns(byte[] data)
    {
        // Check for 4-byte repeating patterns
        var patternCounts = new Dictionary<uint, int>();
        
        for (int i = 0; i <= data.Length - 4; i++)
        {
            var pattern = BitConverter.ToUInt32(data, i);
            patternCounts[pattern] = patternCounts.GetValueOrDefault(pattern, 0) + 1;
        }
        
        return patternCounts.Any(kvp => kvp.Value > 2);
    }
}