using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class ExtendedKeyRecoveryTest
{
    private readonly ITestOutputHelper _output;
    private readonly string _fixturesPath;

    public ExtendedKeyRecoveryTest(ITestOutputHelper output)
    {
        _output = output;
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task ExtendedKeySearch_SystematicApproach()
    {
        _output.WriteLine("🔍 EXTENDED KEY RECOVERY - SYSTEMATIC APPROACH");
        _output.WriteLine("=".PadRight(60, '='));

        // Use a small file for faster testing
        var testFile = "S900_SkidJogFwd.L5X";
        var protectedPath = Path.Combine(_fixturesPath, "Protected", testFile);
        var unprotectedPath = Path.Combine(_fixturesPath, "Unprotected", testFile);

        if (!File.Exists(protectedPath) || !File.Exists(unprotectedPath))
        {
            _output.WriteLine($"❌ Required files not found");
            return;
        }

        // Extract data
        var protectedContent = await File.ReadAllTextAsync(protectedPath);
        var unprotectedContent = await File.ReadAllTextAsync(unprotectedPath);
        
        var encodedData = ExtractEncodedData(protectedContent);
        var cleanedBase64 = CleanBase64String(encodedData);
        var encryptedBytes = Convert.FromBase64String(cleanedBase64);
        var expectedPlaintext = ExtractRoutineContent(unprotectedContent);

        _output.WriteLine($"📄 Encrypted data: {encryptedBytes.Length} bytes");
        _output.WriteLine($"📄 Expected plaintext: {expectedPlaintext.Length} chars");

        // Extended key patterns based on directory name hints
        var extendedKeys = new[]
        {
            // Based on "Know Key Fixture 33"
            "KnowKey", "Know Key", "KnowKeyFixture", "Know Key Fixture",
            "Fixture", "Fixture33", "KnowKey33", "Know_Key_33", "KNOW_KEY_33",
            
            // Variations of the number 33
            "33", "Key33", "PASSWORD33", "SECRET33", "PROTECT33",
            "Visual33", "Visual2033", "RSLogix33", "Allen33", "Rockwell33",
            
            // Common industrial/automation keys
            "FACTORY", "MACHINE", "CONTROLLER", "PROCESS", "SAFETY", "EMERGENCY",
            "OPERATOR", "ENGINEER", "MAINTENANCE", "SERVICE", "DIAGNOSTIC",
            "PROGRAM", "LOGIC", "CONTROL", "SYSTEM", "NETWORK", "STATION",
            
            // Possible project-specific keys
            "Disa2070mk2", "DISA2070", "MK2", "DISA", "2070", "mk2",
            "SKID", "INDEX", "SEQUENCE", "MODES", "JOG", "REVERSE",
            "STATION", "STOP", "FORWARD", "MANUAL", "AUTO", "PRODUCTION",
            
            // Technical variations
            "ENCRYPTED", "PROTECTED", "LOCKED", "SECURE", "PRIVATE", "ACCESS",
            "UNLOCK", "DECODE", "DECRYPT", "CIPHER", "CRYPT", "ENCODE",
            
            // Date/time based (assuming file dates)
            "2025", "2024", "2023", "072025", "170725", "Jul2025",
            "Visual2025!", "Visual2025#", "Visual2025$", "Visual2025%",
            
            // Case variations of Visual2025
            "VISUAL2025", "visual2025", "Visual2025", "ViSuAl2025",
            
            // Common password variations
            "password123", "admin123", "test123", "user123", "key123",
            "Pass123", "Admin123", "Test123", "User123", "Key123",
            
            // Possible company/project names
            "EXXERPRO", "Exxerpro", "HEBEL", "Hebel", "DESKTOP", "FB2ES22",
            
            // Hardware/software versions
            "V33", "V30", "V27", "V19", "V24", "VERSION33", "REV33",
            
            // Special characters combinations
            "Visual2025.", "Visual2025,", "Visual2025;", "Visual2025:",
            "Visual2025-", "Visual2025_", "Visual2025+", "Visual2025*",
            
            // Doubled or modified versions
            "Visual2025Visual2025", "2025Visual", "25Visual20", "20Visual25"
        };

        _output.WriteLine($"🔑 Testing {extendedKeys.Length} extended key patterns...");

        foreach (var key in extendedKeys)
        {
            _output.WriteLine($"🔍 Testing key: \"{key}\"");
            
            if (await TryDecryptWithExtendedMethods(encryptedBytes, key, expectedPlaintext))
            {
                _output.WriteLine($"");
                _output.WriteLine($"🎉🎉🎉 SUCCESS! THE UNKNOWN KEY IS: \"{key}\" 🎉🎉🎉");
                _output.WriteLine($"");
                return;
            }
        }

        _output.WriteLine($"\n❌ Extended key search failed. The key may be:");
        _output.WriteLine($"   - A completely random/generated string");
        _output.WriteLine($"   - A combination of words not tested");
        _output.WriteLine($"   - Using a different encryption algorithm");
        _output.WriteLine($"   - Requiring additional parameters (salt, IV, etc.)");
        
        // Try some final creative combinations
        await TryCreativeCombinations(encryptedBytes, expectedPlaintext);
    }

    private async Task TryCreativeCombinations(byte[] encryptedBytes, string expectedPlaintext)
    {
        _output.WriteLine($"\n🎨 TRYING CREATIVE COMBINATIONS...");
        
        // Combinations of base words
        var baseWords = new[] { "Visual", "Know", "Key", "Fixture", "33", "2025", "Disa", "2070", "mk2" };
        var separators = new[] { "", "_", "-", ".", "2025", "33" };
        
        var combinations = new List<string>();
        
        // Two-word combinations
        foreach (var word1 in baseWords)
        {
            foreach (var word2 in baseWords)
            {
                if (word1 != word2)
                {
                    foreach (var sep in separators)
                    {
                        combinations.Add($"{word1}{sep}{word2}");
                        combinations.Add($"{word2}{sep}{word1}");
                    }
                }
            }
        }
        
        _output.WriteLine($"🔍 Testing {combinations.Count} creative combinations...");
        
        foreach (var combo in combinations.Take(50)) // Limit to first 50 to avoid timeout
        {
            _output.WriteLine($"🎨 Testing: \"{combo}\"");
            
            if (await TryDecryptWithExtendedMethods(encryptedBytes, combo, expectedPlaintext))
            {
                _output.WriteLine($"");
                _output.WriteLine($"🎉🎉🎉 SUCCESS! THE UNKNOWN KEY IS: \"{combo}\" 🎉🎉🎉");
                _output.WriteLine($"");
                return;
            }
        }
        
        _output.WriteLine($"❌ Creative combinations also failed.");
    }

    private async Task<bool> TryDecryptWithExtendedMethods(byte[] encryptedBytes, string key, string expectedPlaintext)
    {
        try
        {
            // Try multiple key transformations
            var keyVariants = new[]
            {
                key,
                key.ToUpper(),
                key.ToLower(),
                key.Trim(),
                key.Replace(" ", ""),
                key.Replace("_", ""),
                key.Replace("-", ""),
                key + "2025",
                key + "33",
                "Visual" + key,
                key + "Visual",
                Reverse(key),
                key + key, // Doubled key
                key.Substring(0, Math.Min(key.Length, 8)), // Truncated
                key.PadRight(16, '0'), // Padded
                key.PadRight(32, '0')  // Padded to 32
            };

            foreach (var variant in keyVariants)
            {
                if (await TryAllDecryptionMethods(encryptedBytes, variant, expectedPlaintext))
                {
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine($"   ❌ Error: {ex.Message}");
        }
        
        return false;
    }

    private async Task<bool> TryAllDecryptionMethods(byte[] encryptedBytes, string key, string expectedPlaintext)
    {
        try
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            
            // Try different key derivations
            var derivedKeys = new[]
            {
                keyBytes,
                MD5.HashData(keyBytes),
                SHA1.HashData(keyBytes),
                SHA256.HashData(keyBytes),
                SHA256.HashData(Encoding.UTF8.GetBytes(key + "Visual2025")),
                SHA256.HashData(Encoding.UTF8.GetBytes("Visual2025" + key)),
                SHA256.HashData(Encoding.UTF8.GetBytes(key + "33")),
                SHA256.HashData(Encoding.UTF8.GetBytes("33" + key))
            };

            foreach (var derivedKey in derivedKeys)
            {
                // Try AES with different modes
                if (await TryAESDecryption(encryptedBytes, derivedKey, expectedPlaintext))
                {
                    return true;
                }
                
                // Try RC4
                if (TryRC4Decryption(encryptedBytes, derivedKey, expectedPlaintext))
                {
                    return true;
                }
                
                // Try XOR
                if (TryXORDecryption(encryptedBytes, derivedKey, expectedPlaintext))
                {
                    return true;
                }
            }
        }
        catch
        {
            // Silent fail
        }
        
        return false;
    }

    private async Task<bool> TryAESDecryption(byte[] encryptedBytes, byte[] keyBytes, string expectedPlaintext)
    {
        try
        {
            var keySizes = new[] { 16, 24, 32 };
            var modes = new[] { CipherMode.ECB, CipherMode.CBC };
            
            foreach (var keySize in keySizes)
            {
                foreach (var mode in modes)
                {
                    var key = new byte[keySize];
                    Array.Copy(keyBytes, key, Math.Min(keyBytes.Length, keySize));
                    
                    using var aes = Aes.Create();
                    aes.Mode = mode;
                    aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key;
                    
                    if (mode == CipherMode.CBC)
                    {
                        aes.IV = new byte[16]; // Zero IV
                    }
                    
                    using var decryptor = aes.CreateDecryptor();
                    using var msDecrypt = new MemoryStream(encryptedBytes);
                    using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                    using var srDecrypt = new StreamReader(csDecrypt);
                    
                    var decryptedText = await srDecrypt.ReadToEndAsync();
                    
                    if (IsValidDecryption(decryptedText, expectedPlaintext))
                    {
                        return true;
                    }
                }
            }
        }
        catch
        {
            // Silent fail
        }
        
        return false;
    }

    private bool TryRC4Decryption(byte[] encryptedBytes, byte[] keyBytes, string expectedPlaintext)
    {
        try
        {
            var s = new byte[256];
            var key = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                key[i] = keyBytes[i % keyBytes.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + key[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            var decrypted = new byte[encryptedBytes.Length];
            int x = 0, y = 0;
            
            for (int i = 0; i < encryptedBytes.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                decrypted[i] = (byte)(encryptedBytes[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(decrypted);
            
            return IsValidDecryption(decryptedText, expectedPlaintext);
        }
        catch
        {
            return false;
        }
    }

    private bool TryXORDecryption(byte[] encryptedBytes, byte[] keyBytes, string expectedPlaintext)
    {
        try
        {
            var decrypted = new byte[encryptedBytes.Length];
            
            for (int i = 0; i < encryptedBytes.Length; i++)
            {
                decrypted[i] = (byte)(encryptedBytes[i] ^ keyBytes[i % keyBytes.Length]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(decrypted);
            
            return IsValidDecryption(decryptedText, expectedPlaintext);
        }
        catch
        {
            return false;
        }
    }

    private bool IsValidDecryption(string decryptedText, string expectedPlaintext)
    {
        if (string.IsNullOrEmpty(decryptedText))
            return false;
        
        // Check for XML structure
        if (decryptedText.Contains("<Routine") && decryptedText.Contains("</Routine>"))
        {
            return true;
        }
        
        // Check for similarity with expected plaintext
        var similarity = CalculateSimilarity(decryptedText, expectedPlaintext);
        return similarity > 0.7;
    }

    private string ExtractEncodedData(string l5xContent)
    {
        var match = Regex.Match(l5xContent, @"<EncodedData[^>]*>(.*?)</EncodedData>", RegexOptions.Singleline);
        if (match.Success)
        {
            var content = match.Groups[1].Value;
            content = Regex.Replace(content, @"<!\[CDATA\[(.*?)\]\]>", "$1", RegexOptions.Singleline);
            return content.Trim();
        }
        return string.Empty;
    }

    private string ExtractRoutineContent(string l5xContent)
    {
        var match = Regex.Match(l5xContent, @"<Routine[^>]*>(.*?)</Routine>", RegexOptions.Singleline);
        if (match.Success)
        {
            return match.Groups[1].Value.Trim();
        }
        return string.Empty;
    }

    private string CleanBase64String(string base64String)
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

    private double CalculateSimilarity(string text1, string text2)
    {
        if (string.IsNullOrEmpty(text1) || string.IsNullOrEmpty(text2))
            return 0;
        
        var minLength = Math.Min(text1.Length, text2.Length);
        var maxLength = Math.Max(text1.Length, text2.Length);
        
        if (maxLength == 0) return 1.0;
        
        var matches = 0;
        for (int i = 0; i < minLength; i++)
        {
            if (text1[i] == text2[i])
                matches++;
        }
        
        return (double)matches / maxLength;
    }

    private string Reverse(string str)
    {
        return new string(str.Reverse().ToArray());
    }
}