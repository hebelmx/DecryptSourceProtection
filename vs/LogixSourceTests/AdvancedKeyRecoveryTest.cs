using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class AdvancedKeyRecoveryTest
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly string _fixturesPath;

    public AdvancedKeyRecoveryTest(ITestOutputHelper output)
    {
        _output = output;
        _logger = new TestLogger<L5XDecryptor>(_output);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task BruteForceKeyRecovery_UsingPlaintextCiphertext()
    {
        _output.WriteLine("🔍 ADVANCED KEY RECOVERY - BRUTE FORCE APPROACH");
        _output.WriteLine("=".PadRight(60, '='));

        // Test with a smaller file first for faster analysis
        var testFile = "S900_SkidJogFwd.L5X";
        
        var protectedPath = Path.Combine(_fixturesPath, "Protected", testFile);
        var unprotectedPath = Path.Combine(_fixturesPath, "Unprotected", testFile);

        if (!File.Exists(protectedPath) || !File.Exists(unprotectedPath))
        {
            _output.WriteLine($"❌ Required files not found");
            return;
        }

        // Extract the encoded data from protected file
        var protectedContent = await File.ReadAllTextAsync(protectedPath);
        var encodedData = ExtractEncodedData(protectedContent);
        
        if (string.IsNullOrEmpty(encodedData))
        {
            _output.WriteLine($"❌ Could not extract encoded data from {testFile}");
            return;
        }

        _output.WriteLine($"📄 Extracted encoded data length: {encodedData.Length}");

        // Read the unprotected content to get expected plaintext
        var unprotectedContent = await File.ReadAllTextAsync(unprotectedPath);
        var expectedPlaintext = ExtractRoutineContent(unprotectedContent);

        _output.WriteLine($"📄 Expected plaintext length: {expectedPlaintext.Length}");

        // Try common key patterns
        var keyPatterns = new[]
        {
            // Common RSLogix keys
            "Visual2025", "Doug'sExportEncryption", "defaultkey", "testkey",
            // Common industrial automation keys
            "RSLogix5000", "Allen-Bradley", "Rockwell", "Automation", "PLC",
            // Common passwords
            "password", "admin", "123456", "qwerty", "secret", "default",
            // Project-specific patterns
            "KnowKeyFixture33", "Fixture33", "Know33", "Key33", "Test33",
            // Variations with numbers
            "Visual2024", "Visual2026", "Visual2023", "Visual2022",
            // Other patterns
            "EncryptionKey", "SourceKey", "ProtectionKey", "L5XKey"
        };

        _output.WriteLine($"🔑 Testing {keyPatterns.Length} key patterns...");

        var cleanedBase64 = CleanBase64String(encodedData);
        byte[] encryptedBytes;
        
        try
        {
            encryptedBytes = Convert.FromBase64String(cleanedBase64);
            _output.WriteLine($"✅ Successfully decoded Base64 to {encryptedBytes.Length} bytes");
        }
        catch (Exception ex)
        {
            _output.WriteLine($"❌ Failed to decode Base64: {ex.Message}");
            return;
        }

        // Try each key pattern
        foreach (var keyPattern in keyPatterns)
        {
            _output.WriteLine($"\n🔍 Testing key: \"{keyPattern}\"");
            
            if (await TryDecryptWithKey(encryptedBytes, keyPattern, expectedPlaintext))
            {
                _output.WriteLine($"🎉 SUCCESS! The unknown key is: \"{keyPattern}\"");
                return;
            }
        }

        _output.WriteLine($"\n❌ None of the tested keys worked. The key may be:");
        _output.WriteLine($"   - A custom/random string not in common patterns");
        _output.WriteLine($"   - A different encryption algorithm than expected");
        _output.WriteLine($"   - Require additional salt/IV that we don't have");
        
        // Additional analysis
        await AnalyzeEncryptionCharacteristics(encryptedBytes, expectedPlaintext);
    }

    private async Task<bool> TryDecryptWithKey(byte[] encryptedBytes, string key, string expectedPlaintext)
    {
        try
        {
            // Try various key derivation methods
            var keyDerivations = new[]
            {
                // Direct UTF-8 key
                Encoding.UTF8.GetBytes(key),
                // MD5 hash of key
                MD5.HashData(Encoding.UTF8.GetBytes(key)),
                // SHA1 hash of key
                SHA1.HashData(Encoding.UTF8.GetBytes(key)),
                // SHA256 hash of key
                SHA256.HashData(Encoding.UTF8.GetBytes(key))
            };

            foreach (var keyBytes in keyDerivations)
            {
                // Try AES decryption
                if (await TryAESDecryption(encryptedBytes, keyBytes, expectedPlaintext))
                {
                    return true;
                }
                
                // Try RC4-like decryption
                if (TryRC4Decryption(encryptedBytes, keyBytes, expectedPlaintext))
                {
                    return true;
                }
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine($"   ❌ Error testing key: {ex.Message}");
        }
        
        return false;
    }

    private async Task<bool> TryAESDecryption(byte[] encryptedBytes, byte[] keyBytes, string expectedPlaintext)
    {
        try
        {
            // Try different AES key sizes
            var keySizes = new[] { 16, 24, 32 }; // 128, 192, 256 bits
            
            foreach (var keySize in keySizes)
            {
                var key = new byte[keySize];
                Array.Copy(keyBytes, key, Math.Min(keyBytes.Length, keySize));
                
                using var aes = Aes.Create();
                aes.Mode = CipherMode.ECB; // Try ECB first
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = key;
                
                using var decryptor = aes.CreateDecryptor();
                using var msDecrypt = new MemoryStream(encryptedBytes);
                using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using var srDecrypt = new StreamReader(csDecrypt);
                
                var decryptedText = await srDecrypt.ReadToEndAsync();
                
                if (IsValidDecryption(decryptedText, expectedPlaintext))
                {
                    _output.WriteLine($"   ✅ AES-{keySize * 8} ECB decryption successful!");
                    return true;
                }
            }
        }
        catch
        {
            // Silent fail - try next method
        }
        
        return false;
    }

    private bool TryRC4Decryption(byte[] encryptedBytes, byte[] keyBytes, string expectedPlaintext)
    {
        try
        {
            // Simple RC4-like decryption
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
            
            if (IsValidDecryption(decryptedText, expectedPlaintext))
            {
                _output.WriteLine($"   ✅ RC4 decryption successful!");
                return true;
            }
        }
        catch
        {
            // Silent fail
        }
        
        return false;
    }

    private bool IsValidDecryption(string decryptedText, string expectedPlaintext)
    {
        if (string.IsNullOrEmpty(decryptedText))
            return false;
        
        // Check for XML structure
        if (decryptedText.Contains("<Routine") && decryptedText.Contains("</Routine>"))
        {
            _output.WriteLine($"   📊 Valid XML structure detected");
            return true;
        }
        
        // Check for similarity with expected plaintext
        var similarity = CalculateSimilarity(decryptedText, expectedPlaintext);
        if (similarity > 0.7)
        {
            _output.WriteLine($"   📊 High similarity with expected plaintext: {similarity:P1}");
            return true;
        }
        
        return false;
    }

    private string ExtractEncodedData(string l5xContent)
    {
        var match = Regex.Match(l5xContent, @"<EncodedData[^>]*>(.*?)</EncodedData>", RegexOptions.Singleline);
        if (match.Success)
        {
            var content = match.Groups[1].Value;
            // Remove CDATA wrapper if present
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

        // Only keep valid Base64 characters
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
        
        // Add proper padding
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

    private async Task AnalyzeEncryptionCharacteristics(byte[] encryptedBytes, string expectedPlaintext)
    {
        _output.WriteLine($"\n🔍 ENCRYPTION ANALYSIS:");
        _output.WriteLine($"   📊 Encrypted data length: {encryptedBytes.Length} bytes");
        _output.WriteLine($"   📊 Expected plaintext length: {expectedPlaintext.Length} chars");
        _output.WriteLine($"   📊 Encryption ratio: {(double)encryptedBytes.Length / expectedPlaintext.Length:F2}");
        
        // Calculate entropy
        var entropy = CalculateEntropy(encryptedBytes);
        _output.WriteLine($"   📊 Data entropy: {entropy:F2} (higher = more random)");
        
        // Look for patterns in first few bytes
        _output.WriteLine($"   📊 First 16 bytes: {string.Join(" ", encryptedBytes.Take(16).Select(b => b.ToString("X2")))}");
        
        if (encryptedBytes.Length >= 16)
        {
            var blockSize = 16;
            var blockCount = Math.Min(4, encryptedBytes.Length / blockSize);
            _output.WriteLine($"   📊 Analyzing first {blockCount} blocks for patterns:");
            
            for (int i = 0; i < blockCount; i++)
            {
                var block = encryptedBytes.Skip(i * blockSize).Take(blockSize).ToArray();
                var blockHex = string.Join(" ", block.Select(b => b.ToString("X2")));
                _output.WriteLine($"     Block {i + 1}: {blockHex}");
            }
        }
    }

    private double CalculateEntropy(byte[] data)
    {
        var frequencies = new int[256];
        foreach (byte b in data)
        {
            frequencies[b]++;
        }
        
        double entropy = 0;
        double length = data.Length;
        
        for (int i = 0; i < 256; i++)
        {
            if (frequencies[i] > 0)
            {
                double probability = frequencies[i] / length;
                entropy -= probability * Math.Log2(probability);
            }
        }
        
        return entropy;
    }
}