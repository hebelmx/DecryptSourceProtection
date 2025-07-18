using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

/// <summary>
/// PLAN A Phase 2: EncodedData Decryption Engine
/// Tests different decryption algorithms on pure EncodedData content
/// </summary>
public class EncodedDataDecryptor
{
    private readonly ILogger<EncodedDataDecryptor> _logger;
    private readonly RSLogixValidator _validator;

    public EncodedDataDecryptor(ILogger<EncodedDataDecryptor> logger, RSLogixValidator validator)
    {
        _logger = logger;
        _validator = validator;
    }

    /// <summary>
    /// Test key candidates against EncodedData content
    /// Returns top 8 promising results per pass
    /// </summary>
    public async Task<List<DecryptionCandidate>> TestKeyCandidatesAsync(
        Dictionary<string, string> encodedDataDict, 
        List<string> keyCandidates, 
        string phase)
    {
        var allCandidates = new List<DecryptionCandidate>();
        
        _logger.LogInformation("🧪 PLAN A Phase 2: Testing {KeyCount} candidates against {FileCount} files in {Phase}", 
            keyCandidates.Count, encodedDataDict.Count, phase);

        int tested = 0;
        foreach (var key in keyCandidates)
        {
            tested++;
            if (tested % 100 == 0)
            {
                _logger.LogInformation("🔄 {Phase}: Tested {Tested}/{Total} keys...", phase, tested, keyCandidates.Count);
            }

            // Test this key against all sample files
            var keyResults = await TestSingleKeyAsync(encodedDataDict, key);
            allCandidates.AddRange(keyResults);
        }

        // Sort by score and take top 8
        var topCandidates = allCandidates
            .OrderByDescending(c => c.ValidationResult.Score)
            .Take(8)
            .ToList();

        _logger.LogInformation("🎯 {Phase}: Found {Count} candidates, top 8 selected", phase, allCandidates.Count);
        
        foreach (var candidate in topCandidates)
        {
            _logger.LogInformation("🏆 Top candidate: {Candidate}", candidate);
        }

        return topCandidates;
    }

    /// <summary>
    /// Test a single key against all files
    /// </summary>
    private async Task<List<DecryptionCandidate>> TestSingleKeyAsync(
        Dictionary<string, string> encodedDataDict, 
        string key)
    {
        var candidates = new List<DecryptionCandidate>();

        foreach (var kvp in encodedDataDict)
        {
            var fileName = kvp.Key;
            var base64Content = kvp.Value;

            try
            {
                // Decode base64 to binary
                var encryptedData = Convert.FromBase64String(base64Content);
                
                // Try different decryption algorithms
                var decryptedContent = await TryDecryptionAlgorithmsAsync(encryptedData, key);
                
                if (!string.IsNullOrEmpty(decryptedContent))
                {
                    // Validate the decrypted content
                    var validation = _validator.ValidateDecryptedContent(decryptedContent, key);
                    
                    if (validation.Score > 0) // Any positive score is worth saving
                    {
                        candidates.Add(new DecryptionCandidate
                        {
                            FileName = fileName,
                            Key = key,
                            DecryptedContent = decryptedContent,
                            ValidationResult = validation
                        });
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("🔍 Key '{Key}' failed on {FileName}: {Error}", key, fileName, ex.Message);
            }
        }

        return candidates;
    }

    /// <summary>
    /// Try different decryption algorithms
    /// </summary>
    private async Task<string> TryDecryptionAlgorithmsAsync(byte[] encryptedData, string key)
    {
        // Try AES-CTR (V9 algorithm)
        var aesResult = await TryAESDecryptionAsync(encryptedData, key);
        if (!string.IsNullOrEmpty(aesResult)) return aesResult;

        // Try RC4 variants
        var rc4Result = await TryRC4DecryptionAsync(encryptedData, key);
        if (!string.IsNullOrEmpty(rc4Result)) return rc4Result;

        // Try simple XOR
        var xorResult = await TryXORDecryptionAsync(encryptedData, key);
        if (!string.IsNullOrEmpty(xorResult)) return xorResult;

        return "";
    }

    /// <summary>
    /// Try AES-CTR decryption (V9 algorithm)
    /// </summary>
    private async Task<string> TryAESDecryptionAsync(byte[] encryptedData, string key)
    {
        try
        {
            // Derive key using SHA256
            var keyBytes = DeriveKey(key, 32);
            
            // Try AES-CTR with different IV patterns
            var ivPatterns = new byte[][]
            {
                new byte[16], // All zeros
                Encoding.UTF8.GetBytes("0123456789ABCDEF").Take(16).ToArray(),
                keyBytes.Take(16).ToArray() // Key-derived IV
            };

            foreach (var iv in ivPatterns)
            {
                var result = TryAESCTRDecrypt(encryptedData, keyBytes, iv);
                if (IsTextLike(result))
                {
                    return Encoding.UTF8.GetString(result);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("AES decryption failed: {Error}", ex.Message);
        }

        return "";
    }

    /// <summary>
    /// Try RC4 decryption
    /// </summary>
    private async Task<string> TryRC4DecryptionAsync(byte[] encryptedData, string key)
    {
        try
        {
            // Try different key derivation methods
            var keyVariants = new[]
            {
                Encoding.UTF8.GetBytes(key),
                DeriveKey(key, 16),
                DeriveKey(key, 32),
                DeriveKey(key + "salt", 16)
            };

            foreach (var keyBytes in keyVariants)
            {
                var result = RC4Decrypt(encryptedData, keyBytes);
                if (IsTextLike(result))
                {
                    return Encoding.UTF8.GetString(result);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("RC4 decryption failed: {Error}", ex.Message);
        }

        return "";
    }

    /// <summary>
    /// Try XOR decryption
    /// </summary>
    private async Task<string> TryXORDecryptionAsync(byte[] encryptedData, string key)
    {
        try
        {
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var result = new byte[encryptedData.Length];

            for (int i = 0; i < encryptedData.Length; i++)
            {
                result[i] = (byte)(encryptedData[i] ^ keyBytes[i % keyBytes.Length]);
            }

            if (IsTextLike(result))
            {
                return Encoding.UTF8.GetString(result);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("XOR decryption failed: {Error}", ex.Message);
        }

        return "";
    }

    /// <summary>
    /// AES-CTR decryption implementation
    /// </summary>
    private byte[] TryAESCTRDecrypt(byte[] encryptedData, byte[] key, byte[] iv)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.ECB; // For CTR mode simulation
        
        var decrypted = new byte[encryptedData.Length];
        var counter = new byte[16];
        Array.Copy(iv, counter, 16);
        
        for (int i = 0; i < encryptedData.Length; i += 16)
        {
            var blockSize = Math.Min(16, encryptedData.Length - i);
            var encryptedCounter = new byte[16];
            
            using (var encryptor = aes.CreateEncryptor())
            {
                encryptor.TransformBlock(counter, 0, 16, encryptedCounter, 0);
            }
            
            for (int j = 0; j < blockSize; j++)
            {
                decrypted[i + j] = (byte)(encryptedData[i + j] ^ encryptedCounter[j]);
            }
            
            // Increment counter (big-endian)
            IncrementCounter(counter);
        }
        
        return decrypted;
    }

    /// <summary>
    /// RC4 decryption implementation
    /// </summary>
    private byte[] RC4Decrypt(byte[] data, byte[] key)
    {
        var s = new byte[256];
        var k = new byte[256];
        
        // Initialize
        for (int i = 0; i < 256; i++)
        {
            s[i] = (byte)i;
            k[i] = key[i % key.Length];
        }
        
        // KSA
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + k[i]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
        }
        
        // PRGA
        var result = new byte[data.Length];
        int x = 0, y = 0;
        
        for (int i = 0; i < data.Length; i++)
        {
            x = (x + 1) & 255;
            y = (y + s[x]) & 255;
            (s[x], s[y]) = (s[y], s[x]);
            result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) & 255]);
        }
        
        return result;
    }

    /// <summary>
    /// Derive key using SHA256
    /// </summary>
    private byte[] DeriveKey(string password, int keyLength)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
        var result = new byte[keyLength];
        Array.Copy(hash, result, Math.Min(keyLength, hash.Length));
        return result;
    }

    /// <summary>
    /// Increment counter for AES-CTR
    /// </summary>
    private void IncrementCounter(byte[] counter)
    {
        for (int i = counter.Length - 1; i >= 0; i--)
        {
            if (++counter[i] != 0) break;
        }
    }

    /// <summary>
    /// Check if data looks like text (not binary garbage)
    /// </summary>
    private bool IsTextLike(byte[] data)
    {
        if (data.Length < 10) return false;
        
        int printableCount = 0;
        int totalCount = Math.Min(data.Length, 1000); // Check first 1000 bytes
        
        for (int i = 0; i < totalCount; i++)
        {
            var b = data[i];
            if ((b >= 32 && b <= 126) || b == 9 || b == 10 || b == 13) // Printable + whitespace
            {
                printableCount++;
            }
        }
        
        return (double)printableCount / totalCount > 0.7; // 70% printable
    }
}

/// <summary>
/// Decryption candidate result
/// </summary>
public class DecryptionCandidate
{
    public string FileName { get; set; } = "";
    public string Key { get; set; } = "";
    public string DecryptedContent { get; set; } = "";
    public ValidationResult ValidationResult { get; set; } = new();
    
    public override string ToString()
    {
        return $"File={FileName}, Key={Key}, Score={ValidationResult.Score}, Valid={ValidationResult.IsValid}";
    }
}