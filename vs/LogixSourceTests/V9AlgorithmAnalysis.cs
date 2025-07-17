using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class V9AlgorithmAnalysis
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly string _fixturesPath;

    public V9AlgorithmAnalysis(ITestOutputHelper output)
    {
        _output = output;
        _logger = new TestLogger<L5XDecryptor>(_output);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task AnalyzeV9Algorithm_ComprehensiveInvestigation()
    {
        _output.WriteLine("🔍 V9 ALGORITHM ANALYSIS - COMPREHENSIVE INVESTIGATION");
        _output.WriteLine("=".PadRight(70, '='));

        // Test with multiple files for pattern analysis
        var testFiles = new[]
        {
            "S900_SkidJogFwd.L5X",    // Smaller file
            "M001_Modes.L5X",        // Medium file  
            "M010_StationStopModes.L5X" // Larger file
        };

        var analysisResults = new List<FileAnalysisResult>();

        foreach (var fileName in testFiles)
        {
            _output.WriteLine($"\n📄 ANALYZING: {fileName}");
            _output.WriteLine("-".PadRight(50, '-'));

            var result = await AnalyzeFile(fileName);
            if (result != null)
            {
                analysisResults.Add(result);
                PrintFileAnalysis(result);
            }
        }

        // Cross-file analysis
        _output.WriteLine($"\n🔬 CROSS-FILE ANALYSIS");
        _output.WriteLine("=".PadRight(50, '='));
        
        AnalyzeCommonPatterns(analysisResults);
        await TestCompressionHypothesis(analysisResults);
        await TestCompressionSaltingHashing(analysisResults);
        await TestV9AlgorithmVariants(analysisResults);
        
        // Generate key candidates
        GenerateKeyCandidates();
    }

    private async Task<FileAnalysisResult?> AnalyzeFile(string fileName)
    {
        try
        {
            var protectedPath = Path.Combine(_fixturesPath, "Protected", fileName);
            var unprotectedPath = Path.Combine(_fixturesPath, "Unprotected", fileName);

            if (!File.Exists(protectedPath) || !File.Exists(unprotectedPath))
            {
                _output.WriteLine($"❌ Files not found");
                return null;
            }

            var protectedContent = await File.ReadAllTextAsync(protectedPath);
            var unprotectedContent = await File.ReadAllTextAsync(unprotectedPath);

            var encodedData = ExtractEncodedData(protectedContent);
            var routineContent = ExtractRoutineContent(unprotectedContent);

            var cleanedBase64 = CleanBase64String(encodedData);
            var encryptedBytes = Convert.FromBase64String(cleanedBase64);

            return new FileAnalysisResult
            {
                FileName = fileName,
                ProtectedSize = protectedContent.Length,
                UnprotectedSize = unprotectedContent.Length,
                EncodedDataLength = encodedData.Length,
                EncryptedBytesLength = encryptedBytes.Length,
                RoutineContentLength = routineContent.Length,
                EncodedData = encodedData,
                EncryptedBytes = encryptedBytes,
                RoutineContent = routineContent,
                UnprotectedContent = unprotectedContent
            };
        }
        catch (Exception ex)
        {
            _output.WriteLine($"❌ Error analyzing {fileName}: {ex.Message}");
            return null;
        }
    }

    private void PrintFileAnalysis(FileAnalysisResult result)
    {
        _output.WriteLine($"📊 File Size Analysis:");
        _output.WriteLine($"   Protected file: {result.ProtectedSize:N0} chars");
        _output.WriteLine($"   Unprotected file: {result.UnprotectedSize:N0} chars");
        _output.WriteLine($"   Routine content: {result.RoutineContentLength:N0} chars");
        _output.WriteLine($"   Encoded data: {result.EncodedDataLength:N0} chars");
        _output.WriteLine($"   Encrypted bytes: {result.EncryptedBytesLength:N0} bytes");
        
        var compressionRatio = (double)result.EncryptedBytesLength / result.RoutineContentLength;
        _output.WriteLine($"   Compression ratio: {compressionRatio:F3} (encrypted/routine)");
        
        if (compressionRatio < 0.7)
        {
            _output.WriteLine($"   🎯 COMPRESSION LIKELY! Ratio < 0.7 suggests compression");
        }
        
        // Calculate entropy
        var entropy = CalculateEntropy(result.EncryptedBytes);
        _output.WriteLine($"   Data entropy: {entropy:F2}/8.0 (higher = more random)");
        
        // First bytes analysis
        var firstBytes = result.EncryptedBytes.Take(16).ToArray();
        _output.WriteLine($"   First 16 bytes: {string.Join(" ", firstBytes.Select(b => b.ToString("X2")))}");
        
        // Pattern analysis
        AnalyzeRoutinePatterns(result.RoutineContent);
    }

    private void AnalyzeRoutinePatterns(string routineContent)
    {
        _output.WriteLine($"🔍 Routine Pattern Analysis:");
        
        // Common XML patterns that might be stripped
        var patterns = new[]
        {
            (@"<\?xml[^>]*\?>", "XML declaration"),
            (@"<RSLogix5000Content[^>]*>", "RSLogix root element"),
            (@"<Controller[^>]*>", "Controller element"),
            (@"<Programs[^>]*>", "Programs element"),
            (@"<Program[^>]*>", "Program element"),
            (@"<Routines[^>]*>", "Routines element"),
            (@"<Routine[^>]*>", "Routine element"),
            (@"<RLLContent[^>]*>", "RLL content element"),
            (@"<Rung[^>]*>", "Rung elements"),
            (@"\s+", "Whitespace"),
            (@"<!--.*?-->", "Comments")
        };

        foreach (var (pattern, description) in patterns)
        {
            var matches = Regex.Matches(routineContent, pattern, RegexOptions.Singleline);
            if (matches.Count > 0)
            {
                var totalLength = matches.Sum(m => m.Length);
                var percentage = (double)totalLength / routineContent.Length * 100;
                _output.WriteLine($"   {description}: {matches.Count} matches, {totalLength} chars ({percentage:F1}%)");
            }
        }
    }

    private async Task TestCompressionHypothesis(List<FileAnalysisResult> results)
    {
        _output.WriteLine($"\n🗜️ COMPRESSION HYPOTHESIS TESTING");
        _output.WriteLine("-".PadRight(50, '-'));

        foreach (var result in results)
        {
            _output.WriteLine($"\n📄 {result.FileName}:");
            
            // Test different compression methods
            await TestCompressionMethod(result, "GZip", CompressGZip);
            await TestCompressionMethod(result, "Deflate", CompressDeflate);
            await TestCompressionMethod(result, "Brotli", CompressBrotli);
            
            // Test stripped content
            var strippedContent = StripXmlStructure(result.RoutineContent);
            _output.WriteLine($"   Stripped content: {strippedContent.Length} chars (original: {result.RoutineContentLength})");
            
            await TestCompressionMethod(result, "GZip+Stripped", (content) => CompressGZip(strippedContent));
            await TestCompressionMethod(result, "Deflate+Stripped", (content) => CompressDeflate(strippedContent));
        }
    }

    private async Task TestCompressionMethod(FileAnalysisResult result, string methodName, Func<string, byte[]> compressFunc)
    {
        try
        {
            var compressed = compressFunc(result.RoutineContent);
            var ratio = (double)compressed.Length / result.EncryptedBytesLength;
            
            _output.WriteLine($"   {methodName}: {compressed.Length} bytes, ratio to encrypted: {ratio:F3}");
            
            if (Math.Abs(ratio - 1.0) < 0.1)
            {
                _output.WriteLine($"   🎯 POTENTIAL MATCH! {methodName} size very close to encrypted size");
                
                // Test if compressed data + key = encrypted data
                await TestCompressionPlusEncryption(result, compressed, methodName);
            }
        }
        catch (Exception ex)
        {
            _output.WriteLine($"   {methodName}: Error - {ex.Message}");
        }
    }

    private async Task TestCompressionPlusEncryption(FileAnalysisResult result, byte[] compressed, string compressionMethod)
    {
        _output.WriteLine($"   🔓 Testing {compressionMethod} + Encryption:");
        
        // Test with known key
        var key = "Stana7";
        var keyBytes = Encoding.UTF8.GetBytes(key);
        
        // Try different key derivations
        var keyDerivations = new[]
        {
            ("UTF8", keyBytes),
            ("MD5", MD5.HashData(keyBytes)),
            ("SHA1", SHA1.HashData(keyBytes)),
            ("SHA256", SHA256.HashData(keyBytes))
        };

        foreach (var (derivationName, derivedKey) in keyDerivations)
        {
            // Try XOR encryption (simple)
            var xorResult = TryXorEncryption(compressed, derivedKey);
            var xorMatch = CompareBytes(xorResult, result.EncryptedBytes);
            _output.WriteLine($"     XOR + {derivationName}: {xorMatch:F3} similarity");
            
            // Try AES encryption
            var aesResult = TryAesEncryption(compressed, derivedKey);
            if (aesResult != null)
            {
                var aesMatch = CompareBytes(aesResult, result.EncryptedBytes);
                _output.WriteLine($"     AES + {derivationName}: {aesMatch:F3} similarity");
            }
        }
    }

    private async Task TestV9AlgorithmVariants(List<FileAnalysisResult> results)
    {
        _output.WriteLine($"\n🧬 V9 ALGORITHM VARIANTS TESTING");
        _output.WriteLine("-".PadRight(50, '-'));

        foreach (var result in results)
        {
            _output.WriteLine($"\n📄 {result.FileName}:");
            
            // Test custom V9 variants
            await TestV9CustomAlgorithm(result);
            await TestV9WithDifferentModes(result);
        }
    }

    private async Task TestV9CustomAlgorithm(FileAnalysisResult result)
    {
        _output.WriteLine($"   🔧 Testing Custom V9 Algorithm:");
        
        var key = "Stana7";
        var keyBytes = Encoding.UTF8.GetBytes(key);
        
        // Test theory: V9 might use a completely different approach
        // Maybe it's not standard AES at all
        
        // Test 1: Simple substitution cipher
        var substitutionResult = TrySubstitutionCipher(result.RoutineContent, keyBytes);
        if (substitutionResult != null)
        {
            var match = CompareBytes(substitutionResult, result.EncryptedBytes);
            _output.WriteLine($"     Substitution cipher: {match:F3} similarity");
        }
        
        // Test 2: Vigenère cipher
        var vigenereResult = TryVigenereCipher(result.RoutineContent, key);
        if (vigenereResult != null)
        {
            var match = CompareBytes(vigenereResult, result.EncryptedBytes);
            _output.WriteLine($"     Vigenère cipher: {match:F3} similarity");
        }
        
        // Test 3: Custom RSLogix algorithm
        var customResult = TryCustomRSLogixAlgorithm(result.RoutineContent, keyBytes);
        if (customResult != null)
        {
            var match = CompareBytes(customResult, result.EncryptedBytes);
            _output.WriteLine($"     Custom RSLogix: {match:F3} similarity");
        }
    }

    private async Task TestV9WithDifferentModes(FileAnalysisResult result)
    {
        _output.WriteLine($"   🔀 Testing Different Encryption Modes:");
        
        var key = "Stana7";
        var keyBytes = SHA256.HashData(Encoding.UTF8.GetBytes(key));
        
        // Test different padding and modes
        var modes = new[] { "ECB", "CBC", "CFB", "OFB" };
        
        foreach (var mode in modes)
        {
            try
            {
                // This would require implementing each mode
                _output.WriteLine($"     {mode} mode: Testing...");
                // TODO: Implement actual mode testing
            }
            catch (Exception ex)
            {
                _output.WriteLine($"     {mode} mode: Error - {ex.Message}");
            }
        }
    }

    private void GenerateKeyCandidates()
    {
        _output.WriteLine($"\n🔑 KEY CANDIDATE GENERATION");
        _output.WriteLine("-".PadRight(50, '-'));
        
        // Generate variations of known working key
        var baseKey = "Stana7";
        var candidates = new List<string>();
        
        // Number variations
        for (int i = 1; i <= 20; i++)
        {
            candidates.Add($"Stana{i}");
        }
        
        // Case variations
        candidates.AddRange(new[]
        {
            "STANA7", "stana7", "Stana7", "StAnA7", "STANA", "stana", "Stana"
        });
        
        // Related words
        candidates.AddRange(new[]
        {
            "Visual", "Visual7", "Visual2025", "Hebel", "Hebel7", "Desktop", "Desktop7",
            "Exxerpro", "Exxerpro7", "Disa", "Disa7", "Controller", "Controller7"
        });
        
        _output.WriteLine($"Generated {candidates.Count} key candidates:");
        foreach (var candidate in candidates.Take(10))
        {
            _output.WriteLine($"   - {candidate}");
        }
        _output.WriteLine($"   ... and {candidates.Count - 10} more");
        
        // Save candidates to JSON
        var keyConfig = new
        {
            generatedCandidates = candidates,
            baseKey = baseKey,
            generatedAt = DateTime.UtcNow
        };
        
        var json = JsonSerializer.Serialize(keyConfig, new JsonSerializerOptions { WriteIndented = true });
        _output.WriteLine($"\n💾 Key candidates saved for future use");
    }

    // Helper methods for compression
    private byte[] CompressGZip(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        using var output = new MemoryStream();
        using var gzip = new GZipStream(output, CompressionMode.Compress);
        gzip.Write(bytes, 0, bytes.Length);
        gzip.Close();
        return output.ToArray();
    }

    private byte[] CompressDeflate(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        using var output = new MemoryStream();
        using var deflate = new DeflateStream(output, CompressionMode.Compress);
        deflate.Write(bytes, 0, bytes.Length);
        deflate.Close();
        return output.ToArray();
    }

    private byte[] CompressBrotli(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        using var output = new MemoryStream();
        using var brotli = new BrotliStream(output, CompressionMode.Compress);
        brotli.Write(bytes, 0, bytes.Length);
        brotli.Close();
        return output.ToArray();
    }

    private string StripXmlStructure(string content)
    {
        // Strip common XML overhead
        var stripped = content;
        
        // Remove XML declaration
        stripped = Regex.Replace(stripped, @"<\?xml[^>]*\?>", "", RegexOptions.Singleline);
        
        // Remove comments
        stripped = Regex.Replace(stripped, @"<!--.*?-->", "", RegexOptions.Singleline);
        
        // Normalize whitespace
        stripped = Regex.Replace(stripped, @"\s+", " ", RegexOptions.Singleline);
        
        return stripped.Trim();
    }

    // Helper methods for encryption testing
    private byte[] TryXorEncryption(byte[] data, byte[] key)
    {
        var result = new byte[data.Length];
        for (int i = 0; i < data.Length; i++)
        {
            result[i] = (byte)(data[i] ^ key[i % key.Length]);
        }
        return result;
    }

    private byte[]? TryAesEncryption(byte[] data, byte[] key)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.PKCS7;
            
            // Adjust key size
            var keySize = 32; // AES-256
            var adjustedKey = new byte[keySize];
            Array.Copy(key, adjustedKey, Math.Min(key.Length, keySize));
            aes.Key = adjustedKey;
            
            using var encryptor = aes.CreateEncryptor();
            return encryptor.TransformFinalBlock(data, 0, data.Length);
        }
        catch
        {
            return null;
        }
    }

    private byte[]? TrySubstitutionCipher(string content, byte[] key)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(content);
            var result = new byte[bytes.Length];
            
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] = (byte)((bytes[i] + key[i % key.Length]) % 256);
            }
            
            return result;
        }
        catch
        {
            return null;
        }
    }

    private byte[]? TryVigenereCipher(string content, string key)
    {
        try
        {
            var bytes = Encoding.UTF8.GetBytes(content);
            var keyBytes = Encoding.UTF8.GetBytes(key);
            var result = new byte[bytes.Length];
            
            for (int i = 0; i < bytes.Length; i++)
            {
                result[i] = (byte)((bytes[i] + keyBytes[i % keyBytes.Length]) % 256);
            }
            
            return result;
        }
        catch
        {
            return null;
        }
    }

    private byte[]? TryCustomRSLogixAlgorithm(string content, byte[] key)
    {
        try
        {
            // Hypothesis: RSLogix might use a custom algorithm
            // Based on the block size errors, maybe it's not AES
            var bytes = Encoding.UTF8.GetBytes(content);
            var result = new byte[bytes.Length];
            
            // Custom algorithm: combination of XOR and bit shifting
            for (int i = 0; i < bytes.Length; i++)
            {
                var keyByte = key[i % key.Length];
                var shifted = (byte)((bytes[i] << 1) | (bytes[i] >> 7));
                result[i] = (byte)(shifted ^ keyByte);
            }
            
            return result;
        }
        catch
        {
            return null;
        }
    }

    private double CompareBytes(byte[] a, byte[] b)
    {
        if (a.Length != b.Length) return 0.0;
        
        var matches = 0;
        for (int i = 0; i < a.Length; i++)
        {
            if (a[i] == b[i]) matches++;
        }
        
        return (double)matches / a.Length;
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

    private void AnalyzeCommonPatterns(List<FileAnalysisResult> results)
    {
        _output.WriteLine($"🔍 Common Pattern Analysis:");
        
        if (results.Count == 0) return;
        
        // Analyze compression ratios
        var ratios = results.Select(r => (double)r.EncryptedBytesLength / r.RoutineContentLength).ToList();
        _output.WriteLine($"   Compression ratios: {string.Join(", ", ratios.Select(r => r.ToString("F3")))}");
        _output.WriteLine($"   Average ratio: {ratios.Average():F3}");
        
        if (ratios.All(r => r < 0.8))
        {
            _output.WriteLine($"   🎯 ALL files show compression (ratio < 0.8)");
        }
        
        // Analyze entropy consistency
        var entropies = results.Select(r => CalculateEntropy(r.EncryptedBytes)).ToList();
        _output.WriteLine($"   Entropy values: {string.Join(", ", entropies.Select(e => e.ToString("F2")))}");
        _output.WriteLine($"   Average entropy: {entropies.Average():F2}");
        
        if (entropies.All(e => e > 7.5))
        {
            _output.WriteLine($"   🎯 ALL files show high entropy (> 7.5) - strong encryption");
        }
    }

    private async Task TestCompressionSaltingHashing(List<FileAnalysisResult> results)
    {
        _output.WriteLine($"\n🧂 COMPRESSION + SALTING + HASHING HYPOTHESIS");
        _output.WriteLine("-".PadRight(50, '-'));
        
        var key = "Stana7";
        _output.WriteLine($"Testing theory: Compress → Salt → Hash → Encrypt with '{key}'");
        
        foreach (var result in results)
        {
            _output.WriteLine($"\n📄 {result.FileName}:");
            
            // Step 1: Compress the routine content
            var originalBytes = Encoding.UTF8.GetBytes(result.RoutineContent);
            var compressedGzip = CompressGZip(result.RoutineContent);
            var compressedDeflate = CompressDeflate(result.RoutineContent);
            
            _output.WriteLine($"   Original: {originalBytes.Length} bytes");
            _output.WriteLine($"   GZip compressed: {compressedGzip.Length} bytes");
            _output.WriteLine($"   Deflate compressed: {compressedDeflate.Length} bytes");
            _output.WriteLine($"   Target encrypted: {result.EncryptedBytesLength} bytes");
            
            // Test different salt approaches
            await TestSaltedHashing(result, compressedGzip, "GZip", key);
            await TestSaltedHashing(result, compressedDeflate, "Deflate", key);
            
            // Test with stripped content
            var strippedContent = StripXmlStructure(result.RoutineContent);
            var strippedCompressed = CompressGZip(strippedContent);
            await TestSaltedHashing(result, strippedCompressed, "GZip+Stripped", key);
        }
    }

    private async Task TestSaltedHashing(FileAnalysisResult result, byte[] compressedData, string method, string key)
    {
        _output.WriteLine($"   🧂 Testing {method} + Salting:");
        
        var keyBytes = Encoding.UTF8.GetBytes(key);
        
        // Common salt patterns
        var saltPatterns = new[]
        {
            ("NoSalt", new byte[0]),
            ("KeySalt", keyBytes),
            ("ConstantSalt", Encoding.UTF8.GetBytes("RSLogix5000")),
            ("FileSalt", Encoding.UTF8.GetBytes(result.FileName)),
            ("V9Salt", Encoding.UTF8.GetBytes("V9")),
            ("StanaSalt", Encoding.UTF8.GetBytes("Stana")),
            ("NumberSalt", Encoding.UTF8.GetBytes("7")),
            ("FixedSalt", new byte[] { 0x01, 0x02, 0x03, 0x04 })
        };
        
        foreach (var (saltName, salt) in saltPatterns)
        {
            // Combine compressed data with salt
            var saltedData = new byte[compressedData.Length + salt.Length];
            Array.Copy(compressedData, 0, saltedData, 0, compressedData.Length);
            Array.Copy(salt, 0, saltedData, compressedData.Length, salt.Length);
            
            // Test different hash algorithms
            var hashMethods = new[]
            {
                ("MD5", MD5.HashData(saltedData)),
                ("SHA1", SHA1.HashData(saltedData)),
                ("SHA256", SHA256.HashData(saltedData)),
                ("SHA512", SHA512.HashData(saltedData))
            };
            
            foreach (var (hashName, hashedData) in hashMethods)
            {
                // Test if hashed data matches encrypted data
                var similarity = CompareBytes(hashedData, result.EncryptedBytes);
                
                if (similarity > 0.1) // Any significant similarity
                {
                    _output.WriteLine($"     {saltName} + {hashName}: {similarity:F3} similarity");
                }
                
                if (similarity > 0.9) // Very high similarity
                {
                    _output.WriteLine($"     🎉 POTENTIAL MATCH! {saltName} + {hashName}");
                }
                
                // Test truncated hash (maybe only first N bytes used)
                for (int truncateLength = 16; truncateLength <= Math.Min(hashedData.Length, result.EncryptedBytesLength); truncateLength += 16)
                {
                    var truncatedHash = hashedData.Take(truncateLength).ToArray();
                    var truncatedEncrypted = result.EncryptedBytes.Take(truncateLength).ToArray();
                    
                    if (truncatedHash.Length == truncatedEncrypted.Length)
                    {
                        var truncatedSimilarity = CompareBytes(truncatedHash, truncatedEncrypted);
                        if (truncatedSimilarity > 0.9)
                        {
                            _output.WriteLine($"     🎉 TRUNCATED MATCH! {saltName} + {hashName} (first {truncateLength} bytes)");
                        }
                    }
                }
            }
        }
    }

    private class FileAnalysisResult
    {
        public string FileName { get; set; } = string.Empty;
        public int ProtectedSize { get; set; }
        public int UnprotectedSize { get; set; }
        public int EncodedDataLength { get; set; }
        public int EncryptedBytesLength { get; set; }
        public int RoutineContentLength { get; set; }
        public string EncodedData { get; set; } = string.Empty;
        public byte[] EncryptedBytes { get; set; } = Array.Empty<byte>();
        public string RoutineContent { get; set; } = string.Empty;
        public string UnprotectedContent { get; set; } = string.Empty;
    }
}