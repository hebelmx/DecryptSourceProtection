using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class V9BlockAnalysis
{
    static void Main(string[] args)
    {
        Console.WriteLine("🔍 V9 ENCRYPTION BLOCK ANALYSIS");
        Console.WriteLine("=" + new string('=', 50));
        
        var fileSets = new[]
        {
            ("V33 Known Files", "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", new[]
            {
                "S025_SkidIndexInVDL.L5X",      // Known working
                "S005_STP1Advance.L5X",        // Target
                "S010_STP1Return.L5X",         // Target
                "S015_STP2Advance.L5X",        // Target
                "S020_STP2Return.L5X",         // Target
                "S025_SkidIndexOut_Clear.L5X"  // Target
            }),
            ("V30 Unknown Files", "/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", new[]
            {
                "_050_SP_MANFREM.L5X",         // Unknown 1
                "_051_PPLAASEUD.L5X",          // Unknown 2
                "_052_PPLAASEIND.L5X",         // Unknown 3
                "_053_SPLAASEUD.L5X"           // Unknown 4
            })
        };

        Console.WriteLine("📊 ANALYZING ENCRYPTED BLOCKS TO CRACK THE CODE");
        Console.WriteLine("🔍 COMPARING V33 (KNOWN) vs V30 (UNKNOWN) PATTERNS");
        Console.WriteLine();

        var allHeaders = new List<(string FileSet, string FileName, string Header)>();
        var allPatterns = new List<(string FileSet, string FileName, string RoutineName, int Length, double Entropy, string Header)>();

        foreach (var (setName, basePath, files) in fileSets)
        {
            Console.WriteLine($"📁 {setName}");
            Console.WriteLine("=" + new string('=', 50));

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
                    
                    // Extract routine name from TargetName attribute
                    var routineMatch = Regex.Match(content, @"TargetName=""([^""]*)""\s+TargetType=""Routine""", RegexOptions.Singleline);
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
                        var entropy = AnalyzeEncryptedBlock(encryptedBytes, routineName);
                        
                        // Get header for comparison
                        var firstBytes = encryptedBytes.Take(16).ToArray();
                        var header = Convert.ToHexString(firstBytes);
                        
                        allHeaders.Add((setName, fileName, header));
                        allPatterns.Add((setName, fileName, routineName, encryptedBytes.Length, entropy, header));
                        
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

        // Cross-analysis between V33 and V30
        Console.WriteLine("🔍 CROSS-ANALYSIS: V33 vs V30 PATTERNS");
        Console.WriteLine("=" + new string('=', 50));
        
        AnalyzeCrossPatterns(allHeaders, allPatterns);
    }

    static double AnalyzeEncryptedBlock(byte[] encryptedBytes, string routineName)
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
        
        return entropy;
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
                ("SHA256-separated", SHA256.HashData(Encoding.UTF8.GetBytes(key + "|" + salt))),
                ("SHA256-underscore", SHA256.HashData(Encoding.UTF8.GetBytes(key + "_" + salt))),
                ("SHA256-colon", SHA256.HashData(Encoding.UTF8.GetBytes(key + ":" + salt))),
                ("SHA256-mixed", SHA256.HashData(Encoding.UTF8.GetBytes(salt + "_" + key)))
            };

            foreach (var (hashName, hashedKey) in combinations)
            {
                // Try AES decryption with different modes
                var aesResults = new[]
                {
                    ("AES-ECB", TryAESDecrypt(encryptedBytes, hashedKey)),
                    ("AES-CBC-ZeroIV", TryAESDecryptCBC(encryptedBytes, hashedKey, new byte[16])),
                    ("AES-CBC-KeyIV", TryAESDecryptCBC(encryptedBytes, hashedKey, hashedKey.Take(16).ToArray()))
                };

                foreach (var (aesMode, result) in aesResults)
                {
                    if (result.Success)
                    {
                        Console.WriteLine($"   🎯 POTENTIAL MATCH: {hashName}({key} + {salt}) with {aesMode}");
                        Console.WriteLine($"   📝 Decrypted length: {result.Content.Length}");
                        if (result.Content.Contains("<") && result.Content.Contains(">"))
                        {
                            Console.WriteLine($"   ✅ CONTAINS XML - REAL BREAKTHROUGH!");
                            Console.WriteLine($"   🔍 First 200 chars: {result.Content.Substring(0, Math.Min(200, result.Content.Length))}");
                            return; // Found it!
                        }
                        else if (result.Content.Length > 100)
                        {
                            Console.WriteLine($"   📋 Large decrypted content - might be valid");
                            Console.WriteLine($"   🔍 First 100 chars: {result.Content.Substring(0, Math.Min(100, result.Content.Length))}");
                        }
                    }
                }
            }
        }
        
        Console.WriteLine($"   ❌ No matches found for routine name salting");
    }

    static void AnalyzeCrossPatterns(List<(string FileSet, string FileName, string Header)> allHeaders, 
                                    List<(string FileSet, string FileName, string RoutineName, int Length, double Entropy, string Header)> allPatterns)
    {
        Console.WriteLine("🔍 HEADER PATTERN COMPARISON:");
        Console.WriteLine("-" + new string('-', 70));
        
        // Group headers by pattern
        var headerGroups = allHeaders.GroupBy(h => h.Header).ToList();
        
        foreach (var group in headerGroups)
        {
            Console.WriteLine($"📍 Header: {group.Key}");
            foreach (var (fileSet, fileName, header) in group)
            {
                Console.WriteLine($"   {fileSet}: {fileName}");
            }
            Console.WriteLine();
        }
        
        // Find common headers between V33 and V30
        var v33Headers = allHeaders.Where(h => h.FileSet.Contains("V33")).Select(h => h.Header).ToHashSet();
        var v30Headers = allHeaders.Where(h => h.FileSet.Contains("V30")).Select(h => h.Header).ToHashSet();
        var commonHeaders = v33Headers.Intersect(v30Headers).ToList();
        
        Console.WriteLine("🎯 COMMON HEADERS BETWEEN V33 AND V30:");
        Console.WriteLine("-" + new string('-', 50));
        
        if (commonHeaders.Any())
        {
            foreach (var header in commonHeaders)
            {
                Console.WriteLine($"✅ SHARED: {header}");
                var v33Files = allHeaders.Where(h => h.Header == header && h.FileSet.Contains("V33")).Select(h => h.FileName);
                var v30Files = allHeaders.Where(h => h.Header == header && h.FileSet.Contains("V30")).Select(h => h.FileName);
                Console.WriteLine($"   V33: {string.Join(", ", v33Files)}");
                Console.WriteLine($"   V30: {string.Join(", ", v30Files)}");
                Console.WriteLine();
            }
        }
        else
        {
            Console.WriteLine("❌ No common headers found between V33 and V30");
        }
        
        // Entropy analysis
        Console.WriteLine("📊 ENTROPY ANALYSIS:");
        Console.WriteLine("-" + new string('-', 50));
        
        var v33Entropies = allPatterns.Where(p => p.FileSet.Contains("V33")).Select(p => p.Entropy);
        var v30Entropies = allPatterns.Where(p => p.FileSet.Contains("V30")).Select(p => p.Entropy);
        
        if (v33Entropies.Any())
            Console.WriteLine($"V33 Entropy Range: {v33Entropies.Min():F2} - {v33Entropies.Max():F2} (avg: {v33Entropies.Average():F2})");
        else
            Console.WriteLine("V33 Entropy: No data");
            
        if (v30Entropies.Any())
            Console.WriteLine($"V30 Entropy Range: {v30Entropies.Min():F2} - {v30Entropies.Max():F2} (avg: {v30Entropies.Average():F2})");
        else
            Console.WriteLine("V30 Entropy: No data");
        
        // Size analysis
        Console.WriteLine("\n📏 SIZE ANALYSIS:");
        Console.WriteLine("-" + new string('-', 50));
        
        var v33Sizes = allPatterns.Where(p => p.FileSet.Contains("V33")).Select(p => p.Length);
        var v30Sizes = allPatterns.Where(p => p.FileSet.Contains("V30")).Select(p => p.Length);
        
        if (v33Sizes.Any())
            Console.WriteLine($"V33 Size Range: {v33Sizes.Min():N0} - {v33Sizes.Max():N0} bytes");
        else
            Console.WriteLine("V33 Size: No data");
            
        if (v30Sizes.Any())
            Console.WriteLine($"V30 Size Range: {v30Sizes.Min():N0} - {v30Sizes.Max():N0} bytes");
        else
            Console.WriteLine("V30 Size: No data");
        
        // Look for potential partial matches
        Console.WriteLine("\n🔍 LOOKING FOR PARTIAL SUCCESSES:");
        Console.WriteLine("-" + new string('-', 50));
        
        TestPartialMatches(allPatterns);
    }

    static void TestPartialMatches(List<(string FileSet, string FileName, string RoutineName, int Length, double Entropy, string Header)> allPatterns)
    {
        Console.WriteLine("🧪 Testing for scrambled/partial content indicators:");
        
        // Look for entropy patterns that might indicate partial decryption
        var v33Pattern = allPatterns.FirstOrDefault(p => p.FileSet.Contains("V33") && p.FileName.Contains("S025_SkidIndexInVDL"));
        if (v33Pattern.FileSet != null)
        {
            Console.WriteLine($"📊 Baseline (working): {v33Pattern.FileName} - Entropy: {v33Pattern.Entropy:F2}");
            
            // Look for V30 files with similar entropy
            var similarEntropy = allPatterns.Where(p => p.FileSet.Contains("V30") && 
                                                  Math.Abs(p.Entropy - v33Pattern.Entropy) < 0.1).ToList();
            
            if (similarEntropy.Any())
            {
                Console.WriteLine("🎯 V30 files with similar entropy (potential partial success):");
                foreach (var file in similarEntropy)
                {
                    Console.WriteLine($"   {file.FileName}: {file.Entropy:F2} (diff: {Math.Abs(file.Entropy - v33Pattern.Entropy):F3})");
                }
            }
        }
        
        // Look for size correlations
        var v33Sizes = allPatterns.Where(p => p.FileSet.Contains("V33")).Select(p => p.Length).ToList();
        var v30Sizes = allPatterns.Where(p => p.FileSet.Contains("V30")).Select(p => p.Length).ToList();
        
        Console.WriteLine($"\n📏 Size correlations:");
        Console.WriteLine($"   V33 sizes: {string.Join(", ", v33Sizes.Select(s => s.ToString("N0")))}");
        Console.WriteLine($"   V30 sizes: {string.Join(", ", v30Sizes.Select(s => s.ToString("N0")))}");
        
        // Check if any V30 sizes match V33 sizes (might indicate same content length)
        var sizematches = v30Sizes.Where(v30Size => v33Sizes.Any(v33Size => Math.Abs(v30Size - v33Size) < 100)).ToList();
        if (sizematches.Any())
        {
            Console.WriteLine("🎯 V30 files with similar sizes to V33 (potential correlation):");
            foreach (var v30Size in sizematches)
            {
                var v30File = allPatterns.First(p => p.FileSet.Contains("V30") && p.Length == v30Size);
                var closestV33 = allPatterns.Where(p => p.FileSet.Contains("V33"))
                                          .OrderBy(p => Math.Abs(p.Length - v30Size))
                                          .First();
                Console.WriteLine($"   {v30File.FileName} ({v30Size:N0}) ≈ {closestV33.FileName} ({closestV33.Length:N0})");
            }
        }
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

    static (bool Success, string Content) TryAESDecryptCBC(byte[] encryptedBytes, byte[] key, byte[] iv)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            
            // Adjust key to 32 bytes for AES-256
            var keyBytes = new byte[32];
            Array.Copy(key, keyBytes, Math.Min(key.Length, 32));
            aes.Key = keyBytes;
            
            // Adjust IV to 16 bytes
            var ivBytes = new byte[16];
            Array.Copy(iv, ivBytes, Math.Min(iv.Length, 16));
            aes.IV = ivBytes;
            
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