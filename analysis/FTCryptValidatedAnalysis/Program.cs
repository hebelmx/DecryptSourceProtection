using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("🚨 FTCrypt.dll VALIDATED ARC4(256) IMPLEMENTATION");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine("🎯 Based on FTCrypt.dll Analysis: ARC4(256) + RC4_drop + PBKDF2");
        Console.WriteLine("🔍 Testing: Exact FTCrypt algorithms vs dictionary attack candidates");
        Console.WriteLine("📊 Target: 100% success rate on V33 + crack all V30 unknown files");
        Console.WriteLine();

        // Extract comprehensive dictionary for validation
        var dictionary = ExtractRSLogixKeywords();
        Console.WriteLine($"📚 Dictionary loaded: {dictionary.Count} keywords for validation");
        
        // Test files - prioritize based on previous success
        var testFiles = new[]
        {
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S025_SkidIndexInVDL.L5X", "V33 Known"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S005_STP1Advance.L5X", "V33 Known"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S010_STP1Return.L5X", "V33 Known"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_050_SP_MANFREM.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_051_PPLAASEUD.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_052_PPLAASEIND.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_053_SPLAASEUD.L5X", "V30 Unknown")
        };

        var globalResults = new List<(string fileName, string algorithm, string keyDerivation, int keywords, string sample, bool isFullDecryption)>();

        foreach (var (basePath, fileName, category) in testFiles)
        {
            Console.WriteLine($"\n🎯 ANALYZING: {fileName} ({category})");
            Console.WriteLine("=" + new string('=', 70));
            
            try
            {
                var filePath = Path.Combine(basePath, fileName);
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"❌ File not found: {fileName}");
                    continue;
                }
                
                var encryptedBytes = ExtractEncryptedBytes(filePath);
                if (encryptedBytes == null)
                {
                    Console.WriteLine($"❌ Failed to extract encrypted bytes from: {fileName}");
                    continue;
                }
                
                Console.WriteLine($"📦 Encrypted bytes: {encryptedBytes.Length:N0}");
                
                // Run FTCrypt validated analysis
                var results = RunFTCryptValidatedAnalysis(encryptedBytes, dictionary, fileName);
                
                // Add to global results
                globalResults.AddRange(results.Select(r => (fileName, r.algorithm, r.keyDerivation, r.keywords, r.sample, r.isFullDecryption)));
                
                // Report top candidates for this file
                ReportTopCandidates(fileName, results);
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 Error analyzing {fileName}: {ex.Message}");
            }
        }
        
        // Global analysis across all files
        Console.WriteLine("\n🌟 GLOBAL ANALYSIS: FTCRYPT VALIDATED RESULTS");
        Console.WriteLine("=" + new string('=', 80));
        AnalyzeGlobalResults(globalResults);
    }

    static List<(string algorithm, string keyDerivation, int keywords, string sample, bool isFullDecryption)> RunFTCryptValidatedAnalysis(
        byte[] encryptedBytes, HashSet<string> dictionary, string fileName)
    {
        var results = new List<(string algorithm, string keyDerivation, int keywords, string sample, bool isFullDecryption)>();
        
        Console.WriteLine("🔍 FTCRYPT VALIDATED ARC4(256) ANALYSIS");
        Console.WriteLine("-" + new string('-', 50));
        
        // Enhanced key generation based on FTCrypt.dll + Dictionary Attack findings
        var keyGenerators = GenerateFTCryptValidatedKeys(fileName);
        
        // ARC4(256) variants based on FTCrypt.dll analysis
        var arc4Methods = new[]
        {
            ("ARC4-256", new Func<byte[], byte[], (bool, string)>((data, key) => TryARC4_256_Decrypt(data, key))),
            ("ARC4-256-Drop", new Func<byte[], byte[], (bool, string)>((data, key) => TryARC4_256_Drop_Decrypt(data, key))),
            ("ARC4-256-Skip", new Func<byte[], byte[], (bool, string)>((data, key) => TryARC4_256_Skip_Decrypt(data, key))),
            ("RC4-Botan", new Func<byte[], byte[], (bool, string)>((data, key) => TryRC4_BotanStyle_Decrypt(data, key))),
            ("RC4-Standard", new Func<byte[], byte[], (bool, string)>((data, key) => TryRC4_Standard_Decrypt(data, key)))
        };
        
        int totalTests = 0;
        int successfulTests = 0;
        
        foreach (var (methodName, decryptFunc) in arc4Methods)
        {
            Console.WriteLine($"\n📊 Testing FTCrypt method: {methodName}");
            
            foreach (var (keyName, keyBytes) in keyGenerators)
            {
                totalTests++;
                
                try
                {
                    // Try ARC4 decryption
                    var (success, decryptedText) = decryptFunc(encryptedBytes, keyBytes);
                    if (!success || string.IsNullOrEmpty(decryptedText) || decryptedText.Length < 50) continue;
                    
                    // Count keyword matches
                    var keywordMatches = CountKeywordMatches(decryptedText, dictionary);
                    
                    // Check if this looks like full XML decryption
                    var isFullDecryption = IsFullXMLDecryption(decryptedText);
                    
                    if (keywordMatches > 0 || isFullDecryption)
                    {
                        successfulTests++;
                        var sample = decryptedText.Length > 200 ? decryptedText.Substring(0, 200) : decryptedText;
                        results.Add((methodName, keyName, keywordMatches, sample, isFullDecryption));
                        
                        Console.WriteLine($"🎯 CANDIDATE: {methodName} with {keyName}");
                        Console.WriteLine($"   Keywords: {keywordMatches}");
                        Console.WriteLine($"   Full XML: {(isFullDecryption ? "YES" : "NO")}");
                        Console.WriteLine($"   Length: {decryptedText.Length:N0} chars");
                        Console.WriteLine($"   Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
                        Console.WriteLine();
                        
                        // If we found complete XML decryption, this is a breakthrough
                        if (isFullDecryption)
                        {
                            Console.WriteLine("🚨 BREAKTHROUGH: Complete XML decryption achieved!");
                            Console.WriteLine($"   Algorithm: {methodName}");
                            Console.WriteLine($"   Key: {keyName}");
                            Console.WriteLine($"   Full sample: {decryptedText.Substring(0, Math.Min(1000, decryptedText.Length))}");
                            Console.WriteLine();
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Silent failure - many combinations will fail
                }
            }
        }
        
        Console.WriteLine($"📈 Test summary: {successfulTests}/{totalTests} combinations successful ({(100.0 * successfulTests / totalTests):F1}%)");
        
        return results;
    }

    static List<(string keyName, byte[] keyBytes)> GenerateFTCryptValidatedKeys(string fileName)
    {
        var keys = new List<(string keyName, byte[] keyBytes)>();
        
        // Top candidates from dictionary attack + FTCrypt.dll analysis
        var baseKeys = new[] { "Stana7", "defaultkey", "Visual2025", "RSLogix5000", "testkey", "admin" };
        
        // Enhanced salt generation based on findings
        var salts = GenerateValidatedSalts(fileName);
        
        // Separators that showed success in dictionary attack
        var separators = new[] { "|", "+", "_", ":", "-", ".", "", "#" };
        
        // Hash algorithms prioritized by FTCrypt.dll findings and dictionary attack success
        var hashAlgorithms = new (string name, Func<string, byte[]> func)[]
        {
            // FTCrypt.dll confirmed algorithms
            ("SHA256", s => SHA256.HashData(Encoding.UTF8.GetBytes(s))),
            ("SHA1", s => SHA1.HashData(Encoding.UTF8.GetBytes(s))),  // PBKDF2(SHA-1) found in FTCrypt
            ("MD5", s => MD5.HashData(Encoding.UTF8.GetBytes(s))),   // MD5 found in FTCrypt
            ("SHA512", s => SHA512.HashData(Encoding.UTF8.GetBytes(s))), // SHA-512 found in FTCrypt
            
            // PBKDF2 variants (found in FTCrypt.dll)
            ("PBKDF2-SHA1", s => PBKDF2DeriveKey(s, "RSLogix", 1000, 32)),
            ("PBKDF2-SHA256", s => PBKDF2DeriveKey(s, "V9", 1000, 32)),
            
            // Direct key (for completeness)
            ("Direct", s => PadKeyTo256Bits(Encoding.UTF8.GetBytes(s)))
        };
        
        foreach (var baseKey in baseKeys)
        {
            foreach (var salt in salts)
            {
                foreach (var separator in separators)
                {
                    foreach (var (hashName, hashFunc) in hashAlgorithms)
                    {
                        // Forward combination (key + separator + salt)
                        var forwardKey = baseKey + separator + salt;
                        var forwardHash = hashFunc(forwardKey);
                        keys.Add(($"{hashName}({baseKey}{separator}{salt})", forwardHash));
                        
                        // Reverse combination (salt + separator + key)
                        var reverseKey = salt + separator + baseKey;
                        var reverseHash = hashFunc(reverseKey);
                        keys.Add(($"{hashName}({salt}{separator}{baseKey})", reverseHash));
                        
                        // Double hash (Hash(Hash(key)))
                        var doubleHash = hashFunc(Convert.ToHexString(hashFunc(forwardKey)).ToLower());
                        keys.Add(($"Double{hashName}({baseKey}{separator}{salt})", doubleHash));
                    }
                }
            }
        }
        
        Console.WriteLine($"🔑 Generated {keys.Count} FTCrypt-validated key combinations");
        return keys;
    }

    static List<string> GenerateValidatedSalts(string fileName)
    {
        var salts = new List<string>();
        
        // File-specific salts (successful in dictionary attack)
        salts.Add(fileName);
        salts.Add(Path.GetFileNameWithoutExtension(fileName));
        salts.Add(fileName.ToUpper());
        salts.Add(fileName.ToLower());
        
        // Extract routine name from filename
        var routineName = ExtractRoutineName(fileName);
        if (!string.IsNullOrEmpty(routineName))
        {
            salts.Add(routineName);
            salts.Add(routineName.ToUpper());
            salts.Add(routineName.ToLower());
        }
        
        // Top successful salts from dictionary attack
        var topSalts = new[] { 
            "encryption", "V9", "RSLogix", "5000", "source", "protection", "config", "data", "routine", "program"
        };
        salts.AddRange(topSalts);
        
        // FTCrypt.dll related salts
        var ftCryptSalts = new[] {
            "ARC4", "RC4", "Botan", "V9QR", "V9h8", "FTCrypt", "256", "stream", "cipher"
        };
        salts.AddRange(ftCryptSalts);
        
        // Empty salt (always test)
        salts.Add("");
        
        return salts.Distinct().ToList();
    }

    static string ExtractRoutineName(string fileName)
    {
        // Extract routine name from filename patterns like S025_SkidIndexInVDL.L5X
        var match = Regex.Match(fileName, @"([A-Z]\d+_\w+)", RegexOptions.IgnoreCase);
        return match.Success ? match.Groups[1].Value : "";
    }

    static byte[] PBKDF2DeriveKey(string password, string salt, int iterations, int keyLength)
    {
        try
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(password, Encoding.UTF8.GetBytes(salt), iterations, HashAlgorithmName.SHA1);
            return pbkdf2.GetBytes(keyLength);
        }
        catch
        {
            // Fallback to simple hash if PBKDF2 fails
            return SHA256.HashData(Encoding.UTF8.GetBytes(password + salt));
        }
    }

    static byte[] PadKeyTo256Bits(byte[] key)
    {
        var paddedKey = new byte[32]; // 256 bits
        Array.Copy(key, paddedKey, Math.Min(key.Length, 32));
        return paddedKey;
    }

    // ARC4(256) implementation based on FTCrypt.dll findings
    static (bool Success, string Content) TryARC4_256_Decrypt(byte[] data, byte[] key)
    {
        try
        {
            // Ensure 256-bit key
            var key256 = PadKeyTo256Bits(key);
            
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            // Initialize S-box
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = key256[i % key256.Length];
            }
            
            // Key scheduling algorithm (KSA)
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            // Pseudo-random generation algorithm (PRGA)
            var result = new byte[data.Length];
            int x = 0, y = 0;
            
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    // ARC4(256) with drop mechanism (RC4_drop found in FTCrypt.dll)
    static (bool Success, string Content) TryARC4_256_Drop_Decrypt(byte[] data, byte[] key)
    {
        try
        {
            // Standard ARC4(256) but drop first N bytes of keystream
            var key256 = PadKeyTo256Bits(key);
            
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = key256[i % key256.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            // Drop first 1024 bytes of keystream (common RC4_drop value)
            int x = 0, y = 0;
            for (int drop = 0; drop < 1024; drop++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
            }
            
            // Now decrypt actual data
            var result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    // ARC4(256) with skip mechanism (RC4_skip found in FTCrypt.dll)
    static (bool Success, string Content) TryARC4_256_Skip_Decrypt(byte[] data, byte[] key)
    {
        try
        {
            // ARC4(256) but skip every Nth byte in keystream
            var key256 = PadKeyTo256Bits(key);
            
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = key256[i % key256.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            var result = new byte[data.Length];
            int x = 0, y = 0;
            int skipCounter = 0;
            
            for (int i = 0; i < data.Length; i++)
            {
                // Generate keystream bytes, skip every 3rd byte
                do
                {
                    x = (x + 1) % 256;
                    y = (y + s[x]) % 256;
                    (s[x], s[y]) = (s[y], s[x]);
                    skipCounter++;
                } while (skipCounter % 3 == 0); // Skip every 3rd keystream byte
                
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    // Botan-style RC4 (attempt to match FTCrypt.dll's Botan library implementation)
    static (bool Success, string Content) TryRC4_BotanStyle_Decrypt(byte[] data, byte[] key)
    {
        try
        {
            // Botan might use different initialization or key handling
            var processedKey = SHA256.HashData(key); // Botan might pre-process keys
            
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = processedKey[i % processedKey.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            var result = new byte[data.Length];
            int x = 0, y = 0;
            
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    // Standard RC4 for comparison
    static (bool Success, string Content) TryRC4_Standard_Decrypt(byte[] data, byte[] key)
    {
        try
        {
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = key[i % key.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            var result = new byte[data.Length];
            int x = 0, y = 0;
            
            for (int i = 0; i < data.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    static bool IsFullXMLDecryption(string text)
    {
        // Check if this looks like a complete XML decryption
        return text.Contains("<?xml") && 
               text.Contains("<RSLogix5000Content") && 
               text.Contains("</RSLogix5000Content>") &&
               text.Contains("<Routine") &&
               text.Length > 1000; // Should be substantial content
    }

    static HashSet<string> ExtractRSLogixKeywords()
    {
        var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Load from unprotected files if available
        var unprotectedPath = "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33 Not encrypted/";
        if (Directory.Exists(unprotectedPath))
        {
            foreach (var file in Directory.GetFiles(unprotectedPath, "*.L5X"))
            {
                try
                {
                    var content = File.ReadAllText(file);
                    ExtractKeywordsFromContent(content, keywords);
                }
                catch { }
            }
        }
        
        // Add comprehensive RSLogix keywords
        AddComprehensiveRSLogixKeywords(keywords);
        
        return keywords;
    }

    static void ExtractKeywordsFromContent(string content, HashSet<string> keywords)
    {
        // XML tags
        var xmlTags = Regex.Matches(content, @"</?(\w+)[^>]*>", RegexOptions.IgnoreCase);
        foreach (Match match in xmlTags)
        {
            if (match.Groups[1].Value.Length > 2)
                keywords.Add(match.Groups[1].Value);
        }
        
        // Attributes
        var attributes = Regex.Matches(content, @"(\w+)=""[^""]*""", RegexOptions.IgnoreCase);
        foreach (Match match in attributes)
        {
            if (match.Groups[1].Value.Length > 2)
                keywords.Add(match.Groups[1].Value);
        }
    }

    static void AddComprehensiveRSLogixKeywords(HashSet<string> keywords)
    {
        var rslogixKeywords = new[]
        {
            // Core XML Structure
            "RSLogix5000Content", "Controller", "Programs", "Program", "Routines", "Routine", "RLLContent", "Rung",
            "EncodedData", "EncryptionConfig", "TargetName", "TargetType", "Text", "Comment", "Description",
            
            // Basic Instructions
            "MOV", "XIO", "XIC", "OTE", "OTL", "OTU", "ONS", "OSR", "OSF", "NEG", "NOT", "CLR", "SET",
            "ADD", "SUB", "MUL", "DIV", "MOD", "SQR", "SQRT", "ABS", "MIN", "MAX", "LIM", "SCL", "SCP",
            "EQU", "NEQ", "LES", "LEQ", "GRT", "GEQ", "MEQ", "MASK", "AND", "OR", "XOR", "NOT",
            
            // System terms
            "Name", "Type", "Class", "Use", "Radix", "Dimension", "Hidden", "ExternalAccess", "Constant"
        };
        
        foreach (var keyword in rslogixKeywords)
        {
            keywords.Add(keyword);
        }
    }

    static byte[] ExtractEncryptedBytes(string filePath)
    {
        try
        {
            var content = File.ReadAllText(filePath);
            var encodedMatch = Regex.Match(content, @"<EncodedData[^>]*>(.*?)</EncodedData>", RegexOptions.Singleline);
            if (!encodedMatch.Success) return null;
            
            var encodedContent = encodedMatch.Groups[1].Value;
            encodedContent = Regex.Replace(encodedContent, @"<!\[CDATA\[(.*?)\]\]>", "$1", RegexOptions.Singleline);
            
            var cleanedBase64 = CleanBase64String(encodedContent);
            return Convert.FromBase64String(cleanedBase64);
        }
        catch
        {
            return null;
        }
    }

    static string CleanBase64String(string base64String)
    {
        if (string.IsNullOrEmpty(base64String)) return base64String;

        var cleaned = Regex.Replace(base64String, @"[^A-Za-z0-9+/=]", "");
        
        // Fix padding
        cleaned = cleaned.TrimEnd('=');
        int paddingCount = 4 - (cleaned.Length % 4);
        if (paddingCount != 4)
            cleaned += new string('=', paddingCount);

        return cleaned;
    }

    static int CountKeywordMatches(string text, HashSet<string> dictionary)
    {
        var matches = 0;
        var upperText = text.ToUpper();
        
        foreach (var keyword in dictionary)
        {
            if (upperText.Contains(keyword.ToUpper()))
            {
                matches++;
            }
        }
        
        return matches;
    }

    static void ReportTopCandidates(string fileName, List<(string algorithm, string keyDerivation, int keywords, string sample, bool isFullDecryption)> results)
    {
        if (results.Count == 0)
        {
            Console.WriteLine($"❌ No candidates found for {fileName}");
            return;
        }
        
        Console.WriteLine($"\n🏆 TOP CANDIDATES FOR {fileName}:");
        Console.WriteLine("-" + new string('-', 50));
        
        var topCandidates = results.OrderByDescending(r => r.isFullDecryption).ThenByDescending(r => r.keywords).Take(10).ToList();
        
        foreach (var (algorithm, keyDerivation, keywords, sample, isFullDecryption) in topCandidates)
        {
            var status = isFullDecryption ? "🚨 FULL DECRYPTION" : $"Keywords: {keywords}";
            Console.WriteLine($"🎯 {algorithm} | {keyDerivation} | {status}");
            Console.WriteLine($"   Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
            Console.WriteLine();
        }
    }

    static void AnalyzeGlobalResults(List<(string fileName, string algorithm, string keyDerivation, int keywords, string sample, bool isFullDecryption)> globalResults)
    {
        if (globalResults.Count == 0)
        {
            Console.WriteLine("❌ No global results to analyze");
            return;
        }
        
        Console.WriteLine($"📊 Total candidates across all files: {globalResults.Count}");
        Console.WriteLine();
        
        // Check for full decryptions first
        var fullDecryptions = globalResults.Where(r => r.isFullDecryption).ToList();
        if (fullDecryptions.Any())
        {
            Console.WriteLine("🚨 FULL DECRYPTIONS ACHIEVED:");
            Console.WriteLine("-" + new string('-', 50));
            foreach (var result in fullDecryptions)
            {
                Console.WriteLine($"✅ {result.fileName}: {result.algorithm} with {result.keyDerivation}");
            }
            Console.WriteLine();
        }
        
        // Best overall candidates
        var bestCandidates = globalResults.OrderByDescending(r => r.isFullDecryption).ThenByDescending(r => r.keywords).Take(20).ToList();
        Console.WriteLine("🏆 TOP 20 GLOBAL CANDIDATES:");
        Console.WriteLine("-" + new string('-', 80));
        
        foreach (var (fileName, algorithm, keyDerivation, keywords, sample, isFullDecryption) in bestCandidates)
        {
            var status = isFullDecryption ? "FULL" : $"{keywords}kw";
            Console.WriteLine($"🎯 {fileName} | {algorithm} | {keyDerivation} | {status}");
            Console.WriteLine($"   Sample: {sample.Substring(0, Math.Min(100, sample.Length))}");
            Console.WriteLine();
        }
        
        // Algorithm effectiveness analysis
        Console.WriteLine("\n📈 ALGORITHM EFFECTIVENESS:");
        Console.WriteLine("-" + new string('-', 50));
        
        var algorithmStats = globalResults.GroupBy(r => r.algorithm)
            .Select(g => new { 
                Algorithm = g.Key, 
                Count = g.Count(), 
                AvgKeywords = g.Average(r => r.keywords),
                FullDecryptions = g.Count(r => r.isFullDecryption)
            })
            .OrderByDescending(s => s.FullDecryptions).ThenByDescending(s => s.AvgKeywords)
            .ToList();
        
        foreach (var stat in algorithmStats)
        {
            Console.WriteLine($"{stat.Algorithm}: {stat.Count} candidates, {stat.FullDecryptions} full decryptions, avg {stat.AvgKeywords:F1} keywords");
        }
    }
}