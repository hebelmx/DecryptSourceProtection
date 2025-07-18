using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class Program
{
    static void Main(string[] args)
    {
        Console.WriteLine("🚀 ENHANCED RC4 CRYPTANALYSIS WITH COMPRESSION VARIANTS");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine("🎯 Based on Dictionary Attack Breakthrough: RC4 + SHA256-Separated");
        Console.WriteLine("🔍 Testing: RC4 + Compression + Extended Salting + Dictionary Validation");
        Console.WriteLine("📊 Focus: Top candidates from previous analysis + compression hypotheses");
        Console.WriteLine();

        // Extract comprehensive dictionary
        var dictionary = ExtractRSLogixKeywords();
        Console.WriteLine($"📚 Dictionary loaded: {dictionary.Count} keywords");
        
        // Test files - focus on high-value targets
        var testFiles = new[]
        {
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S025_SkidIndexInVDL.L5X", "Known Working"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S005_STP1Advance.L5X", "Known Target"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_050_SP_MANFREM.L5X", "Unknown V30"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_051_PPLAASEUD.L5X", "Unknown V30"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_052_PPLAASEIND.L5X", "Unknown V30"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_053_SPLAASEUD.L5X", "Unknown V30")
        };

        var globalResults = new List<(string fileName, string algorithm, string keyDerivation, int keywords, string sample, string compressionType)>();

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
                
                // Run comprehensive RC4 analysis
                var results = RunComprehensiveRC4Analysis(encryptedBytes, dictionary, fileName);
                
                // Add to global results
                globalResults.AddRange(results.Select(r => (fileName, r.algorithm, r.keyDerivation, r.keywords, r.sample, r.compressionType)));
                
                // Report top candidates for this file
                ReportTopCandidates(fileName, results);
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 Error analyzing {fileName}: {ex.Message}");
            }
        }
        
        // Global analysis across all files
        Console.WriteLine("\n🌟 GLOBAL ANALYSIS: CROSS-FILE PATTERNS");
        Console.WriteLine("=" + new string('=', 80));
        AnalyzeGlobalPatterns(globalResults);
    }

    static List<(string algorithm, string keyDerivation, int keywords, string sample, string compressionType)> RunComprehensiveRC4Analysis(
        byte[] encryptedBytes, HashSet<string> dictionary, string fileName)
    {
        var results = new List<(string algorithm, string keyDerivation, int keywords, string sample, string compressionType)>();
        
        Console.WriteLine("🔍 COMPREHENSIVE RC4 ANALYSIS");
        Console.WriteLine("-" + new string('-', 50));
        
        // Enhanced key generation based on dictionary attack findings
        var keyGenerators = GenerateEnhancedKeys(fileName);
        
        // Compression methods to test
        var compressionMethods = new[]
        {
            ("None", new Func<byte[], byte[]>(data => data)),
            ("GZip", new Func<byte[], byte[]>(data => TryGZipDecompress(data))),
            ("Deflate", new Func<byte[], byte[]>(data => TryDeflateDecompress(data))),
            ("Brotli", new Func<byte[], byte[]>(data => TryBrotliDecompress(data))),
            ("LZ4-Emulated", new Func<byte[], byte[]>(data => TryLZ4EmulatedDecompress(data)))
        };
        
        int totalTests = 0;
        int successfulTests = 0;
        
        foreach (var (compressionName, decompressionFunc) in compressionMethods)
        {
            Console.WriteLine($"\n📊 Testing compression method: {compressionName}");
            
            foreach (var (keyName, keyBytes) in keyGenerators)
            {
                totalTests++;
                
                try
                {
                    // Try RC4 decryption
                    var decryptedBytes = RC4Decrypt(encryptedBytes, keyBytes);
                    
                    // Try decompression
                    var decompressedBytes = decompressionFunc(decryptedBytes);
                    if (decompressedBytes == null) continue;
                    
                    // Convert to string and validate
                    var decryptedText = Encoding.UTF8.GetString(decompressedBytes);
                    if (string.IsNullOrEmpty(decryptedText) || decryptedText.Length < 50) continue;
                    
                    // Count keyword matches
                    var keywordMatches = CountKeywordMatches(decryptedText, dictionary);
                    
                    if (keywordMatches > 0)
                    {
                        successfulTests++;
                        var sample = decryptedText.Length > 200 ? decryptedText.Substring(0, 200) : decryptedText;
                        results.Add(($"RC4+{compressionName}", keyName, keywordMatches, sample, compressionName));
                        
                        Console.WriteLine($"🎯 CANDIDATE: RC4+{compressionName} with {keyName}");
                        Console.WriteLine($"   Keywords: {keywordMatches}");
                        Console.WriteLine($"   Length: {decryptedText.Length:N0} chars");
                        Console.WriteLine($"   Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
                        Console.WriteLine();
                        
                        // If we found XML-like content, this is very promising
                        if (decryptedText.Contains("<") && decryptedText.Contains(">") && decryptedText.Contains("RSLogix"))
                        {
                            Console.WriteLine("🚨 POTENTIAL BREAKTHROUGH: XML + RSLogix detected!");
                            Console.WriteLine($"   Full sample: {decryptedText.Substring(0, Math.Min(500, decryptedText.Length))}");
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

    static List<(string keyName, byte[] keyBytes)> GenerateEnhancedKeys(string fileName)
    {
        var keys = new List<(string keyName, byte[] keyBytes)>();
        
        // Base keys from dictionary attack analysis
        var baseKeys = new[] { "Stana7", "Visual2025", "RSLogix5000", "defaultkey", "testkey", "key", "password", "secret", "admin" };
        
        // Enhanced salt generation
        var salts = GenerateEnhancedSalts(fileName);
        
        // Separators that showed promise
        var separators = new[] { "|", "+", "_", ":", "-", ".", "@", "#", "" };
        
        // Hash algorithms in order of success from dictionary attack
        var hashAlgorithms = new (string name, Func<string, byte[]> func)[]
        {
            ("SHA256", s => SHA256.HashData(Encoding.UTF8.GetBytes(s))),
            ("SHA1", s => SHA1.HashData(Encoding.UTF8.GetBytes(s))),
            ("MD5", s => MD5.HashData(Encoding.UTF8.GetBytes(s))),
            ("SHA512", s => SHA512.HashData(Encoding.UTF8.GetBytes(s))),
            ("Direct", s => Encoding.UTF8.GetBytes(s))
        };
        
        foreach (var baseKey in baseKeys)
        {
            foreach (var salt in salts)
            {
                foreach (var separator in separators)
                {
                    foreach (var (hashName, hashFunc) in hashAlgorithms)
                    {
                        // Forward combination
                        var forwardKey = baseKey + separator + salt;
                        var forwardHash = hashFunc(forwardKey);
                        keys.Add(($"{hashName}({baseKey}{separator}{salt})", forwardHash));
                        
                        // Reverse combination
                        var reverseKey = salt + separator + baseKey;
                        var reverseHash = hashFunc(reverseKey);
                        keys.Add(($"{hashName}({salt}{separator}{baseKey})", reverseHash));
                        
                        // Double hash
                        var doubleHash = hashFunc(Convert.ToHexString(hashFunc(forwardKey)).ToLower());
                        keys.Add(($"Double{hashName}({baseKey}{separator}{salt})", doubleHash));
                    }
                }
            }
        }
        
        Console.WriteLine($"🔑 Generated {keys.Count} key combinations");
        return keys;
    }

    static List<string> GenerateEnhancedSalts(string fileName)
    {
        var salts = new List<string>();
        
        // File-specific salts
        salts.Add(fileName);
        salts.Add(Path.GetFileNameWithoutExtension(fileName));
        salts.Add(fileName.ToUpper());
        salts.Add(fileName.ToLower());
        
        // Extract components from filename
        var parts = fileName.Split('_', '.');
        salts.AddRange(parts.Where(p => !string.IsNullOrEmpty(p) && p.Length > 1));
        
        // Generic salts from dictionary attack
        var genericSalts = new[] { 
            "RSLogix", "encryption", "V9", "config", "data", "source", "protection", "encoded", "routine", "program",
            "L5X", "5000", "ladder", "logic", "controller", "PLC", "automation", "industrial", "allen", "bradley",
            "rockwell", "software", "studio", "logix", "compact", "control", "system", "network", "ethernet",
            "devicenet", "modbus", "profibus", "safety", "motion", "drive", "servo", "hmi", "scada", "historian"
        };
        salts.AddRange(genericSalts);
        
        // Numerical variations
        for (int i = 0; i <= 20; i++)
        {
            salts.Add(i.ToString());
        }
        
        // Year variations
        for (int year = 2020; year <= 2025; year++)
        {
            salts.Add(year.ToString());
        }
        
        // Empty salt
        salts.Add("");
        
        return salts.Distinct().ToList();
    }

    static byte[] RC4Decrypt(byte[] data, byte[] key)
    {
        var s = new byte[256];
        var keyBytes = new byte[256];
        
        // Initialize
        for (int i = 0; i < 256; i++)
        {
            s[i] = (byte)i;
            keyBytes[i] = key[i % key.Length];
        }
        
        // Key scheduling
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + keyBytes[i]) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }
        
        // Decryption
        var result = new byte[data.Length];
        int x = 0, y = 0;
        
        for (int i = 0; i < data.Length; i++)
        {
            x = (x + 1) % 256;
            y = (y + s[x]) % 256;
            (s[x], s[y]) = (s[y], s[x]);
            result[i] = (byte)(data[i] ^ s[(s[x] + s[y]) % 256]);
        }
        
        return result;
    }

    static byte[] TryGZipDecompress(byte[] data)
    {
        try
        {
            using var input = new MemoryStream(data);
            using var gzip = new GZipStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            gzip.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    static byte[] TryDeflateDecompress(byte[] data)
    {
        try
        {
            using var input = new MemoryStream(data);
            using var deflate = new DeflateStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            deflate.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    static byte[] TryBrotliDecompress(byte[] data)
    {
        try
        {
            using var input = new MemoryStream(data);
            using var brotli = new BrotliStream(input, CompressionMode.Decompress);
            using var output = new MemoryStream();
            brotli.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    static byte[] TryLZ4EmulatedDecompress(byte[] data)
    {
        try
        {
            // Simple LZ4-style decompression emulation
            // This is a simplified approach - real LZ4 would need proper implementation
            if (data.Length < 4) return null;
            
            var result = new List<byte>();
            int pos = 0;
            
            while (pos < data.Length)
            {
                if (pos + 4 > data.Length) break;
                
                // Simple pattern detection
                byte token = data[pos++];
                
                // Literal length
                int literalLength = token >> 4;
                if (literalLength == 15)
                {
                    if (pos >= data.Length) break;
                    literalLength += data[pos++];
                }
                
                // Copy literals
                for (int i = 0; i < literalLength && pos < data.Length; i++)
                {
                    result.Add(data[pos++]);
                }
                
                if (pos >= data.Length) break;
                
                // Match length
                int matchLength = (token & 0xF) + 4;
                if (matchLength == 19)
                {
                    if (pos >= data.Length) break;
                    matchLength += data[pos++];
                }
                
                // Skip match processing for simplicity
                pos += Math.Min(2, data.Length - pos);
            }
            
            return result.Count > 0 ? result.ToArray() : null;
        }
        catch
        {
            return null;
        }
    }

    static HashSet<string> ExtractRSLogixKeywords()
    {
        var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Load from unprotected files
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
        
        // RSLogix instructions
        var instructions = Regex.Matches(content, @"\b(MOV|XIO|XIC|OTE|OTL|OTU|ADD|SUB|MUL|DIV|EQU|NEQ|GRT|LES|AND|OR|NOT|JMP|JSR|RET|TON|TOF|CTU|CTD|PID|MSG|GSV|SSV)\b", RegexOptions.IgnoreCase);
        foreach (Match match in instructions)
        {
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
            
            // Timers and Counters
            "TON", "TOF", "RTO", "CTU", "CTD", "RES", "TONR", "TOFR", "CTUD",
            
            // Program Control
            "JMP", "LBL", "JSR", "RET", "SBR", "MCR", "END", "NOP", "AFI", "TND", "BREAK",
            "FOR", "NEXT", "WHILE", "ENDWHILE", "REPEAT", "UNTIL", "IF", "ELSE", "ELSIF", "ENDIF",
            
            // Data Types
            "BOOL", "SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT", "REAL", "LREAL",
            "STRING", "WSTRING", "TIME", "DATE", "TOD", "DT", "ARRAY", "STRUCT", "UNION", "ENUM",
            
            // File Operations
            "COP", "CPS", "FLL", "FAL", "FSC", "DDT", "DCD", "ENC", "SEL", "MUX", "BSL", "BSR",
            "FIFO", "LIFO", "SORT", "SIZE", "UPPER", "LOWER", "MID", "FIND", "REPLACE", "CONCAT",
            
            // Math and Trigonometry
            "SIN", "COS", "TAN", "ASN", "ACS", "ATN", "LN", "LOG", "XPY", "DEG", "RAD", "TRN",
            
            // Motion and PID
            "PID", "PIDE", "PMUL", "PRNP", "PCLR", "PXRQ", "POVR", "PATT", "AXIS", "SERVO", "MOTION",
            
            // Communication
            "MSG", "DTOS", "STOD", "RTOS", "STOR", "GSV", "SSV", "IOT", "IIT", "PEEK", "POKE",
            
            // System and Status
            "Name", "Type", "Class", "Use", "Radix", "Dimension", "Hidden", "ExternalAccess", "Constant",
            "SchemaRevision", "SoftwareRevision", "ContainsContext", "Owner", "TimeStamp", "EditedBy",
            
            // Industrial Terms
            "INTERLOCK", "SAFETY", "ESTOP", "ALARM", "FAULT", "STATUS", "ENABLE", "DISABLE", "START", "STOP",
            "MANUAL", "AUTO", "READY", "RUNNING", "STOPPED", "ERROR", "WARNING", "NORMAL", "BYPASS"
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

    static void ReportTopCandidates(string fileName, List<(string algorithm, string keyDerivation, int keywords, string sample, string compressionType)> results)
    {
        if (results.Count == 0)
        {
            Console.WriteLine($"❌ No candidates found for {fileName}");
            return;
        }
        
        Console.WriteLine($"\n🏆 TOP CANDIDATES FOR {fileName}:");
        Console.WriteLine("-" + new string('-', 50));
        
        var topCandidates = results.OrderByDescending(r => r.keywords).Take(10).ToList();
        
        foreach (var (algorithm, keyDerivation, keywords, sample, compressionType) in topCandidates)
        {
            Console.WriteLine($"🎯 {algorithm} | {keyDerivation} | Keywords: {keywords}");
            Console.WriteLine($"   Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
            Console.WriteLine();
        }
    }

    static void AnalyzeGlobalPatterns(List<(string fileName, string algorithm, string keyDerivation, int keywords, string sample, string compressionType)> globalResults)
    {
        if (globalResults.Count == 0)
        {
            Console.WriteLine("❌ No global results to analyze");
            return;
        }
        
        Console.WriteLine($"📊 Total candidates across all files: {globalResults.Count}");
        Console.WriteLine();
        
        // Best overall candidates
        var bestCandidates = globalResults.OrderByDescending(r => r.keywords).Take(20).ToList();
        Console.WriteLine("🏆 TOP 20 GLOBAL CANDIDATES:");
        Console.WriteLine("-" + new string('-', 80));
        
        foreach (var (fileName, algorithm, keyDerivation, keywords, sample, compressionType) in bestCandidates)
        {
            Console.WriteLine($"🎯 {fileName} | {algorithm} | {keyDerivation} | Keywords: {keywords}");
            Console.WriteLine($"   Sample: {sample.Substring(0, Math.Min(100, sample.Length))}");
            Console.WriteLine();
        }
        
        // Compression analysis
        Console.WriteLine("\n📈 COMPRESSION METHOD ANALYSIS:");
        Console.WriteLine("-" + new string('-', 50));
        
        var compressionStats = globalResults.GroupBy(r => r.compressionType)
            .Select(g => new { Compression = g.Key, Count = g.Count(), AvgKeywords = g.Average(r => r.keywords) })
            .OrderByDescending(s => s.Count)
            .ToList();
        
        foreach (var stat in compressionStats)
        {
            Console.WriteLine($"{stat.Compression}: {stat.Count} candidates, avg {stat.AvgKeywords:F1} keywords");
        }
        
        // Key derivation analysis
        Console.WriteLine("\n🔑 KEY DERIVATION ANALYSIS:");
        Console.WriteLine("-" + new string('-', 50));
        
        var keyStats = globalResults.GroupBy(r => r.keyDerivation.Split('(')[0])
            .Select(g => new { KeyType = g.Key, Count = g.Count(), AvgKeywords = g.Average(r => r.keywords) })
            .OrderByDescending(s => s.Count)
            .ToList();
        
        foreach (var stat in keyStats.Take(10))
        {
            Console.WriteLine($"{stat.KeyType}: {stat.Count} candidates, avg {stat.AvgKeywords:F1} keywords");
        }
        
        // Cross-file consistency
        Console.WriteLine("\n🔄 CROSS-FILE CONSISTENCY:");
        Console.WriteLine("-" + new string('-', 50));
        
        var consistentAlgorithms = globalResults.GroupBy(r => r.algorithm + " | " + r.keyDerivation)
            .Where(g => g.Select(r => r.fileName).Distinct().Count() > 1)
            .Select(g => new { Algorithm = g.Key, Files = g.Select(r => r.fileName).Distinct().Count(), TotalKeywords = g.Sum(r => r.keywords) })
            .OrderByDescending(c => c.TotalKeywords)
            .Take(10)
            .ToList();
        
        foreach (var consistent in consistentAlgorithms)
        {
            Console.WriteLine($"{consistent.Algorithm} | Files: {consistent.Files}, Total Keywords: {consistent.TotalKeywords}");
        }
    }
}
