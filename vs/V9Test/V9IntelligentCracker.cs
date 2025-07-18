using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

/// <summary>
/// V9 Intelligent Dictionary Attack System
/// Based on real-world OEM password patterns: CompanyName+Year, ProjectName+Version, etc.
/// </summary>
public class V9IntelligentCracker
{
    private readonly L5XDecryptor _decryptor;
    private readonly ILogger<V9IntelligentCracker> _logger;

    public V9IntelligentCracker(L5XDecryptor decryptor, ILogger<V9IntelligentCracker> logger)
    {
        _decryptor = decryptor;
        _logger = logger;
    }

    public async Task<(bool Success, string Key, string DecryptedContent, string SavedPath)> CrackV9FileAsync(string filePath)
    {
        _logger.LogInformation("🎯 V9 INTELLIGENT CRACKER: Starting attack on {FilePath}", filePath);
        
        // Phase 1: Intelligence-based seeded dictionary
        _logger.LogInformation("📊 Phase 1: Intelligence-based targeted attack");
        var intelligenceResult = await TryIntelligenceBasedAttack(filePath);
        if (intelligenceResult.Success)
        {
            _logger.LogInformation("✅ SUCCESS: Intelligence attack cracked the key: {Key}", intelligenceResult.Key);
            var savedPath = await SaveCrackedFile(filePath, intelligenceResult.DecryptedContent, intelligenceResult.Key, "Intelligence");
            return (true, intelligenceResult.Key, intelligenceResult.DecryptedContent, savedPath);
        }
        
        // Phase 2: Common OEM password patterns
        _logger.LogInformation("📊 Phase 2: Common OEM password patterns");
        var oemResult = await TryOEMPatternAttack(filePath);
        if (oemResult.Success)
        {
            _logger.LogInformation("✅ SUCCESS: OEM pattern attack cracked the key: {Key}", oemResult.Key);
            var savedPath = await SaveCrackedFile(filePath, oemResult.DecryptedContent, oemResult.Key, "OEM");
            return (true, oemResult.Key, oemResult.DecryptedContent, savedPath);
        }
        
        // Phase 3: Standard dictionary attack
        _logger.LogInformation("📊 Phase 3: Standard dictionary attack");
        var dictionaryResult = await TryStandardDictionaryAttack(filePath);
        if (dictionaryResult.Success)
        {
            _logger.LogInformation("✅ SUCCESS: Dictionary attack cracked the key: {Key}", dictionaryResult.Key);
            var savedPath = await SaveCrackedFile(filePath, dictionaryResult.DecryptedContent, dictionaryResult.Key, "Dictionary");
            return (true, dictionaryResult.Key, dictionaryResult.DecryptedContent, savedPath);
        }
        
        _logger.LogWarning("❌ All attack phases failed - key not found");
        return (false, "", "", "");
    }

    private async Task<(bool Success, string Key, string DecryptedContent)> TryIntelligenceBasedAttack(string filePath)
    {
        // Extract intelligence keywords from the XML file itself
        var keywords = ExtractIntelligenceKeywords(filePath);
        _logger.LogInformation("🔍 Extracted {Count} intelligence keywords from file", keywords.Count);
        
        // Generate intelligent mutations
        var candidateKeys = GenerateIntelligentMutations(keywords);
        _logger.LogInformation("🧬 Generated {Count} intelligent key candidates", candidateKeys.Count);
        
        return await TestKeyCandidates(filePath, candidateKeys, "Intelligence");
    }

    private List<string> ExtractIntelligenceKeywords(string filePath)
    {
        var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        try
        {
            var content = File.ReadAllText(filePath);
            
            // Extract company/manufacturer names
            ExtractCompanyNames(content, keywords);
            
            // Extract project/controller names
            ExtractProjectNames(content, keywords);
            
            // Extract version/revision info
            ExtractVersionInfo(content, keywords);
            
            // Extract target/routine names
            ExtractTargetNames(content, keywords);
            
            // Extract dates and years
            ExtractDateInfo(content, keywords);
            
            // Add filename-based keywords
            ExtractFilenameKeywords(filePath, keywords);
            
        }
        catch (Exception ex)
        {
            _logger.LogWarning("⚠️ Error extracting intelligence keywords: {Error}", ex.Message);
        }
        
        return keywords.Where(k => k.Length >= 3 && k.Length <= 50).ToList();
    }

    private void ExtractCompanyNames(string content, HashSet<string> keywords)
    {
        // Look for company indicators in XML attributes and comments
        var companyPatterns = new[]
        {
            @"Owner=\""([^""]+)\""",
            @"Manufacturer=\""([^""]+)\""", 
            @"Company[:\s]*([A-Za-z0-9]+)",
            @"Corp[:\s]*([A-Za-z0-9]+)",
            @"Inc[:\s]*([A-Za-z0-9]+)",
            @"LLC[:\s]*([A-Za-z0-9]+)",
            @"<!--\s*([A-Za-z0-9]+(?:\s+[A-Za-z0-9]+){0,2})\s*-->",
        };
        
        foreach (var pattern in companyPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                var company = match.Groups[1].Value.Trim();
                if (company.Length >= 3) keywords.Add(company);
                
                // Add variations
                keywords.Add(company.Replace(" ", ""));
                keywords.Add(company.Replace(" ", "_"));
            }
        }
    }

    private void ExtractProjectNames(string content, HashSet<string> keywords)
    {
        var projectPatterns = new[]
        {
            @"TargetName=\""([^""]+)\""",
            @"Name=\""([^""]+Controller[^""]*)\""",
            @"Name=\""([^""]+Project[^""]*)\""",
            @"ProjectName[:\s]*([A-Za-z0-9_-]+)",
        };
        
        foreach (var pattern in projectPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                var project = match.Groups[1].Value.Trim();
                if (project.Length >= 3) keywords.Add(project);
            }
        }
    }

    private void ExtractVersionInfo(string content, HashSet<string> keywords)
    {
        var versionPatterns = new[]
        {
            @"SoftwareRevision=\""([^""]+)\""",
            @"SchemaRevision=\""([^""]+)\""",
            @"Version[:\s]*([0-9.]+)",
            @"Rev[:\s]*([0-9.]+)",
            @"V(\d+)",
        };
        
        foreach (var pattern in versionPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                var version = match.Groups[1].Value.Trim();
                keywords.Add(version);
                keywords.Add(version.Replace(".", ""));
            }
        }
    }

    private void ExtractTargetNames(string content, HashSet<string> keywords)
    {
        var targetPatterns = new[]
        {
            @"TargetType=\""([^""]+)\""",
            @"<Routine[^>]+Name=\""([^""]+)\""",
            @"<Program[^>]+Name=\""([^""]+)\""",
        };
        
        foreach (var pattern in targetPatterns)
        {
            var matches = Regex.Matches(content, pattern, RegexOptions.IgnoreCase);
            foreach (Match match in matches)
            {
                var target = match.Groups[1].Value.Trim();
                if (target.Length >= 3) keywords.Add(target);
            }
        }
    }

    private void ExtractDateInfo(string content, HashSet<string> keywords)
    {
        // Extract years from various date formats
        var datePatterns = new[]
        {
            @"ExportDate=\""[^""]*(\d{4})[^""]*\""",
            @"(\d{4})", // Any 4-digit year
            @"20(\d{2})", // 2000s years
        };
        
        foreach (var pattern in datePatterns)
        {
            var matches = Regex.Matches(content, pattern);
            foreach (Match match in matches)
            {
                var year = match.Groups[1].Value;
                if (int.TryParse(year, out int yearInt) && yearInt >= 2000 && yearInt <= 2030)
                {
                    keywords.Add(year);
                    keywords.Add((yearInt - 1).ToString()); // Previous year
                    keywords.Add((yearInt + 1).ToString()); // Next year
                }
            }
        }
    }

    private void ExtractFilenameKeywords(string filePath, HashSet<string> keywords)
    {
        var filename = Path.GetFileNameWithoutExtension(filePath);
        
        // Split filename by common separators
        var parts = filename.Split(new[] { '_', '-', ' ', '.' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (part.Length >= 3) keywords.Add(part);
        }
        
        // Add whole filename without extension
        keywords.Add(filename);
    }

    private List<string> GenerateIntelligentMutations(List<string> keywords)
    {
        var mutations = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // Common years for industrial automation
        var years = new[] { "2020", "2021", "2022", "2023", "2024", "2025", "20", "21", "22", "23", "24", "25" };
        
        // Common suffixes/prefixes
        var suffixes = new[] { "", "123", "1", "01", "2024", "2025", "Key", "Pass", "PW", "Code" };
        var prefixes = new[] { "", "PLC", "HMI", "Auto", "Line", "Cell", "Station" };
        
        foreach (var keyword in keywords.Take(20)) // Limit to prevent explosion
        {
            // Direct keyword
            mutations.Add(keyword);
            
            // Case variations
            mutations.Add(keyword.ToUpper());
            mutations.Add(keyword.ToLower());
            mutations.Add(CapitalizeFirst(keyword));
            
            // Year combinations
            foreach (var year in years)
            {
                mutations.Add(keyword + year);
                mutations.Add(year + keyword);
                mutations.Add(keyword + "_" + year);
                mutations.Add(keyword + "-" + year);
            }
            
            // Prefix/suffix combinations
            foreach (var suffix in suffixes)
            {
                if (!string.IsNullOrEmpty(suffix))
                {
                    mutations.Add(keyword + suffix);
                    mutations.Add(keyword + "_" + suffix);
                }
            }
            
            foreach (var prefix in prefixes)
            {
                if (!string.IsNullOrEmpty(prefix))
                {
                    mutations.Add(prefix + keyword);
                    mutations.Add(prefix + "_" + keyword);
                }
            }
            
            // Multi-keyword combinations (first 5 keywords only)
            foreach (var keyword2 in keywords.Take(5))
            {
                if (keyword != keyword2)
                {
                    mutations.Add(keyword + keyword2);
                    mutations.Add(keyword + "_" + keyword2);
                    mutations.Add(keyword + "-" + keyword2);
                }
            }
        }
        
        return mutations.Where(m => m.Length >= 3 && m.Length <= 100).ToList();
    }

    private async Task<(bool Success, string Key, string DecryptedContent)> TryOEMPatternAttack(string filePath)
    {
        var oemPatterns = GenerateOEMPatterns();
        _logger.LogInformation("🏭 Generated {Count} OEM pattern candidates", oemPatterns.Count);
        
        return await TestKeyCandidates(filePath, oemPatterns, "OEM Pattern");
    }

    private List<string> GenerateOEMPatterns()
    {
        var patterns = new List<string>();
        
        // Common OEM company patterns
        var companies = new[] { "Rockwell", "AB", "Allen", "Bradley", "Siemens", "Schneider", "GE", "Mitsubishi", "Omron", "Beckhoff" };
        var projects = new[] { "Line1", "Line2", "Cell1", "Station1", "Auto", "Manual", "Production", "Test", "Demo" };
        var years = new[] { "2020", "2021", "2022", "2023", "2024", "2025", "20", "21", "22", "23", "24", "25" };
        
        foreach (var company in companies)
        {
            foreach (var year in years)
            {
                patterns.Add(company + year);
                patterns.Add(company + "_" + year);
                patterns.Add(company.ToUpper() + year);
            }
            
            foreach (var project in projects)
            {
                patterns.Add(company + project);
                patterns.Add(company + "_" + project);
                patterns.Add(project + company);
            }
        }
        
        // Common industrial passwords
        patterns.AddRange(new[]
        {
            "password", "Password", "PASSWORD", "admin", "Admin", "ADMIN",
            "user", "User", "USER", "guest", "Guest", "GUEST",
            "operator", "Operator", "OPERATOR", "engineer", "Engineer", "ENGINEER",
            "maintenance", "Maintenance", "MAINTENANCE", "service", "Service", "SERVICE",
            "default", "Default", "DEFAULT", "key", "Key", "KEY",
            "secret", "Secret", "SECRET", "pass", "Pass", "PASS",
            "code", "Code", "CODE", "unlock", "Unlock", "UNLOCK",
            "open", "Open", "OPEN", "access", "Access", "ACCESS",
            
            // Variations with numbers
            "password1", "Password1", "admin123", "Admin123", "user1", "User1",
            "password2024", "Password2025", "admin2024", "Admin2025",
            
            // PLC/Industrial specific
            "plc", "PLC", "hmi", "HMI", "scada", "SCADA", "rsl", "RSL",
            "rslogix", "RSLogix", "RSLOGIX", "logix", "Logix", "LOGIX",
            "automation", "Automation", "AUTOMATION", "control", "Control", "CONTROL",
            
            // Visual patterns (user mentioned Visual2025)
            "Visual2024", "Visual2025", "Visual2026", "visual2024", "visual2025",
            "Studio2024", "Studio2025", "studio2024", "studio2025",
        });
        
        return patterns.Distinct().ToList();
    }

    private async Task<(bool Success, string Key, string DecryptedContent)> TryStandardDictionaryAttack(string filePath)
    {
        var dictionary = GenerateStandardDictionary();
        _logger.LogInformation("📚 Generated {Count} standard dictionary candidates", dictionary.Count);
        
        return await TestKeyCandidates(filePath, dictionary, "Standard Dictionary");
    }

    private List<string> GenerateStandardDictionary()
    {
        // Standard password dictionary - common weak passwords
        return new List<string>
        {
            // Top common passwords
            "123456", "password", "123456789", "12345678", "12345", "1234567", "1234567890",
            "qwerty", "abc123", "111111", "123123", "admin", "letmein", "welcome", "monkey",
            "password1", "1234", "1q2w3e4r", "dragon", "master", "hello", "freedom", "whatever",
            
            // Industrial/Technical passwords
            "engineer", "operator", "maintenance", "service", "technician", "supervisor",
            "manager", "production", "quality", "safety", "emergency", "backup",
            
            // Company/Product related
            "rockwell", "allenbradley", "siemens", "schneider", "automation", "control",
            "factory", "plant", "machine", "equipment", "system", "network",
            
            // Years and dates
            "2020", "2021", "2022", "2023", "2024", "2025", "2019", "2018",
            "01012020", "01012021", "01012022", "01012023", "01012024", "01012025",
            
            // Simple patterns
            "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
            "abcdef", "fedcba", "qwertz", "asdfgh", "zxcvbn", "poiuyt",
        };
    }

    private async Task<(bool Success, string Key, string DecryptedContent)> TestKeyCandidates(
        string filePath, List<string> candidates, string phase)
    {
        _logger.LogInformation("🧪 Testing {Count} candidates in {Phase} phase", candidates.Count, phase);
        
        int tested = 0;
        foreach (var candidate in candidates)
        {
            tested++;
            if (tested % 100 == 0)
            {
                _logger.LogInformation("🔄 {Phase}: Tested {Tested}/{Total} candidates...", phase, tested, candidates.Count);
            }
            
            try
            {
                // Test this candidate key
                var result = await TestSingleKey(filePath, candidate);
                if (result.Success)
                {
                    _logger.LogInformation("🎉 CRACKED! Key found: '{Key}' (tested {Tested}/{Total})", 
                        candidate, tested, candidates.Count);
                    return (true, candidate, result.DecryptedContent);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug("🔍 Key '{Key}' failed: {Error}", candidate, ex.Message);
            }
        }
        
        _logger.LogInformation("❌ {Phase} phase complete: {Tested} candidates tested, no success", phase, tested);
        return (false, "", "");
    }

    private async Task<(bool Success, string DecryptedContent)> TestSingleKey(string filePath, string key)
    {
        // Create a temporary keystore with just this key
        var tempKeyStore = new KeyStore();
        tempKeyStore.ClearKeys(); // Start fresh
        tempKeyStore.AddKey(key);
        
        var tempDecryptor = new L5XDecryptor(tempKeyStore, null);
        
        try
        {
            var result = await tempDecryptor.DecryptFromFileAsync(filePath);
            if (result.IsSuccess && IsValidDecryption(result.Value.XmlContent))
            {
                return (true, result.Value.XmlContent);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug("Key '{Key}' test failed: {Error}", key, ex.Message);
        }
        
        return (false, "");
    }

    private bool IsValidDecryption(string content)
    {
        // Enhanced validation for successful V9 decryption
        if (string.IsNullOrEmpty(content) || content.Length < 100) return false;
        
        // Must contain XML structure
        if (!content.Contains("<") || !content.Contains(">")) return false;
        
        // Must contain RSLogix-specific content
        var rslogixIndicators = new[]
        {
            "RSLogix", "Controller", "Routine", "Program", "DataType",
            "RLLContent", "STContent", "Ladder", "TargetName", "TargetType"
        };
        
        int indicators = rslogixIndicators.Count(indicator => 
            content.Contains(indicator, StringComparison.OrdinalIgnoreCase));
            
        return indicators >= 2; // At least 2 RSLogix indicators
    }

    private string CapitalizeFirst(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        return char.ToUpper(input[0]) + input.Substring(1).ToLower();
    }

    private async Task<string> SaveCrackedFile(string originalFilePath, string decryptedContent, string key, string method)
    {
        try
        {
            // Create organized folder structure
            var originalDir = Path.GetDirectoryName(originalFilePath);
            var originalFileName = Path.GetFileNameWithoutExtension(originalFilePath);
            var originalExtension = Path.GetExtension(originalFilePath);
            
            // Create cracked folder with timestamp
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var crackedDir = Path.Combine(originalDir, "cracked", $"v9_{timestamp}");
            Directory.CreateDirectory(crackedDir);
            
            // Create filename with method and key info
            var sanitizedKey = key.Replace(",", "_").Replace(" ", "_").Replace("\"", "").Replace("'", "");
            var crackedFileName = $"{originalFileName}_CRACKED_{method}_{sanitizedKey}{originalExtension}";
            var crackedFilePath = Path.Combine(crackedDir, crackedFileName);
            
            // Save the decrypted content
            await File.WriteAllTextAsync(crackedFilePath, decryptedContent);
            
            // Create metadata file
            var metadataPath = Path.Combine(crackedDir, $"{originalFileName}_metadata.txt");
            var metadata = $"V9 Intelligent Cracker Results\n" +
                          $"=============================\n" +
                          $"Original File: {originalFilePath}\n" +
                          $"Cracked File: {crackedFilePath}\n" +
                          $"Method: {method}\n" +
                          $"Key: {key}\n" +
                          $"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n" +
                          $"Content Size: {decryptedContent.Length:N0} characters\n" +
                          $"Success: True\n";
            
            await File.WriteAllTextAsync(metadataPath, metadata);
            
            _logger.LogInformation("💾 Saved cracked file: {FilePath}", crackedFilePath);
            _logger.LogInformation("📋 Saved metadata: {MetadataPath}", metadataPath);
            
            return crackedFilePath;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Failed to save cracked file for {FilePath}", originalFilePath);
            return "";
        }
    }

    /// <summary>
    /// Generate intelligence-based keys for PLAN A
    /// </summary>
    public async Task<List<string>> GenerateIntelligenceKeys(string filePath)
    {
        var keys = new List<string>();
        
        // Extract intelligence from file path
        var fileName = Path.GetFileNameWithoutExtension(filePath);
        var directoryName = Path.GetFileName(Path.GetDirectoryName(filePath) ?? "");
        
        // Basic intelligence extraction from path
        var companies = new[] { "Exxerpro", "Rockwell", "Allen", "Bradley", "Siemens", "Schneider" };
        var projects = new[] { fileName, directoryName, "Main", "Project", "Demo", "Test" };
        var years = new[] { "2020", "2021", "2022", "2023", "2024", "2025" };
        
        // Generate keys based on intelligence
        foreach (var company in companies)
        {
            foreach (var project in projects)
            {
                foreach (var year in years)
                {
                    keys.Add($"{company}");
                    keys.Add($"{project}");
                    keys.Add($"{company}{year}");
                    keys.Add($"{project}{year}");
                    keys.Add($"{company}, {project}");
                    keys.Add($"{company}, {company}");
                    keys.Add($"{project}, {project}");
                }
            }
        }
        
        return keys.Distinct().ToList();
    }

    /// <summary>
    /// Generate OEM-based keys for PLAN A
    /// </summary>
    public async Task<List<string>> GenerateOEMKeys(string filePath)
    {
        var keys = new List<string>();
        
        // Common OEM patterns
        var companies = new[] { "Rockwell", "Allen", "Bradley", "Siemens", "Schneider", "Mitsubishi", "Omron", "GE", "Honeywell", "Emerson" };
        var projects = new[] { "Main", "Project", "Demo", "Test", "Sample", "Example", "Production", "Line", "Station", "Cell" };
        var years = new[] { "2020", "2021", "2022", "2023", "2024", "2025" };
        
        foreach (var company in companies)
        {
            foreach (var project in projects)
            {
                foreach (var year in years)
                {
                    keys.Add($"{company}");
                    keys.Add($"{project}");
                    keys.Add($"{company}{year}");
                    keys.Add($"{project}{year}");
                    keys.Add($"{company}, {project}");
                }
            }
        }
        
        return keys.Distinct().ToList();
    }

    /// <summary>
    /// Generate dictionary keys for PLAN A
    /// </summary>
    public async Task<List<string>> GenerateDictionaryKeys()
    {
        var keys = new List<string>();
        
        // Standard dictionary
        keys.AddRange(new[]
        {
            "password", "admin", "123456", "12345", "1234", "test", "default", "user",
            "root", "guest", "demo", "sample", "example", "main", "project", "system",
            "master", "supervisor", "operator", "engineer", "technician", "service",
            "maintenance", "factory", "production", "line", "station", "cell", "zone",
            "area", "unit", "module", "device", "control", "automation", "plc", "hmi",
            "scada", "dcs", "mes", "erp", "opc", "modbus", "ethernet", "profibus",
            "profinet", "devicenet", "controlnet", "canbus", "fieldbus", "io", "ai",
            "di", "do", "pid", "loop", "tag", "alarm", "event", "history", "trend",
            "recipe", "batch", "sequence", "program", "routine", "logic", "ladder",
            "function", "block", "instruction", "rung", "branch", "contact", "coil",
            "timer", "counter", "compare", "math", "move", "copy", "file", "array",
            "string", "real", "integer", "bool", "dint", "sint", "lint", "usint",
            "uint", "udint", "ulint", "lreal", "time", "date", "datetime", "tod"
        });
        
        return keys.Distinct().ToList();
    }
}