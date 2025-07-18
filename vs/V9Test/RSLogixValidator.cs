using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

/// <summary>
/// PLAN A Phase 2.3: RSLogix Structure Validation
/// Dual approach: Instruction keywords + Repeated token analysis
/// Handles potential tokenization/obfuscation
/// </summary>
public class RSLogixValidator
{
    private readonly ILogger<RSLogixValidator> _logger;
    private readonly HashSet<string> _rslogixInstructions;
    private readonly HashSet<string> _rslogixStructures;

    public RSLogixValidator(ILogger<RSLogixValidator> logger)
    {
        _logger = logger;
        _rslogixInstructions = BuildRSLogixInstructionDictionary();
        _rslogixStructures = BuildRSLogixStructureDictionary();
    }

    /// <summary>
    /// Validate decrypted content using dual approach
    /// </summary>
    public ValidationResult ValidateDecryptedContent(string decryptedContent, string key)
    {
        if (string.IsNullOrEmpty(decryptedContent) || decryptedContent.Length < 50)
        {
            return new ValidationResult { IsValid = false, Score = 0, Key = key };
        }

        var result = new ValidationResult { Key = key };
        
        // Approach 1: Count RSLogix instruction keywords
        var instructionScore = CountInstructionKeywords(decryptedContent);
        result.InstructionMatches = instructionScore.matches;
        result.InstructionScore = instructionScore.score;
        
        // Approach 2: Count RSLogix structure keywords
        var structureScore = CountStructureKeywords(decryptedContent);
        result.StructureMatches = structureScore.matches;
        result.StructureScore = structureScore.score;
        
        // Approach 3: Analyze repeated tokens (compression/tokenization indicators)
        var tokenScore = AnalyzeRepeatedTokens(decryptedContent);
        result.RepeatedTokens = tokenScore.tokens;
        result.TokenScore = tokenScore.score;
        
        // Approach 4: Check for XML-like structure
        var xmlScore = AnalyzeXMLStructure(decryptedContent);
        result.XMLScore = xmlScore;
        
        // Calculate composite score
        result.Score = CalculateCompositeScore(result);
        result.IsValid = result.Score > 10; // Threshold for "promising" result
        
        _logger.LogDebug("🔍 Validation: Key={Key}, Instructions={InstrCount}, Structures={StructCount}, Tokens={TokenCount}, XML={XMLScore}, Total={Score}",
            key, result.InstructionMatches, result.StructureMatches, result.RepeatedTokens.Count, result.XMLScore, result.Score);
        
        return result;
    }

    /// <summary>
    /// Count RSLogix instruction keywords
    /// </summary>
    private (int matches, int score) CountInstructionKeywords(string content)
    {
        var matches = 0;
        var contentUpper = content.ToUpper();
        
        foreach (var instruction in _rslogixInstructions)
        {
            if (contentUpper.Contains(instruction))
            {
                matches++;
            }
        }
        
        // Higher score for more instruction matches
        var score = matches * 5;
        return (matches, score);
    }

    /// <summary>
    /// Count RSLogix structure keywords
    /// </summary>
    private (int matches, int score) CountStructureKeywords(string content)
    {
        var matches = 0;
        var contentUpper = content.ToUpper();
        
        foreach (var structure in _rslogixStructures)
        {
            if (contentUpper.Contains(structure))
            {
                matches++;
            }
        }
        
        // Higher score for structure matches (more important)
        var score = matches * 10;
        return (matches, score);
    }

    /// <summary>
    /// Analyze repeated tokens (could indicate successful decryption)
    /// </summary>
    private (List<string> tokens, int score) AnalyzeRepeatedTokens(string content)
    {
        var tokenCounts = new Dictionary<string, int>();
        var repeatedTokens = new List<string>();
        
        // Extract potential tokens (3-8 character sequences)
        var tokenPattern = @"\b[A-Za-z0-9]{3,8}\b";
        var matches = Regex.Matches(content, tokenPattern);
        
        foreach (Match match in matches)
        {
            var token = match.Value.ToUpper();
            tokenCounts[token] = tokenCounts.GetValueOrDefault(token, 0) + 1;
        }
        
        // Find tokens that appear multiple times
        foreach (var kvp in tokenCounts)
        {
            if (kvp.Value >= 3) // Appears 3+ times
            {
                repeatedTokens.Add($"{kvp.Key}({kvp.Value})");
            }
        }
        
        // Score based on number of repeated tokens
        var score = repeatedTokens.Count * 3;
        return (repeatedTokens, score);
    }

    /// <summary>
    /// Check for XML-like structure
    /// </summary>
    private int AnalyzeXMLStructure(string content)
    {
        var score = 0;
        
        // Look for XML-like patterns
        if (content.Contains("<") && content.Contains(">")) score += 5;
        if (content.Contains("</")) score += 10; // Closing tags
        if (content.Contains("=\"")) score += 5; // Attributes
        if (Regex.IsMatch(content, @"<[A-Za-z][^>]*>")) score += 10; // Valid XML tags
        
        return score;
    }

    /// <summary>
    /// Calculate composite score
    /// </summary>
    private int CalculateCompositeScore(ValidationResult result)
    {
        return result.InstructionScore + result.StructureScore + result.TokenScore + result.XMLScore;
    }

    /// <summary>
    /// Build comprehensive RSLogix instruction dictionary
    /// </summary>
    private HashSet<string> BuildRSLogixInstructionDictionary()
    {
        return new HashSet<string>
        {
            // Bit Logic Instructions
            "XIC", "XIO", "OTE", "OTL", "OTU", "OSR", "OSF", "ONS",
            
            // Timer Instructions
            "TON", "TOF", "RTO", "TONR", "TOFR", "RTOR",
            
            // Counter Instructions
            "CTU", "CTD", "RES", "CTUD",
            
            // Math Instructions
            "ADD", "SUB", "MUL", "DIV", "MOD", "SQR", "ABS", "NEG",
            "SIN", "COS", "TAN", "ASN", "ACS", "ATN", "LN", "LOG",
            
            // Compare Instructions
            "EQU", "NEQ", "LES", "LEQ", "GRT", "GEQ", "LIM", "MEQ",
            
            // Move Instructions
            "MOV", "MVM", "COP", "FLL", "SWPB", "CLR",
            
            // File Instructions
            "FAL", "FSC", "AVE", "SUM", "STD", "SRT",
            
            // Program Control
            "JSR", "SBR", "RET", "JMP", "LBL", "MCR", "TND", "AFI",
            "NOP", "UID", "UIE", "OVR", "SFR", "SFP",
            
            // Communication
            "MSG", "PID", "PIDE", "RMPS", "SCALE", "SCL", "DEDT",
            
            // Diagnostic
            "DTR", "GSV", "SSV", "IOT", "REF",
            
            // Motion
            "MSO", "MSF", "MAH", "MAM", "MAS", "MAW", "MAJ", "MCD",
            "MCLM", "MCCM", "MDO", "MDF", "MDR", "MDS", "MDW",
            
            // Additional Common Instructions
            "BTD", "BTR", "BTS", "FBC", "DDT", "DCD", "ENC", "SEL",
            "SIZE", "FIFO", "LIFO", "BSL", "BSR", "FFL", "FFU", "LFL", "LFU"
        };
    }

    /// <summary>
    /// Build RSLogix structure dictionary
    /// </summary>
    private HashSet<string> BuildRSLogixStructureDictionary()
    {
        return new HashSet<string>
        {
            // XML Structure
            "RUNG", "RLLCONTENT", "STCONTENT", "PROGRAM", "ROUTINE", "CONTROLLER",
            "DATATYPE", "TAG", "MEMBER", "ELEMENT", "ARRAY", "STRUCTURE",
            
            // RSLogix Specific
            "RSLOGIX", "RSLOGIX5000", "TARGETNAME", "TARGETTYPE", "LADDER",
            "ENCRYPTIONCONFIG", "ENCODEDDATA", "ENCODEDTYPE",
            
            // Data Types
            "BOOL", "SINT", "INT", "DINT", "REAL", "TIMER", "COUNTER",
            "STRING", "CONTROL", "PID", "MESSAGE",
            
            // Attributes
            "NAME", "TYPE", "VALUE", "RADIX", "DIMENSION", "HIDDEN",
            "EXTERNALACCESS", "CONSTANT", "DESCRIPTION"
        };
    }
}

/// <summary>
/// Validation result for decrypted content
/// </summary>
public class ValidationResult
{
    public string Key { get; set; } = "";
    public bool IsValid { get; set; }
    public int Score { get; set; }
    public int InstructionMatches { get; set; }
    public int InstructionScore { get; set; }
    public int StructureMatches { get; set; }
    public int StructureScore { get; set; }
    public List<string> RepeatedTokens { get; set; } = new();
    public int TokenScore { get; set; }
    public int XMLScore { get; set; }
    
    public override string ToString()
    {
        return $"Key={Key}, Score={Score}, Valid={IsValid}, Instr={InstructionMatches}, Struct={StructureMatches}, Tokens={RepeatedTokens.Count}";
    }
}