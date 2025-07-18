using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

/// <summary>
/// PLAN A: EncodedData Content Extraction and Management
/// Extracts only the encrypted content from EncodedData sections
/// </summary>
public class EncodedDataExtractor
{
    private readonly ILogger<EncodedDataExtractor> _logger;

    public EncodedDataExtractor(ILogger<EncodedDataExtractor> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Extract EncodedData content from all target files
    /// Returns Dictionary<filename, base64_content>
    /// </summary>
    public async Task<Dictionary<string, string>> ExtractEncodedDataAsync(string[] filePaths)
    {
        var encodedDataDict = new Dictionary<string, string>();
        
        _logger.LogInformation("🔍 PLAN A: Extracting EncodedData content from {Count} files", filePaths.Length);

        foreach (var filePath in filePaths)
        {
            try
            {
                var fileName = Path.GetFileName(filePath);
                var encodedContent = await ExtractEncodedDataFromFileAsync(filePath);
                
                if (!string.IsNullOrEmpty(encodedContent))
                {
                    encodedDataDict[fileName] = encodedContent;
                    _logger.LogInformation("✅ {FileName}: Extracted {Size} chars of EncodedData", 
                        fileName, encodedContent.Length);
                }
                else
                {
                    _logger.LogWarning("⚠️ {FileName}: No EncodedData found", fileName);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "❌ Failed to extract EncodedData from {FilePath}", filePath);
            }
        }

        _logger.LogInformation("🎯 PLAN A: Extracted EncodedData from {Count}/{Total} files", 
            encodedDataDict.Count, filePaths.Length);
        
        return encodedDataDict;
    }

    /// <summary>
    /// Extract EncodedData content from a single file
    /// Looks for <EncodedData...EncryptionConfig="9">...base64...</EncodedData>
    /// </summary>
    private async Task<string> ExtractEncodedDataFromFileAsync(string filePath)
    {
        var content = await File.ReadAllTextAsync(filePath);
        
        // Pattern to match EncodedData with EncryptionConfig="9"
        var pattern = @"<EncodedData[^>]*EncryptionConfig=""9""[^>]*>\s*([A-Za-z0-9+/=\s]+)\s*</EncodedData>";
        var match = Regex.Match(content, pattern, RegexOptions.Singleline);
        
        if (match.Success)
        {
            // Extract and clean the base64 content
            var base64Content = match.Groups[1].Value;
            base64Content = Regex.Replace(base64Content, @"\s+", ""); // Remove all whitespace
            
            _logger.LogDebug("🔍 Found EncodedData in {FileName}: {Size} chars", 
                Path.GetFileName(filePath), base64Content.Length);
            
            return base64Content;
        }
        
        return "";
    }

    /// <summary>
    /// Get sample of files for testing (pick 4 random files)
    /// </summary>
    public Dictionary<string, string> GetSampleFiles(Dictionary<string, string> allFiles, int sampleSize = 4)
    {
        var sampleDict = new Dictionary<string, string>();
        var fileList = new List<string>(allFiles.Keys);
        
        // Use deterministic "random" selection based on filename hash
        var selectedFiles = new HashSet<string>();
        var random = new Random(42); // Fixed seed for reproducibility
        
        while (selectedFiles.Count < Math.Min(sampleSize, fileList.Count))
        {
            var randomIndex = random.Next(fileList.Count);
            selectedFiles.Add(fileList[randomIndex]);
        }
        
        foreach (var fileName in selectedFiles)
        {
            sampleDict[fileName] = allFiles[fileName];
        }
        
        _logger.LogInformation("📊 Selected {Count} sample files: {Files}", 
            sampleDict.Count, string.Join(", ", sampleDict.Keys));
        
        return sampleDict;
    }
}