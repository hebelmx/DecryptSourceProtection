using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

/// <summary>
/// PLAN A: Main Orchestrator for Structured EncodedData Decryption
/// Coordinates all phases of the attack
/// </summary>
public class PlanAOrchestrator
{
    private readonly ILogger<PlanAOrchestrator> _logger;
    private readonly EncodedDataExtractor _extractor;
    private readonly EncodedDataDecryptor _decryptor;
    private readonly RSLogixValidator _validator;
    private readonly V9IntelligentCracker _cracker;

    public PlanAOrchestrator(
        ILogger<PlanAOrchestrator> logger,
        EncodedDataExtractor extractor,
        EncodedDataDecryptor decryptor,
        RSLogixValidator validator,
        V9IntelligentCracker cracker)
    {
        _logger = logger;
        _extractor = extractor;
        _decryptor = decryptor;
        _validator = validator;
        _cracker = cracker;
    }

    /// <summary>
    /// Execute PLAN A: Complete structured attack
    /// </summary>
    public async Task<PlanAResults> ExecutePlanAAsync(string[] targetFiles)
    {
        _logger.LogInformation("🚀 PLAN A: Starting structured EncodedData decryption attack");
        _logger.LogInformation("📊 Target files: {Count}", targetFiles.Length);

        var results = new PlanAResults();
        
        try
        {
            // Phase 1: Extract EncodedData content
            _logger.LogInformation("🔍 Phase 1: Extracting EncodedData content...");
            var encodedDataDict = await _extractor.ExtractEncodedDataAsync(targetFiles);
            
            if (encodedDataDict.Count == 0)
            {
                _logger.LogError("❌ No EncodedData content found in target files");
                return results;
            }

            // Select sample files for testing (4 random files)
            var sampleFiles = _extractor.GetSampleFiles(encodedDataDict, 4);
            _logger.LogInformation("📊 Using {Count} sample files for testing", sampleFiles.Count);

            // Phase 2: Test different attack phases
            await ExecuteAttackPhases(sampleFiles, results);

            // Phase 3: Test with known key files (if available)
            await TestWithKnownKeyFiles(sampleFiles, results);

            // Phase 4: Generate final report
            GenerateFinalReport(results);

        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ PLAN A execution failed");
            results.Success = false;
            results.Error = ex.Message;
        }

        return results;
    }

    /// <summary>
    /// Execute different attack phases
    /// </summary>
    private async Task ExecuteAttackPhases(Dictionary<string, string> sampleFiles, PlanAResults results)
    {
        _logger.LogInformation("🎯 Phase 2: Executing attack phases...");

        // Phase 2.1: Intelligence-based attack
        var intelligenceKeys = await _cracker.GenerateIntelligenceKeys(sampleFiles.Keys.First());
        var intelligenceResults = await _decryptor.TestKeyCandidatesAsync(sampleFiles, intelligenceKeys, "Intelligence");
        results.IntelligenceResults.AddRange(intelligenceResults);
        
        // Phase 2.2: OEM pattern attack
        var oemKeys = await _cracker.GenerateOEMKeys(sampleFiles.Keys.First());
        var oemResults = await _decryptor.TestKeyCandidatesAsync(sampleFiles, oemKeys, "OEM");
        results.OEMResults.AddRange(oemResults);
        
        // Phase 2.3: Dictionary attack
        var dictionaryKeys = await _cracker.GenerateDictionaryKeys();
        var dictionaryResults = await _decryptor.TestKeyCandidatesAsync(sampleFiles, dictionaryKeys, "Dictionary");
        results.DictionaryResults.AddRange(dictionaryResults);

        // Save top 8 results from each phase
        results.TopCandidates = CombineAndRankResults(results);
    }

    /// <summary>
    /// Test with known key files (key not first in dictionary)
    /// </summary>
    private async Task TestWithKnownKeyFiles(Dictionary<string, string> sampleFiles, PlanAResults results)
    {
        _logger.LogInformation("🔑 Phase 3: Testing with known key files...");

        // Test with known keys from V33 files (but not as first priority)
        var knownKeys = new List<string>
        {
            "admin", "password", "12345", "test", "default",
            "Stana7", "Visual", "Demo", "Sample", "Example",
            "Rockwell", "Allen", "Bradley", "RSLogix", "Logix5000"
        };

        // Mix known keys into middle of dictionary (not first)
        var mixedKeys = new List<string>();
        mixedKeys.AddRange(await _cracker.GenerateIntelligenceKeys(sampleFiles.Keys.First()));
        mixedKeys.AddRange(knownKeys); // Add known keys in middle
        mixedKeys.AddRange(await _cracker.GenerateDictionaryKeys());

        var knownKeyResults = await _decryptor.TestKeyCandidatesAsync(sampleFiles, mixedKeys, "KnownKeys");
        results.KnownKeyResults.AddRange(knownKeyResults);
    }

    /// <summary>
    /// Combine and rank all results
    /// </summary>
    private List<DecryptionCandidate> CombineAndRankResults(PlanAResults results)
    {
        var allResults = new List<DecryptionCandidate>();
        allResults.AddRange(results.IntelligenceResults);
        allResults.AddRange(results.OEMResults);
        allResults.AddRange(results.DictionaryResults);
        allResults.AddRange(results.KnownKeyResults);

        // Remove duplicates and sort by score
        var uniqueResults = allResults
            .GroupBy(r => $"{r.Key}_{r.FileName}")
            .Select(g => g.OrderByDescending(r => r.ValidationResult.Score).First())
            .OrderByDescending(r => r.ValidationResult.Score)
            .Take(24) // Top 24 results
            .ToList();

        return uniqueResults;
    }

    /// <summary>
    /// Generate final report
    /// </summary>
    private void GenerateFinalReport(PlanAResults results)
    {
        _logger.LogInformation("📋 Phase 4: Generating final report...");

        results.Success = results.TopCandidates.Count > 0;
        results.TotalCandidates = results.TopCandidates.Count;
        results.BestScore = results.TopCandidates.FirstOrDefault()?.ValidationResult.Score ?? 0;

        _logger.LogInformation("🏆 PLAN A Results:");
        _logger.LogInformation("📊 Total candidates: {Count}", results.TotalCandidates);
        _logger.LogInformation("🎯 Best score: {Score}", results.BestScore);
        _logger.LogInformation("✅ Success: {Success}", results.Success);

        // Log top 10 candidates
        var top10 = results.TopCandidates.Take(10).ToList();
        for (int i = 0; i < top10.Count; i++)
        {
            var candidate = top10[i];
            _logger.LogInformation("🏆 #{Rank}: {Candidate}", i + 1, candidate);
        }
    }

    /// <summary>
    /// Save results to organized folder structure
    /// </summary>
    public async Task SaveResultsAsync(PlanAResults results, string targetDirectory)
    {
        try
        {
            var timestamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var resultsDir = Path.Combine(targetDirectory, "planA_results", $"session_{timestamp}");
            Directory.CreateDirectory(resultsDir);

            // Save top candidates
            var topCandidatesPath = Path.Combine(resultsDir, "top_candidates.txt");
            var report = GenerateDetailedReport(results);
            await File.WriteAllTextAsync(topCandidatesPath, report);

            // Save decrypted content samples (only top 8)
            var samplesDir = Path.Combine(resultsDir, "samples");
            Directory.CreateDirectory(samplesDir);

            var top8 = results.TopCandidates.Take(8).ToList();
            for (int i = 0; i < top8.Count; i++)
            {
                var candidate = top8[i];
                var samplePath = Path.Combine(samplesDir, $"sample_{i+1}_{candidate.Key}_{candidate.FileName}.txt");
                var content = $"Key: {candidate.Key}\n" +
                             $"File: {candidate.FileName}\n" +
                             $"Score: {candidate.ValidationResult.Score}\n" +
                             $"Valid: {candidate.ValidationResult.IsValid}\n" +
                             $"Instructions: {candidate.ValidationResult.InstructionMatches}\n" +
                             $"Structures: {candidate.ValidationResult.StructureMatches}\n" +
                             $"Tokens: {string.Join(", ", candidate.ValidationResult.RepeatedTokens)}\n" +
                             $"Content Length: {candidate.DecryptedContent.Length}\n" +
                             $"\n--- DECRYPTED CONTENT ---\n" +
                             $"{candidate.DecryptedContent.Substring(0, Math.Min(2000, candidate.DecryptedContent.Length))}";
                
                await File.WriteAllTextAsync(samplePath, content);
            }

            _logger.LogInformation("💾 Results saved to: {Directory}", resultsDir);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "❌ Failed to save results");
        }
    }

    /// <summary>
    /// Generate detailed report
    /// </summary>
    private string GenerateDetailedReport(PlanAResults results)
    {
        var report = $"PLAN A: Structured EncodedData Decryption Results\n";
        report += $"=====================================================\n";
        report += $"Timestamp: {DateTime.Now:yyyy-MM-dd HH:mm:ss}\n";
        report += $"Success: {results.Success}\n";
        report += $"Total Candidates: {results.TotalCandidates}\n";
        report += $"Best Score: {results.BestScore}\n";
        report += $"Intelligence Results: {results.IntelligenceResults.Count}\n";
        report += $"OEM Results: {results.OEMResults.Count}\n";
        report += $"Dictionary Results: {results.DictionaryResults.Count}\n";
        report += $"Known Key Results: {results.KnownKeyResults.Count}\n";
        report += $"\n";
        report += $"TOP CANDIDATES:\n";
        report += $"===============\n";

        for (int i = 0; i < Math.Min(24, results.TopCandidates.Count); i++)
        {
            var candidate = results.TopCandidates[i];
            report += $"#{i+1}: {candidate}\n";
            report += $"       Instructions: {candidate.ValidationResult.InstructionMatches}\n";
            report += $"       Structures: {candidate.ValidationResult.StructureMatches}\n";
            report += $"       Repeated Tokens: {string.Join(", ", candidate.ValidationResult.RepeatedTokens)}\n";
            report += $"       Content Preview: {candidate.DecryptedContent.Substring(0, Math.Min(100, candidate.DecryptedContent.Length)).Replace('\n', ' ')}\n";
            report += $"\n";
        }

        return report;
    }
}

/// <summary>
/// PLAN A execution results
/// </summary>
public class PlanAResults
{
    public bool Success { get; set; }
    public string Error { get; set; } = "";
    public int TotalCandidates { get; set; }
    public int BestScore { get; set; }
    
    public List<DecryptionCandidate> IntelligenceResults { get; set; } = new();
    public List<DecryptionCandidate> OEMResults { get; set; } = new();
    public List<DecryptionCandidate> DictionaryResults { get; set; } = new();
    public List<DecryptionCandidate> KnownKeyResults { get; set; } = new();
    public List<DecryptionCandidate> TopCandidates { get; set; } = new();
}