using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

class V9TestProgram
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🚀 PLAN A: STRUCTURED ENCODEDDATA DECRYPTION");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine("🔍 Extracts EncodedData content + Multi-algorithm testing");
        Console.WriteLine("💡 Dual validation: RSLogix keywords + Repeated tokens");
        Console.WriteLine("🎯 Focus on actual encrypted content, not XML structure");
        Console.WriteLine();
        
        // Setup logging
        using var loggerFactory = LoggerFactory.Create(builder =>
            builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        
        var extractorLogger = loggerFactory.CreateLogger<EncodedDataExtractor>();
        var decryptorLogger = loggerFactory.CreateLogger<EncodedDataDecryptor>();
        var validatorLogger = loggerFactory.CreateLogger<RSLogixValidator>();
        var orchestratorLogger = loggerFactory.CreateLogger<PlanAOrchestrator>();
        var crackerLogger = loggerFactory.CreateLogger<V9IntelligentCracker>();
        var l5xDecryptorLogger = loggerFactory.CreateLogger<L5XDecryptor>();
        
        // Initialize PLAN A components
        var extractor = new EncodedDataExtractor(extractorLogger);
        var validator = new RSLogixValidator(validatorLogger);
        var encodedDecryptor = new EncodedDataDecryptor(decryptorLogger, validator);
        
        // Initialize legacy components for key generation
        var emptyKeyStore = new KeyStore();
        var l5xDecryptor = new L5XDecryptor(emptyKeyStore, l5xDecryptorLogger);
        var cracker = new V9IntelligentCracker(l5xDecryptor, crackerLogger);
        
        // Initialize orchestrator
        var orchestrator = new PlanAOrchestrator(
            orchestratorLogger,
            extractor,
            encodedDecryptor,
            validator,
            cracker);
        
        // Get all target files
        var targetDirectory = "/mnt/e/Dynamic/Source/DecryptSourceProtection/target";
        var targetFiles = Directory.GetFiles(targetDirectory, "*.L5X");
        
        Console.WriteLine($"📂 Target Directory: {targetDirectory}");
        Console.WriteLine($"📊 Found {targetFiles.Length} L5X files");
        Console.WriteLine();
        
        try
        {
            var startTime = DateTime.Now;
            
            // Execute PLAN A
            var results = await orchestrator.ExecutePlanAAsync(targetFiles);
            
            var elapsed = DateTime.Now - startTime;
            
            // Display results
            DisplayResults(results, elapsed);
            
            // Save results to organized folder structure
            await orchestrator.SaveResultsAsync(results, targetDirectory);
            
        }
        catch (Exception ex)
        {
            Console.WriteLine($"💥 PLAN A FAILED: {ex.Message}");
            Console.WriteLine($"🔍 Stack Trace: {ex.StackTrace}");
        }
        
        Console.WriteLine("\n🎯 PLAN A Complete!");
    }
    
    private static void DisplayResults(PlanAResults results, TimeSpan elapsed)
    {
        Console.WriteLine("\n🏆 PLAN A RESULTS");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine($"⏱️ Total Time: {elapsed.TotalSeconds:F1} seconds");
        Console.WriteLine($"✅ Success: {results.Success}");
        Console.WriteLine($"📊 Total Candidates: {results.TotalCandidates}");
        Console.WriteLine($"🎯 Best Score: {results.BestScore}");
        Console.WriteLine();
        
        // Phase results
        Console.WriteLine("📋 PHASE RESULTS:");
        Console.WriteLine($"🧠 Intelligence Results: {results.IntelligenceResults.Count}");
        Console.WriteLine($"🏭 OEM Results: {results.OEMResults.Count}");
        Console.WriteLine($"📖 Dictionary Results: {results.DictionaryResults.Count}");
        Console.WriteLine($"🔑 Known Key Results: {results.KnownKeyResults.Count}");
        Console.WriteLine();
        
        // Top candidates
        if (results.TopCandidates.Any())
        {
            Console.WriteLine("🏆 TOP CANDIDATES:");
            var top10 = results.TopCandidates.Take(10).ToList();
            for (int i = 0; i < top10.Count; i++)
            {
                var candidate = top10[i];
                Console.WriteLine($"#{i+1:D2}: {candidate}");
                Console.WriteLine($"       Instructions: {candidate.ValidationResult.InstructionMatches}");
                Console.WriteLine($"       Structures: {candidate.ValidationResult.StructureMatches}");
                Console.WriteLine($"       Tokens: {string.Join(", ", candidate.ValidationResult.RepeatedTokens)}");
                
                var preview = candidate.DecryptedContent.Length > 100 
                    ? candidate.DecryptedContent.Substring(0, 100).Replace('\n', ' ').Replace('\r', ' ') + "..."
                    : candidate.DecryptedContent.Replace('\n', ' ').Replace('\r', ' ');
                Console.WriteLine($"       Preview: {preview}");
                Console.WriteLine();
            }
        }
        else
        {
            Console.WriteLine("❌ No promising candidates found");
        }
        
        // Recommendations
        Console.WriteLine("💡 RECOMMENDATIONS:");
        if (results.Success && results.BestScore > 50)
        {
            Console.WriteLine("🎉 Strong candidates found! Check the saved samples for manual verification.");
        }
        else if (results.Success && results.BestScore > 20)
        {
            Console.WriteLine("🔍 Moderate candidates found. May need additional validation or key variants.");
        }
        else
        {
            Console.WriteLine("⚠️ Low scores suggest:");
            Console.WriteLine("  - Encryption algorithm may be different than expected");
            Console.WriteLine("  - Key derivation method may be more complex");
            Console.WriteLine("  - Additional layers of encryption/compression");
            Console.WriteLine("  - Need domain-specific password patterns");
        }
        
        if (!string.IsNullOrEmpty(results.Error))
        {
            Console.WriteLine($"❌ Error: {results.Error}");
        }
    }
}
