using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;

class V9IntelligentCrackerConsole
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🎯 V9 INTELLIGENT DICTIONARY CRACKER");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine("🔍 Intelligence-based + OEM patterns + Standard dictionary attack");
        Console.WriteLine("💡 Based on real-world OEM password usage patterns");
        Console.WriteLine();
        
        // Setup logging
        using var loggerFactory = LoggerFactory.Create(builder =>
            builder.SetMinimumLevel(LogLevel.Information));
        var logger = loggerFactory.CreateLogger<V9IntelligentCracker>();
        var decryptorLogger = loggerFactory.CreateLogger<L5XDecryptor>();
        
        // Initialize components
        var emptyKeyStore = new KeyStore(); // Start with empty keystore
        var decryptor = new L5XDecryptor(emptyKeyStore, decryptorLogger);
        var cracker = new V9IntelligentCracker(decryptor, logger);
        
        // Test files - focus on unknown V30 files
        var testFiles = new[]
        {
            // V30 Unknown files (our target)
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_050_SP_MANFREM.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_051_PPLAASEUD.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_052_PPLAASEIND.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_053_SPLAASEUD.L5X", "V30 Unknown"),
            
            // V33 Known files (for validation - should find "Stana7")
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S025_SkidIndexInVDL.L5X", "V33 Known (Validation)"),
        };
        
        var totalSuccesses = 0;
        var totalFiles = 0;
        
        foreach (var (basePath, fileName, category) in testFiles)
        {
            Console.WriteLine($"\n🎯 CRACKING: {fileName} ({category})");
            Console.WriteLine("=" + new string('=', 80));
            
            try
            {
                var filePath = Path.Combine(basePath, fileName);
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"❌ File not found: {fileName}");
                    continue;
                }
                
                totalFiles++;
                Console.WriteLine($"📂 Target: {filePath}");
                
                var startTime = DateTime.Now;
                
                // Attempt intelligent crack
                var result = await cracker.CrackV9FileAsync(filePath);
                
                var elapsed = DateTime.Now - startTime;
                
                if (result.Success)
                {
                    totalSuccesses++;
                    Console.WriteLine($"\n🎉 SUCCESS! File cracked in {elapsed.TotalSeconds:F1} seconds");
                    Console.WriteLine($"🔑 Key found: '{result.Key}'");
                    Console.WriteLine($"📝 Decrypted content length: {result.DecryptedContent.Length:N0} chars");
                    
                    // Save decrypted content
                    var outputPath = Path.Combine("/tmp", $"{fileName}.CRACKED.xml");
                    await File.WriteAllTextAsync(outputPath, result.DecryptedContent);
                    Console.WriteLine($"💾 Saved to: {outputPath}");
                    
                    // Show sample
                    var sample = result.DecryptedContent.Length > 300 
                        ? result.DecryptedContent.Substring(0, 300) + "..."
                        : result.DecryptedContent;
                    Console.WriteLine($"📋 Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
                }
                else
                {
                    Console.WriteLine($"\n❌ FAILED: Could not crack {fileName} in {elapsed.TotalSeconds:F1} seconds");
                    Console.WriteLine("🔍 Key not found in any attack phase");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 EXCEPTION: {fileName} - {ex.Message}");
            }
        }
        
        // Summary
        Console.WriteLine("\n🏆 V9 INTELLIGENT CRACKER RESULTS");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine($"📊 Success Rate: {totalSuccesses}/{totalFiles} ({(100.0 * totalSuccesses / totalFiles):F1}%)");
        
        if (totalSuccesses == totalFiles)
        {
            Console.WriteLine("🎉 COMPLETE SUCCESS! All files cracked!");
        }
        else if (totalSuccesses > 0)
        {
            Console.WriteLine($"✅ PARTIAL SUCCESS! {totalSuccesses} files cracked!");
        }
        else
        {
            Console.WriteLine("❌ NO SUCCESS - May need additional keywords or patterns");
        }
        
        Console.WriteLine("\n💡 RECOMMENDATIONS:");
        if (totalSuccesses < totalFiles)
        {
            Console.WriteLine("- Add more company/project specific keywords");
            Console.WriteLine("- Check for additional password patterns in documentation");
            Console.WriteLine("- Consider extending dictionary with domain-specific terms");
            Console.WriteLine("- Analyze any successful patterns for insights");
        }
        
        Console.WriteLine("\n🎯 V9 Intelligent Cracker Complete!");
    }
}