using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
using Xunit.Abstractions;

namespace LogixSourceTests
{
    public class V9IntelligentCrackerTest
    {
        private readonly ITestOutputHelper _output;

        public V9IntelligentCrackerTest(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task CrackV9UnknownFiles_ShouldSucceed()
        {
            _output.WriteLine("🎯 V9 INTELLIGENT DICTIONARY CRACKER");
            _output.WriteLine("=" + new string('=', 80));
            _output.WriteLine("🔍 Intelligence-based + OEM patterns + Standard dictionary attack");
            _output.WriteLine("💡 Based on real-world OEM password usage patterns");
            _output.WriteLine("");
        
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
            _output.WriteLine($"\n🎯 CRACKING: {fileName} ({category})");
            _output.WriteLine("=" + new string('=', 80));
            
            try
            {
                var filePath = Path.Combine(basePath, fileName);
                if (!File.Exists(filePath))
                {
                    _output.WriteLine($"❌ File not found: {fileName}");
                    continue;
                }
                
                totalFiles++;
                _output.WriteLine($"📂 Target: {filePath}");
                
                var startTime = DateTime.Now;
                
                // Attempt intelligent crack
                var result = await cracker.CrackV9FileAsync(filePath);
                
                var elapsed = DateTime.Now - startTime;
                
                if (result.Success)
                {
                    totalSuccesses++;
                    _output.WriteLine($"\n🎉 SUCCESS! File cracked in {elapsed.TotalSeconds:F1} seconds");
                    _output.WriteLine($"🔑 Key found: '{result.Key}'");
                    _output.WriteLine($"📝 Decrypted content length: {result.DecryptedContent.Length:N0} chars");
                    
                    // Save decrypted content
                    var outputPath = Path.Combine("/tmp", $"{fileName}.CRACKED.xml");
                    await File.WriteAllTextAsync(outputPath, result.DecryptedContent);
                    _output.WriteLine($"💾 Saved to: {outputPath}");
                    
                    // Show sample
                    var sample = result.DecryptedContent.Length > 300 
                        ? result.DecryptedContent.Substring(0, 300) + "..."
                        : result.DecryptedContent;
                    _output.WriteLine($"📋 Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
                }
                else
                {
                    _output.WriteLine($"\n❌ FAILED: Could not crack {fileName} in {elapsed.TotalSeconds:F1} seconds");
                    _output.WriteLine("🔍 Key not found in any attack phase");
                }
            }
            catch (Exception ex)
            {
                _output.WriteLine($"💥 EXCEPTION: {fileName} - {ex.Message}");
            }
        }
        
        // Summary
        _output.WriteLine("\n🏆 V9 INTELLIGENT CRACKER RESULTS");
        _output.WriteLine("=" + new string('=', 80));
        _output.WriteLine($"📊 Success Rate: {totalSuccesses}/{totalFiles} ({(100.0 * totalSuccesses / totalFiles):F1}%)");
        
        if (totalSuccesses == totalFiles)
        {
            _output.WriteLine("🎉 COMPLETE SUCCESS! All files cracked!");
        }
        else if (totalSuccesses > 0)
        {
            _output.WriteLine($"✅ PARTIAL SUCCESS! {totalSuccesses} files cracked!");
        }
        else
        {
            _output.WriteLine("❌ NO SUCCESS - May need additional keywords or patterns");
        }
        
        _output.WriteLine("\n💡 RECOMMENDATIONS:");
        if (totalSuccesses < totalFiles)
        {
            _output.WriteLine("- Add more company/project specific keywords");
            _output.WriteLine("- Check for additional password patterns in documentation");
            _output.WriteLine("- Consider extending dictionary with domain-specific terms");
            _output.WriteLine("- Analyze any successful patterns for insights");
        }
        
        _output.WriteLine("\n🎯 V9 Intelligent Cracker Complete!");
        
        // Assert at least one success for validation
        Assert.True(totalSuccesses > 0, "At least one file should be successfully cracked");
    }
    }
}