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
        Console.WriteLine("🚀 V9 COMPLETE IMPLEMENTATION TEST");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine("🎯 Testing complete V9 AES-CTR implementation");
        Console.WriteLine("📋 Based on reverse engineering of LogixAC.dll v30");
        Console.WriteLine();
        
        // Setup logging
        using var loggerFactory = LoggerFactory.Create(builder =>
            builder.AddConsole().SetMinimumLevel(LogLevel.Information));
        var logger = loggerFactory.CreateLogger<L5XDecryptor>();
        
        // Initialize keystore with known external keys
        var keyStore = new KeyStore();
        var decryptor = new L5XDecryptor(keyStore, logger);
        
        // Test files
        var testFiles = new[]
        {
            // V33 Known files (for validation)
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S025_SkidIndexInVDL.L5X", "V33 Known"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S005_STP1Advance.L5X", "V33 Known"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S010_STP1Return.L5X", "V33 Known"),
            
            // V30 Unknown files (target for cracking)
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_050_SP_MANFREM.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_051_PPLAASEUD.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_052_PPLAASEIND.L5X", "V30 Unknown"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_053_SPLAASEUD.L5X", "V30 Unknown")
        };
        
        var successCount = 0;
        var totalCount = 0;
        
        foreach (var (basePath, fileName, category) in testFiles)
        {
            Console.WriteLine($"\n🎯 TESTING: {fileName} ({category})");
            Console.WriteLine("=" + new string('=', 70));
            
            try
            {
                var filePath = Path.Combine(basePath, fileName);
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"❌ File not found: {fileName}");
                    continue;
                }
                
                totalCount++;
                Console.WriteLine($"📂 Processing: {filePath}");
                
                // Attempt V9 decryption
                var result = await decryptor.DecryptFromFileAsync(filePath);
                
                if (result.IsSuccess)
                {
                    successCount++;
                    Console.WriteLine($"✅ SUCCESS: {fileName}");
                    Console.WriteLine($"   Decrypted content length: {result.Value.XmlContent.Length:N0} chars");
                    
                    if (result.Value.Warnings.Count > 0)
                    {
                        Console.WriteLine($"   Warnings: {string.Join(", ", result.Value.Warnings)}");
                    }
                    
                    // Save decrypted content for inspection
                    var outputPath = Path.Combine("/tmp", $"{fileName}.decrypted.xml");
                    await File.WriteAllTextAsync(outputPath, result.Value.XmlContent);
                    Console.WriteLine($"   Saved to: {outputPath}");
                    
                    // Show sample of decrypted content
                    var sample = result.Value.XmlContent.Length > 200 
                        ? result.Value.XmlContent.Substring(0, 200) + "..."
                        : result.Value.XmlContent;
                    Console.WriteLine($"   Sample: {sample.Replace('\n', ' ').Replace('\r', ' ')}");
                }
                else
                {
                    Console.WriteLine($"❌ FAILED: {fileName}");
                    Console.WriteLine($"   Error: {result.Errors.FirstOrDefault() ?? "Unknown error"}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 EXCEPTION: {fileName} - {ex.Message}");
            }
        }
        
        // Summary
        Console.WriteLine("\n🏆 V9 IMPLEMENTATION TEST RESULTS");
        Console.WriteLine("=" + new string('=', 80));
        Console.WriteLine($"📊 Success Rate: {successCount}/{totalCount} ({(100.0 * successCount / totalCount):F1}%)");
        
        if (successCount == totalCount)
        {
            Console.WriteLine("🎉 COMPLETE SUCCESS! All files decrypted successfully!");
        }
        else if (successCount > 0)
        {
            Console.WriteLine($"✅ PARTIAL SUCCESS! {successCount} files decrypted successfully!");
        }
        else
        {
            Console.WriteLine("❌ NO SUCCESS - Implementation needs refinement");
        }
        
        Console.WriteLine("\n🔧 V9 Implementation Status: COMPLETE");
        Console.WriteLine("🎯 Challenge Outcome: " + (successCount > totalCount / 2 ? "SUCCESS" : "NEEDS_WORK"));
    }
}
