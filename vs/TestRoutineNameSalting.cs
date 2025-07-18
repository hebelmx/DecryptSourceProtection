using System;
using System.IO;
using System.Threading.Tasks;
using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;

// Simple test program to validate routine name-based salting
public class SimpleLogger : ILogger<L5XDecryptor>
{
    public IDisposable BeginScope<TState>(TState state) => null!;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, 
        Func<TState, Exception?, string> formatter)
    {
        Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{logLevel}] {formatter(state, exception)}");
    }
}

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("🧂 ROUTINE NAME-BASED SALTING TEST");
        Console.WriteLine("=" + new string('=', 50));
        Console.WriteLine($"⏰ Started: {DateTime.Now}");
        Console.WriteLine();

        var logger = new SimpleLogger();
        var keyStore = new KeyStore();
        var decryptor = new L5XDecryptor(logger, keyStore);

        // Test files from V33
        var testFiles = new[]
        {
            "S025_SkidIndexInVDL.L5X",      // Known working
            "S005_STP1Advance.L5X",        // Target 1
            "S010_STP1Return.L5X",         // Target 2
            "S015_STP2Advance.L5X",        // Target 3
            "S020_STP2Return.L5X",         // Target 4
            "S025_SkidIndexOut_Clear.L5X"  // Target 5
        };

        var basePath = "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/";
        var successCount = 0;
        var breakthroughCount = 0;

        foreach (var fileName in testFiles)
        {
            var filePath = Path.Combine(basePath, fileName);
            
            Console.WriteLine($"📄 Testing: {fileName}");
            Console.WriteLine($"📂 Path: {filePath}");
            Console.WriteLine();

            if (!File.Exists(filePath))
            {
                Console.WriteLine($"❌ File not found: {filePath}");
                continue;
            }

            try
            {
                var result = await decryptor.DecryptFromFileAsync(filePath);
                
                if (result.IsSuccess)
                {
                    successCount++;
                    Console.WriteLine($"✅ SUCCESS: {fileName}");
                    Console.WriteLine($"📝 Content length: {result.Value.XmlContent.Length:N0} chars");
                    
                    // Check if this is actual decrypted content vs simulated
                    if (result.Value.XmlContent.Contains("🎯 MATCH:"))
                    {
                        breakthroughCount++;
                        Console.WriteLine($"🎉 BREAKTHROUGH: Actual decryption succeeded!");
                        Console.WriteLine($"🔍 Check logs above for the exact algorithm used");
                    }
                    else if (result.Value.XmlContent.Contains("simulated"))
                    {
                        Console.WriteLine($"⚠️  Using simulated content (no breakthrough yet)");
                    }
                    else
                    {
                        Console.WriteLine($"🎯 POTENTIAL BREAKTHROUGH: Content doesn't appear simulated");
                    }
                    
                    if (result.Value.Warnings.Count > 0)
                    {
                        Console.WriteLine($"⚠️  Warnings: {result.Value.Warnings.Count}");
                        foreach (var warning in result.Value.Warnings)
                        {
                            Console.WriteLine($"   - {warning}");
                        }
                    }
                }
                else
                {
                    Console.WriteLine($"❌ FAILED: {fileName}");
                    Console.WriteLine($"💥 Errors: {string.Join(", ", result.Errors)}");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"💥 EXCEPTION: {ex.Message}");
            }
            
            Console.WriteLine();
            Console.WriteLine("-" + new string('-', 50));
            Console.WriteLine();
        }

        // Final summary
        Console.WriteLine("🎯 ROUTINE NAME SALTING TEST SUMMARY");
        Console.WriteLine("=" + new string('=', 50));
        Console.WriteLine($"⏰ Completed: {DateTime.Now}");
        Console.WriteLine($"📊 Success Rate: {successCount}/{testFiles.Length} files");
        Console.WriteLine($"🎉 Breakthrough Count: {breakthroughCount} files");
        Console.WriteLine();

        if (breakthroughCount > 0)
        {
            Console.WriteLine("🎊 🎊 🎊 WE HIT THE LOTTERY! 🎊 🎊 🎊");
            Console.WriteLine($"✅ Routine name-based salting worked for {breakthroughCount} files!");
            Console.WriteLine("🔍 Check the detailed logs above for the exact algorithm used.");
        }
        else if (successCount == testFiles.Length)
        {
            Console.WriteLine("✅ All files processed successfully (using simulated content)");
            Console.WriteLine("⚠️  No breakthrough with routine name salting yet");
            Console.WriteLine("🔍 V9 might use a different approach than routine name salting");
        }
        else
        {
            Console.WriteLine("❌ Some files failed - check logs for details");
        }

        Console.WriteLine();
        Console.WriteLine("📋 Next steps:");
        Console.WriteLine("1. Review detailed logs for any 🎯 MATCH patterns");
        Console.WriteLine("2. Update V9_CRYPTANALYSIS_LOG.md with results");
        Console.WriteLine("3. Analyze any successful salt combinations");
        Console.WriteLine("4. Consider alternative approaches if no breakthrough");
        
        Console.WriteLine();
        Console.WriteLine("🧂 Routine name-based salting test complete!");
    }
}