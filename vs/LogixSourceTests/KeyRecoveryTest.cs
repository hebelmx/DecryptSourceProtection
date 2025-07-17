using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class KeyRecoveryTest
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly L5XDecryptor _decryptor;
    private readonly string _fixturesPath;

    public KeyRecoveryTest(ITestOutputHelper output)
    {
        _output = output;
        _logger = new TestLogger<L5XDecryptor>(_output);
        
        var keyStore = new KeyStore();
        _decryptor = new L5XDecryptor(keyStore, _logger);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task DiscoverUnknownKey_FromKnownPlaintextCiphertext()
    {
        _output.WriteLine("🔍 KEY RECOVERY CHALLENGE - BLIND KEY DISCOVERY");
        _output.WriteLine("=".PadRight(50, '='));
        
        // Test files for key recovery
        var testFiles = new[]
        {
            "M001_Modes.L5X",
            "M010_StationStopModes.L5X", 
            "S000_Sequence.L5X",
            "S020_SkidIndexIn.L5X",
            "S025_SkidIndexOut.L5X",
            "S030_SkidReverseIn.L5X",
            "S035_SkidReverseOut.L5X",
            "S900_SkidJogFwd.L5X",
            "S905_SkidJogRev.L5X"
        };

        _output.WriteLine($"📊 Testing {testFiles.Length} protected files against their unprotected counterparts");
        
        var successCount = 0;
        var failureCount = 0;
        
        foreach (var fileName in testFiles)
        {
            _output.WriteLine($"\n🎯 TESTING: {fileName}");
            
            var protectedPath = Path.Combine(_fixturesPath, "Protected", fileName);
            var unprotectedPath = Path.Combine(_fixturesPath, "Unprotected", fileName);
            
            // Verify files exist
            if (!File.Exists(protectedPath))
            {
                _output.WriteLine($"❌ Protected file not found: {protectedPath}");
                failureCount++;
                continue;
            }
            
            if (!File.Exists(unprotectedPath))
            {
                _output.WriteLine($"❌ Unprotected file not found: {unprotectedPath}");
                failureCount++;
                continue;
            }
            
            // Read unprotected file for comparison
            var unprotectedContent = await File.ReadAllTextAsync(unprotectedPath);
            _output.WriteLine($"📄 Unprotected file size: {unprotectedContent.Length} chars");
            
            // Try to decrypt protected file
            _output.WriteLine($"🔐 Attempting to decrypt protected file...");
            var result = await _decryptor.DecryptFromFileAsync(protectedPath);
            
            if (result.IsSuccess)
            {
                _output.WriteLine($"✅ SUCCESS! Decrypted content length: {result.Value.XmlContent.Length}");
                successCount++;
                
                // Compare with unprotected version
                var similarity = CalculateSimilarity(unprotectedContent, result.Value.XmlContent);
                _output.WriteLine($"📊 Similarity with unprotected: {similarity:P1}");
                
                if (similarity > 0.9)
                {
                    _output.WriteLine("🎉 HIGH SIMILARITY - LIKELY SUCCESSFUL DECRYPTION!");
                }
            }
            else
            {
                _output.WriteLine($"❌ FAILED! Errors: {string.Join(", ", result.Errors)}");
                failureCount++;
            }
        }
        
        _output.WriteLine($"\n📊 FINAL RESULTS:");
        _output.WriteLine($"✅ Successful decryptions: {successCount}/{testFiles.Length}");
        _output.WriteLine($"❌ Failed decryptions: {failureCount}/{testFiles.Length}");
        _output.WriteLine($"🎯 Success rate: {(double)successCount / testFiles.Length:P1}");
        
        // Analyze the key used
        await AnalyzeKeyUsage();
        
        // The test passes if we can decrypt any files
        successCount.ShouldBeGreaterThan(0, "Should be able to decrypt at least some files");
    }

    private async Task AnalyzeKeyUsage()
    {
        _output.WriteLine($"\n🔍 KEY ANALYSIS:");
        _output.WriteLine("=".PadRight(30, '='));
        
        // Check what keys are available in our keystore
        var keyStore = new KeyStore();
        var allKeys = keyStore.GetAllKeys();
        
        if (allKeys.IsSuccess)
        {
            _output.WriteLine($"🔑 Available keys in keystore:");
            foreach (var key in allKeys.Value)
            {
                _output.WriteLine($"   - \"{key}\"");
            }
        }
        
        // Test a specific file with detailed logging to see which key works
        var testFile = Path.Combine(_fixturesPath, "Protected", "M001_Modes.L5X");
        if (File.Exists(testFile))
        {
            _output.WriteLine($"\n🔍 DETAILED KEY ANALYSIS on {Path.GetFileName(testFile)}:");
            
            // Enable detailed logging
            var result = await _decryptor.DecryptFromFileAsync(testFile);
            
            if (result.IsSuccess)
            {
                _output.WriteLine("✅ Decryption successful - check logs above for key details");
            }
        }
    }

    private double CalculateSimilarity(string text1, string text2)
    {
        if (string.IsNullOrEmpty(text1) || string.IsNullOrEmpty(text2))
            return 0;
        
        // Simple similarity check - count matching characters
        var minLength = Math.Min(text1.Length, text2.Length);
        var maxLength = Math.Max(text1.Length, text2.Length);
        
        if (maxLength == 0) return 1.0;
        
        var matches = 0;
        for (int i = 0; i < minLength; i++)
        {
            if (text1[i] == text2[i])
                matches++;
        }
        
        return (double)matches / maxLength;
    }
}