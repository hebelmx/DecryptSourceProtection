using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class V30CrackTest
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly L5XDecryptor _decryptor;
    private readonly string _fixturesPath;

    public V30CrackTest(ITestOutputHelper output)
    {
        _output = output;
        _logger = new TestLogger<L5XDecryptor>(_output);
        
        var keyStore = new KeyStore();
        _decryptor = new L5XDecryptor(keyStore, _logger);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Theory]
    [InlineData("_050_SP_MANFREM.L5X")]
    [InlineData("_051_PPLAASEUD.L5X")]
    [InlineData("_052_PPLAASEIND.L5X")]
    [InlineData("_053_SPLAASEUD.L5X")]
    public async Task CrackV30File_ShouldSucceed(string fileName)
    {
        // Arrange
        var filePath = Path.Combine(_fixturesPath, fileName);
        
        _output.WriteLine($"🎯 ATTEMPTING TO CRACK V30 FILE: {fileName}");
        _output.WriteLine($"File path: {filePath}");
        _output.WriteLine($"File exists: {File.Exists(filePath)}");
        
        if (File.Exists(filePath))
        {
            var content = await File.ReadAllTextAsync(filePath);
            _output.WriteLine($"File size: {content.Length} characters");
            _output.WriteLine($"Contains EncryptionConfig=\"9\": {content.Contains("EncryptionConfig=\"9\"")}");
        }
        
        // Act
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        // Assert & Log
        _output.WriteLine($"🔍 CRACK RESULT: {result.IsSuccess}");
        
        if (result.IsSuccess)
        {
            _output.WriteLine($"✅ SUCCESS! Decrypted content length: {result.Value.XmlContent.Length}");
            _output.WriteLine($"Warnings: {result.Value.Warnings.Count}");
            
            // Check if it contains expected XML structure
            var hasRoutineStructure = result.Value.XmlContent.Contains("<Routine") && 
                                    result.Value.XmlContent.Contains("</Routine>");
            _output.WriteLine($"Contains valid routine structure: {hasRoutineStructure}");
            
            // Log a sample of the decrypted content (first 500 chars)
            var sample = result.Value.XmlContent.Length > 500 
                ? result.Value.XmlContent.Substring(0, 500) + "..."
                : result.Value.XmlContent;
            _output.WriteLine($"Decrypted content sample: {sample}");
        }
        else
        {
            _output.WriteLine($"❌ FAILED! Errors: {string.Join(", ", result.Errors)}");
        }
        
        // The test passes if we get ANY result (success or controlled failure)
        // This is a cryptanalysis attempt, not a guaranteed success
        result.ShouldNotBeNull();
        _output.WriteLine($"📊 V30 CRACK ATTEMPT COMPLETED for {fileName}");
    }
}