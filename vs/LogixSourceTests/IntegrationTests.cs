using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;

namespace LogixSourceTests;

public class IntegrationTests : IDisposable
{
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly L5XDecryptor _decryptor;
    private readonly string _fixturesPath;

    public IntegrationTests()
    {
        _logger = Microsoft.Extensions.Logging.Abstractions.NullLogger<L5XDecryptor>.Instance;
        _decryptor = new L5XDecryptor();
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task DecryptRealFixture_OpenL5X_WithConfig8_ReturnsSuccessWithWarning()
    {
        var filePath = Path.Combine(_fixturesPath, "Open.L5X");
        
        if (!File.Exists(filePath))
        {
            Assert.True(false, $"Fixture file not found: {filePath}");
        }

        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.Warnings.ShouldContain(w => w.Contains("EncryptionConfig=\"8\""));
    }

    [Fact]
    public async Task KeyStore_LoadsFromSkDat_ContainsExpectedKeys()
    {
        var skDatPath = Path.Combine(_fixturesPath, "sk.dat");
        
        if (!File.Exists(skDatPath))
        {
            Assert.True(false, $"sk.dat file not found: {skDatPath}");
        }

        var keyStore = new KeyStore(skDatPath);
        var keysResult = keyStore.GetAllKeys();
        
        keysResult.IsSuccess.ShouldBeTrue();
        keysResult.Value.ShouldContain("Visual2025");
        keysResult.Value.ShouldContain("Doug'sExportEncryption");
    }

    [Fact]
    public async Task DecryptorWithCustomKeyStore_ProcessesCorrectly()
    {
        var skDatPath = Path.Combine(_fixturesPath, "sk.dat");
        var keyStore = new KeyStore(skDatPath);
        var decryptor = new L5XDecryptor(keyStore);

        var filePath = Path.Combine(_fixturesPath, "Open.L5X");
        
        if (!File.Exists(filePath))
        {
            Assert.True(false, $"Fixture file not found: {filePath}");
        }

        var result = await decryptor.DecryptFromFileAsync(filePath);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.Warnings.ShouldContain(w => w.Contains("Source key recovery is not supported"));
    }

    [Fact]
    public async Task DecryptFromString_WithRealFixtureContent_ProcessesCorrectly()
    {
        var filePath = Path.Combine(_fixturesPath, "Open.L5X");
        
        if (!File.Exists(filePath))
        {
            Assert.True(false, $"Fixture file not found: {filePath}");
        }

        var content = await File.ReadAllTextAsync(filePath);
        var result = await _decryptor.DecryptFromStringAsync(content);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.XmlContent.ShouldContain("<RLLContent>");
        result.Value.Warnings.ShouldNotBeEmpty();
    }

    public void Dispose()
    {
        // Nothing to dispose for NullLogger
    }
}