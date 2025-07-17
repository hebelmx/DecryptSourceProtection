using LogyxSource.Domain;
using Shouldly;

namespace LogixSourceTests;

public class KeyStoreTests
{
    [Fact]
    public void DefaultConstructor_InitializesWithHardcodedKeys()
    {
        var keyStore = new KeyStore();
        
        var result = keyStore.GetAllKeys();
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldContain("Visual2025");
        result.Value.ShouldContain("Doug'sExportEncryption");
        result.Value.ShouldContain("defaultkey");
        result.Value.ShouldContain("testkey");
    }

    [Fact]
    public void Constructor_WithCustomKeys_AddsCustomKeys()
    {
        var customKeys = new[] { "customkey1", "customkey2" };
        var keyStore = new KeyStore(customKeys);
        
        var result = keyStore.GetAllKeys();
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldContain("customkey1");
        result.Value.ShouldContain("customkey2");
        result.Value.ShouldContain("Visual2025");
    }

    [Fact]
    public void GetKeysForConfig_WithUnknownConfig_ReturnsAllKeys()
    {
        var keyStore = new KeyStore();
        
        var result = keyStore.GetKeysForConfig(999);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldContain("Visual2025");
    }

    [Fact]
    public void Constructor_WithNonExistentFile_OnlyHasHardcodedKeys()
    {
        var keyStore = new KeyStore("/nonexistent/file.dat");
        
        var result = keyStore.GetAllKeys();
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldContain("Visual2025");
        result.Value.Count.ShouldBe(4);
    }
}