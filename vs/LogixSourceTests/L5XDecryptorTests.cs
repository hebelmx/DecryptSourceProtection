using LogyxSource.Domain;
using Shouldly;

namespace LogixSourceTests;

public class L5XDecryptorTests
{
    private readonly L5XDecryptor _decryptor = new();

    [Fact]
    public async Task DecryptFromStringAsync_WithNullContent_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromStringAsync(null!);
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("L5X content cannot be null or empty");
    }

    [Fact]
    public async Task DecryptFromStringAsync_WithEmptyContent_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromStringAsync("");
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("L5X content cannot be null or empty");
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task DecryptFromStringAsync_WithSupportedConfig_ReturnsSuccess(int encryptionConfig)
    {
        var l5xContent = CreateL5XContentWithConfig(encryptionConfig);
        
        var result = await _decryptor.DecryptFromStringAsync(l5xContent);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public async Task DecryptFromStringAsync_WithConfig8_ReturnsSuccessWithWarning()
    {
        var l5xContent = CreateL5XContentWithConfig(8);
        
        var result = await _decryptor.DecryptFromStringAsync(l5xContent);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.Warnings.ShouldContain("Source key recovery is not supported for EncryptionConfig=\"8\"");
    }

    [Fact]
    public async Task DecryptFromStringAsync_WithConfig9_ReturnsFailure()
    {
        var l5xContent = CreateL5XContentWithConfig(9);
        
        var result = await _decryptor.DecryptFromStringAsync(l5xContent);
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("Error: An unsupported EncryptionConfig value was found. (9) Decryption of this file is not yet supported.");
    }

    [Fact]
    public async Task DecryptFromStringAsync_WithNoEncryptionConfig_ReturnsSuccess()
    {
        var l5xContent = CreateL5XContentWithoutConfig();
        
        var result = await _decryptor.DecryptFromStringAsync(l5xContent);
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public async Task DecryptFromStringAsync_WithInvalidXml_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromStringAsync("invalid xml");
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldNotBeEmpty();
    }

    [Fact]
    public async Task DecryptFromFileAsync_WithNullPath_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromFileAsync(null!);
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("File path cannot be null or empty");
    }

    [Fact]
    public async Task DecryptFromFileAsync_WithEmptyPath_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromFileAsync("");
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("File path cannot be null or empty");
    }

    [Fact]
    public async Task DecryptFromFileAsync_WithNonExistentFile_ReturnsFailure()
    {
        var result = await _decryptor.DecryptFromFileAsync("/nonexistent/file.l5x");
        
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain("File not found: /nonexistent/file.l5x");
    }

    private static string CreateL5XContentWithConfig(int encryptionConfig)
    {
        return $@"<?xml version=""1.0"" encoding=""UTF-8""?>
<RSLogix5000Content>
    <Controller>
        <Programs>
            <Program>
                <Routines>
                    <EncodedData EncryptionConfig=""{encryptionConfig}"">
                        Base64EncodedData
                    </EncodedData>
                </Routines>
            </Program>
        </Programs>
    </Controller>
</RSLogix5000Content>";
    }

    private static string CreateL5XContentWithoutConfig()
    {
        return @"<?xml version=""1.0"" encoding=""UTF-8""?>
<RSLogix5000Content>
    <Controller>
        <Programs>
            <Program>
                <Routines>
                    <EncodedData>
                        Base64EncodedData
                    </EncodedData>
                </Routines>
            </Program>
        </Programs>
    </Controller>
</RSLogix5000Content>";
    }
}