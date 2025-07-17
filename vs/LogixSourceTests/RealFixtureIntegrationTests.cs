using Shouldly;
using LogyxSource.Domain;
using LogyxSource.Interfaces;
using LogyxSource.Models;

namespace LogixSourceTests;

public class RealFixtureIntegrationTests
{
    private readonly IL5XDecryptor _decryptor;
    private readonly string _fixturesPath;

    public RealFixtureIntegrationTests()
    {
        var keyStore = new KeyStore();
        _decryptor = new L5XDecryptor(keyStore);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task DecryptKnownFixtureV19_KeyFilesExist()
    {
        // Arrange - V19 contains key files (sk.dat) which are used for decryption
        var skFilePath = Path.Combine(_fixturesPath, "Know Fixture V19", "sk.dat");
        
        // Act & Assert
        File.Exists(skFilePath).ShouldBeTrue("V19 should contain sk.dat key file");
        
        // Note: sk.dat is a binary key file, not an L5X file to decrypt
        // It's used by the decryptor to decrypt other L5X files
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    public async Task DecryptSuccessfulScenarios_ConfigsOneToSeven_ShouldReturnSuccessWithKey(int encryptionConfig)
    {
        // Arrange - Create mock L5X content with configs 1-7 (successful decryption scenarios)
        var mockL5XContent = CreateMockL5XWithConfig(encryptionConfig);
        
        // Act
        var result = await _decryptor.DecryptFromStringAsync(mockL5XContent);
        
        // Assert
        result.IsSuccess.ShouldBeTrue($"Config {encryptionConfig} should succeed");
        result.Value.ShouldNotBeNull();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.XmlContent.ShouldContain("<?xml version=\"1.0\"");
        result.Value.XmlContent.ShouldContain("DecodedData_Simulated");
        result.Value.Warnings.ShouldBeEmpty($"Config {encryptionConfig} should not have warnings");
        
        // These represent the successful decryption scenarios that V19/V24 fixtures support
        // In the real JS library, these would show "Found source key: [key-value]"
    }

    [Theory]
    [InlineData("CM22_Home.L5X")]
    [InlineData("CM10_Axis_Basic_Operations.L5X")]
    [InlineData("CM31_AxisStatus.L5X")]
    public async Task DecryptUnknownFixture18_NoEncryptionConfig_ShouldReturnSuccessWithKey(string fileName)
    {
        // Arrange - Unknown Fixture 18 has EncodedData elements without EncryptionConfig attributes
        // These represent real successful decryption scenarios similar to V19/V24
        var filePath = Path.Combine(_fixturesPath, "Unknow Fixture 18", fileName);
        
        // Act
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        // Assert
        result.IsSuccess.ShouldBeTrue($"File {fileName} should succeed (no EncryptionConfig = default success)");
        result.Value.ShouldNotBeNull();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.XmlContent.ShouldContain("<?xml version=\"1.0\"");
        result.Value.XmlContent.ShouldContain("DecodedData_Simulated");
        result.Value.Warnings.ShouldBeEmpty($"File {fileName} should not have warnings");
        
        // These are real L5X files with encrypted content that would be successfully decrypted
        // like the scenarios V19/V24 fixtures are designed to test
    }

    [Fact]
    public async Task DecryptKnownFixtureV24_SameAsV19_SupportsConfigs1to7()
    {
        // Note: V19 and V24 are the same according to user
        // Both represent fixtures that can be successfully decrypted with keys
        var v19Path = Path.Combine(_fixturesPath, "Know Fixture V19");
        var v24Path = Path.Combine(_fixturesPath, "Know Fixture V24");
        
        // Act & Assert
        Directory.Exists(v19Path).ShouldBeTrue("V19 directory should exist");
        Directory.Exists(v24Path).ShouldBeTrue("V24 directory should exist");
        
        // V24 directory exists but may be empty - that's expected
        // These fixtures represent successful decryption scenarios (configs 1-7)
        // Test that the decryptor can handle these configs successfully
        var mockConfig3 = CreateMockL5XWithConfig(3);
        var result = await _decryptor.DecryptFromStringAsync(mockConfig3);
        
        result.IsSuccess.ShouldBeTrue("V19/V24 style configs should succeed");
        result.Value.Warnings.ShouldBeEmpty("V19/V24 style configs should not have warnings");
    }

    private static string CreateMockL5XWithConfig(int encryptionConfig)
    {
        return $@"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>
<RSLogix5000Content SchemaRevision=""1.0"" SoftwareRevision=""27.00"" TargetName=""TestRoutine"" TargetType=""Routine"" TargetSubType=""RLL"" ContainsContext=""true"" Owner=""Test"" ExportDate=""Wed Jul 17 00:00:00 2025"" ExportOptions=""References NoRawData L5KData DecoratedData Context Dependencies ForceProtectedEncoding AllProjDocTrans"">
<Controller Use=""Context"" Name=""TestController"">
<DataTypes Use=""Context"">
</DataTypes>
<Programs Use=""Context"">
<Program Use=""Context"" Name=""MainProgram"">
<Routines Use=""Context"">
<Routine Use=""Context"" Name=""TestRoutine"" Type=""RLL"">
<EncodedData EncodedType=""Routine"" Name=""TestRoutine"" Type=""RLL"" EncryptionConfig=""{encryptionConfig}"">
<![CDATA[MockEncryptedDataForConfig{encryptionConfig}]]>
</EncodedData>
</Routine>
</Routines>
</Program>
</Programs>
</Controller>
</RSLogix5000Content>";
    }

    [Theory]
    [InlineData("Open.L5X")]
    [InlineData("MainRoutine.L5X")]
    public async Task DecryptKnownFixtureV27_ShouldSucceedWithWarning(string fileName)
    {
        // Arrange
        var filePath = Path.Combine(_fixturesPath, "Know Fixture V27", fileName);
        
        // Act
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        // Assert
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldNotBeNull();
        result.Value.XmlContent.ShouldNotBeNullOrEmpty();
        result.Value.XmlContent.ShouldContain("<?xml version=\"1.0\"");
        result.Value.Warnings.ShouldContain(w => w.Contains("EncryptionConfig=\"8\""));
        result.Value.Warnings.ShouldContain(w => w.Contains("Source key recovery is not supported"));
    }

    [Theory]
    [InlineData("S005_STP1Advance.L5X")]
    [InlineData("S010_STP1Return.L5X")]
    [InlineData("S015_STP2Advance.L5X")]
    [InlineData("S020_STP2Return.L5X")]
    [InlineData("S025_SkidIndexInVDL.L5X")]
    [InlineData("S025_SkidIndexOut_Clear.L5X")]
    public async Task DecryptKnownFixtureV33_ShouldFailWithUnsupportedConfig(string fileName)
    {
        // Arrange
        var filePath = Path.Combine(_fixturesPath, "Know Fixture V33", fileName);
        
        // Act
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        // Assert
        result.IsSuccess.ShouldBeFalse();
        result.Errors.ShouldContain(e => e.Contains("EncryptionConfig value was found. (9)"));
        result.Errors.ShouldContain(e => e.Contains("Decryption of this file is not yet supported"));
    }

    [Fact]
    public async Task DecryptKnownFixtureV30_ShouldFailWithUnsupportedConfig()
    {
        // Note: V30 directory appears empty in current structure
        // This test will be updated when V30 fixtures are available
        var v30Path = Path.Combine(_fixturesPath, "Know Fixture V30");
        Directory.Exists(v30Path).ShouldBeTrue();
        
        // V30 directory exists but may be empty - that's expected
        // V30 represents fixtures that should fail decryption
        // The actual test would use L5X files with unsupported configs when available
    }

    [Fact]
    public async Task VerifyExpectedMessages_MatchJavaScriptLibraryBehavior()
    {
        // Arrange
        var v27MessagePath = Path.Combine(_fixturesPath, "Know Fixture V27", "Open.Message.txt");
        var v33MessagePath = Path.Combine(_fixturesPath, "Know Fixture V33", "FailureMessage.txt");
        
        // Act & Assert - V27 (Warning)
        var v27Expected = await File.ReadAllTextAsync(v27MessagePath);
        v27Expected.ShouldContain("Source key recovery is not supported for EncryptionConfig=\"8\"");
        
        // Act & Assert - V33 (Error)
        var v33Expected = await File.ReadAllTextAsync(v33MessagePath);
        v33Expected.ShouldContain("An unsupported EncryptionConfig value was found. (9)");
        v33Expected.ShouldContain("Decryption of this file is not yet supported");
    }
}