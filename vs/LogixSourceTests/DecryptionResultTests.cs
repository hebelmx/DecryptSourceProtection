using LogyxSource.Domain;
using Shouldly;

namespace LogixSourceTests;

public class DecryptionResultTests
{
    [Fact]
    public void DecryptionResult_WithXmlContent_SetsXmlContent()
    {
        var result = new DecryptionResult { XmlContent = "<xml>test</xml>" };
        
        result.XmlContent.ShouldBe("<xml>test</xml>");
        result.Warnings.ShouldBeEmpty();
    }

    [Fact]
    public void DecryptionResult_WithWarnings_SetsWarnings()
    {
        var warnings = new List<string> { "Warning 1", "Warning 2" };
        var result = new DecryptionResult { Warnings = warnings };
        
        result.Warnings.ShouldBe(warnings);
        result.XmlContent.ShouldBe(string.Empty);
    }

    [Fact]
    public void DecryptionResult_WithXmlContentAndWarnings_SetsBoth()
    {
        var warnings = new List<string> { "Warning 1" };
        var result = new DecryptionResult 
        { 
            XmlContent = "<xml>test</xml>", 
            Warnings = warnings 
        };
        
        result.XmlContent.ShouldBe("<xml>test</xml>");
        result.Warnings.ShouldBe(warnings);
    }
}