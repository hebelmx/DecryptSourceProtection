using LogyxSource.Models;
using Shouldly;

namespace LogixSourceTests;

public class ResultTests
{
    [Fact]
    public void Success_WithValue_ReturnsSuccessResult()
    {
        var result = Result<string>.Success("test");
        
        result.IsSuccess.ShouldBeTrue();
        result.Value.ShouldBe("test");
        result.Errors.ShouldBeEmpty();
    }

    [Fact]
    public void Failure_WithError_ReturnsFailureResult()
    {
        var result = Result<string>.Failure("test error");
        
        result.IsSuccess.ShouldBeFalse();
        result.Value.ShouldBeNull();
        result.Errors.ShouldContain("test error");
    }

    [Fact]
    public void Error_WithException_ReturnsErrorResult()
    {
        var exception = new InvalidOperationException("test exception");
        var result = Result<string>.Error(exception);
        
        result.IsSuccess.ShouldBeFalse();
        result.Value.ShouldBeNull();
        result.Errors.ShouldContain("test exception");
    }

    [Fact]
    public void Canceled_ReturnsCanceledResult()
    {
        var result = Result<string>.Canceled();
        
        result.IsSuccess.ShouldBeFalse();
        result.Value.ShouldBeNull();
        result.Errors.ShouldContain("Operation was canceled.");
    }
}