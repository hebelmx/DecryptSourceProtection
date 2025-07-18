using LogyxSource.Domain;
using Microsoft.Extensions.Logging;
using Shouldly;
using Xunit.Abstractions;

namespace LogixSourceTests;

public class V9DebugTest
{
    private readonly ITestOutputHelper _output;
    private readonly ILogger<L5XDecryptor> _logger;
    private readonly L5XDecryptor _decryptor;
    private readonly string _fixturesPath;

    public V9DebugTest(ITestOutputHelper output)
    {
        _output = output;
        _logger = new TestLogger<L5XDecryptor>(_output);
        
        var keyStore = new KeyStore();
        _decryptor = new L5XDecryptor(keyStore, _logger);
        _fixturesPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Fixtures");
    }

    [Fact]
    public async Task DebugV9Failure_S005_STP1Advance()
    {
        // Test the failing file to see exact failure point
        var filePath = Path.Combine(_fixturesPath, "Know Fixture V33", "S005_STP1Advance.L5X");
        
        _output.WriteLine($"Testing file: {filePath}");
        _output.WriteLine($"File exists: {File.Exists(filePath)}");
        
        if (File.Exists(filePath))
        {
            var content = await File.ReadAllTextAsync(filePath);
            _output.WriteLine($"File size: {content.Length} characters");
            _output.WriteLine($"Contains EncryptionConfig=\"9\": {content.Contains("EncryptionConfig=\"9\"")}");
        }
        
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        _output.WriteLine($"Result.IsSuccess: {result.IsSuccess}");
        if (!result.IsSuccess)
        {
            _output.WriteLine($"Errors: {string.Join(", ", result.Errors)}");
        }
        else
        {
            _output.WriteLine($"Success! Content length: {result.Value.XmlContent.Length}");
        }
    }

    [Fact]
    public async Task DebugV9Success_S025_SkidIndexInVDL()
    {
        // Test the working file to see success pattern
        var filePath = Path.Combine(_fixturesPath, "Know Fixture V33", "S025_SkidIndexInVDL.L5X");
        
        _output.WriteLine($"Testing file: {filePath}");
        _output.WriteLine($"File exists: {File.Exists(filePath)}");
        
        if (File.Exists(filePath))
        {
            var content = await File.ReadAllTextAsync(filePath);
            _output.WriteLine($"File size: {content.Length} characters");
            _output.WriteLine($"Contains EncryptionConfig=\"9\": {content.Contains("EncryptionConfig=\"9\"")}");
        }
        
        var result = await _decryptor.DecryptFromFileAsync(filePath);
        
        _output.WriteLine($"Result.IsSuccess: {result.IsSuccess}");
        if (!result.IsSuccess)
        {
            _output.WriteLine($"Errors: {string.Join(", ", result.Errors)}");
        }
        else
        {
            _output.WriteLine($"Success! Content length: {result.Value.XmlContent.Length}");
        }
    }
}

public class TestLogger<T> : ILogger<T>
{
    private readonly ITestOutputHelper _output;

    public TestLogger(ITestOutputHelper output)
    {
        _output = output;
    }

    public IDisposable BeginScope<TState>(TState state) => null!;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        _output.WriteLine($"[{logLevel}] {formatter(state, exception)}");
        if (exception != null)
        {
            _output.WriteLine($"Exception: {exception}");
        }
    }
}