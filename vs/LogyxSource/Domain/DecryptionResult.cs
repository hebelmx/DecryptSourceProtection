namespace LogyxSource.Domain;

public record DecryptionResult
{
    public string XmlContent { get; init; } = string.Empty;
    public IReadOnlyList<string> Warnings { get; init; } = new List<string>();
}