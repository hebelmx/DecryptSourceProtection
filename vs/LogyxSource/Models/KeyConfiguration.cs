using System.Text.Json.Serialization;

namespace LogyxSource.Models;

public class KeyConfiguration
{
    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("version")]
    public string Version { get; set; } = string.Empty;

    [JsonPropertyName("keys")]
    public List<KeyInfo> Keys { get; set; } = new();

    [JsonPropertyName("candidateKeys")]
    public List<string> CandidateKeys { get; set; } = new();
}

public class KeyInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("description")]
    public string Description { get; set; } = string.Empty;

    [JsonPropertyName("encryptionConfigs")]
    public List<int> EncryptionConfigs { get; set; } = new();
}