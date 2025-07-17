using LogyxSource.Models;
using System.Text.Json;

namespace LogyxSource.Domain;

public class KeyStore
{
    private readonly Dictionary<int, List<string>> _keysByConfig = new();
    private readonly List<string> _allKeys = new();
    private readonly List<string> _candidateKeys = new();

    public KeyStore()
    {
        InitializeFromJsonFile();
    }

    public KeyStore(string skDatFilePath)
    {
        InitializeFromJsonFile();
        LoadKeysFromFile(skDatFilePath);
    }

    public KeyStore(IEnumerable<string> keys)
    {
        InitializeFromJsonFile();
        foreach (var key in keys)
        {
            _allKeys.Add(key);
        }
    }

    public Result<IReadOnlyList<string>> GetKeysForConfig(int encryptionConfig)
    {
        if (_keysByConfig.TryGetValue(encryptionConfig, out var keys))
        {
            return Result<IReadOnlyList<string>>.Success(keys.AsReadOnly());
        }

        return Result<IReadOnlyList<string>>.Success(_allKeys.AsReadOnly());
    }

    public Result<IReadOnlyList<string>> GetAllKeys()
    {
        return Result<IReadOnlyList<string>>.Success(_allKeys.AsReadOnly());
    }

    public Result<IReadOnlyList<string>> GetCandidateKeys()
    {
        return Result<IReadOnlyList<string>>.Success(_candidateKeys.AsReadOnly());
    }

    private void InitializeFromJsonFile()
    {
        try
        {
            var jsonPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "keys.json");
            if (!File.Exists(jsonPath))
            {
                // Fallback to hardcoded keys if JSON file doesn't exist
                InitializeHardcodedKeys();
                return;
            }

            var jsonContent = File.ReadAllText(jsonPath);
            var keyConfig = JsonSerializer.Deserialize<KeyConfiguration>(jsonContent);
            
            if (keyConfig?.Keys != null)
            {
                foreach (var keyInfo in keyConfig.Keys)
                {
                    _allKeys.Add(keyInfo.Name);
                    
                    // Associate key with specific encryption configs
                    if (keyInfo.EncryptionConfigs != null)
                    {
                        foreach (var config in keyInfo.EncryptionConfigs)
                        {
                            if (!_keysByConfig.ContainsKey(config))
                            {
                                _keysByConfig[config] = new List<string>();
                            }
                            _keysByConfig[config].Add(keyInfo.Name);
                        }
                    }
                }
            }

            if (keyConfig?.CandidateKeys != null)
            {
                _candidateKeys.AddRange(keyConfig.CandidateKeys);
            }
        }
        catch (Exception)
        {
            // Fallback to hardcoded keys if JSON parsing fails
            InitializeHardcodedKeys();
        }
    }

    private void InitializeHardcodedKeys()
    {
        _allKeys.AddRange(new[]
        {
            "Visual2025",
            "Doug'sExportEncryption",
            "defaultkey",
            "testkey",
            "Stana7"
        });
    }

    private void LoadKeysFromFile(string filePath)
    {
        try
        {
            if (!File.Exists(filePath))
            {
                return;
            }

            // Handle both binary and text sk.dat files
            var content = File.ReadAllText(filePath, System.Text.Encoding.UTF8);
            var lines = content.Split('\n');
            
            foreach (var line in lines)
            {
                var trimmed = line.Trim().Trim('\r', '\n', '\t');
                if (!string.IsNullOrEmpty(trimmed) && 
                    !trimmed.StartsWith("<") && 
                    !trimmed.StartsWith("RSLOGIX") &&
                    !trimmed.StartsWith("﻿"))
                {
                    _allKeys.Add(trimmed);
                }
            }
        }
        catch
        {
            // Silently ignore file loading errors
        }
    }
}