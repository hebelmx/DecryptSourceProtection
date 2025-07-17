using LogyxSource.Models;

namespace LogyxSource.Domain;

public class KeyStore
{
    private readonly Dictionary<int, List<string>> _keysByConfig = new();
    private readonly List<string> _allKeys = new();

    public KeyStore()
    {
        InitializeHardcodedKeys();
    }

    public KeyStore(string skDatFilePath)
    {
        InitializeHardcodedKeys();
        LoadKeysFromFile(skDatFilePath);
    }

    public KeyStore(IEnumerable<string> keys)
    {
        InitializeHardcodedKeys();
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

    private void InitializeHardcodedKeys()
    {
        _allKeys.AddRange(new[]
        {
            "Visual2025",
            "Doug'sExportEncryption",
            "defaultkey",
            "testkey"
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