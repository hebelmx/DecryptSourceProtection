using LogyxSource.Domain;
using LogyxSource.Models;

namespace LogyxSource.Interfaces;

public interface IL5XDecryptor
{
    Task<Result<DecryptionResult>> DecryptFromStringAsync(string l5xContent);
    Task<Result<DecryptionResult>> DecryptFromFileAsync(string filePath);
}