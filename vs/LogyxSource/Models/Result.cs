namespace LogyxSource.Models;

public class Result<T>
{
    public bool IsSuccess { get; init; }
    public T? Value { get; init; }
    public List<string> Errors { get; init; } = new();

    public static Result<T> Success(T value) => new() { IsSuccess = true, Value = value };
    public static Result<T> Failure(string error) => new() { IsSuccess = false, Errors = new List<string> { error } };
    public static Result<T> Error(Exception ex) => new() { IsSuccess = false, Errors = new List<string> { ex.Message } };
    public static Result<T> Canceled() => new() { IsSuccess = false, Errors = new List<string> { "Operation was canceled." } };
}