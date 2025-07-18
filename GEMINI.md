# LogixSource

## 🔧 Overview
A strongly typed, testable, and extensible C# library for decrypting RSLogix 5000 `.L5X` files. This is the first stage of a two-phase system, focusing purely on domain decryption logic without a UI. Designed for Blazor WebAssembly and .NET applications, supporting modern practices like functional result handling, structured logging, and unit test coverage.

Is a browser-based  tool designed to decrypt RSLogix 5000 .L5X files that have source protection applied. It uses cryptographic algorithms like AES, RC4, SHA1, and SHA256 (through libraries such as aes.js, rc4.js, sha1.js, sha256.js, and enc-utf16-min.js) to analyze and transform the file's content.

Goal of the Project
The main goal is to remove or bypass the source protection from .L5X files by analyzing and decrypting them in the browser. This is typically done through:
Drag-and-drop interface via decrypt.html

The ouuput are the XML decrypted files, which can be used for further analysis or modification.
And Optionally a message with the key used for decryption. or a warning if the key is not supported.

Processing and decryption entirely client-side using CSharp libraries.

The first objective is to create a C# library that replicates the decryption logic of the original JavaScript tool, allowing for integration into .NET applications. The second phase will involve creating a Blazor UI for user interaction, enabling drag-and-drop functionality similar to the original browser-based tool.
A porting on C# of the original JavaScript decryption tool, this library provides a structured and maintainable approach to decrypting `.L5X` files. It is designed to be used in Blazor applications, supporting both WebAssembly and server-side models.

This library is a faithful and maintainable port of a JavaScript-based decryption tool originally composed of:
- `decrypt.html` and browser-based UI
- `aes.js`, `rc4.js`, `sha1.js`, `sha256.js`, `enc-utf16-min.js` for encryption/decryption
- `sk.dat` for embedded source keys

The original tool allowed drag-and-drop `.L5X` decryption directly in the browser. The C# version replicates all key features with additional structure and integration capabilities.

---
## 📋 Agent Execution Instructions (Imperative Tasks)
These steps describe the exact order and responsibility for an automation agent or junior developer.

### Step 0: Project Setup

## 🧭 Assessment & Planning
> "Measure twice, code once."
1. Analyze all provided `.L5X` input and output samples.
2. Understand JavaScript logic and expected transformation behavior.
3. Map encryption configurations to expected results.
4. Define unit test cases from message expectations and fixture outputs.

---

### Step 1: Project Setup
1. Create a or work on the exisintg solution and class library project named `LogixSource` 
2. Create a test project `LogixSourceTest`.
3. Install necessary NuGet packages:
   - `xunit`, `xunit.runner.visualstudio`
   - `Shouldly`
   - `Meziantou.Extensions.Logging.Xunit`
   - (optional) `FluentResults` if not using a custom `Result<T>`

### Step 2: Implement Base Models
1. Create document, augment, test , `Result<T>` class in `Models/`.
2. Create document, augment, test , `DecryptionResult` in `Domain/`.
3. Create document, augment, test  interface `IL5XDecryptor` in `Interfaces/`.

### Step 3: Domain Logic Stub
1. Implement,document, augment, test  a stub `L5XDecryptor` that reads XML.
2. Parse `EncryptionConfig` and handle conditions:
   - If 1–7, simulate decrypt and return `Success` with message.
   - If 8, simulate warning and return `Success` with warning.
   - If 9 or unknown, return `Failure`.

### Step 4: File Handling Support
1. Add methods to handle `.L5X` string and path inputs.
2. Use `File.ReadAllTextAsync` for path input.

### Step 5: Key Handling
1. Implement `KeyStore` class with mock list or `sk.dat` parsing.
2. Provide access to keys by config ID.

### Step 6: Logging and Functional Safety
1. Implement logging hooks using `ILogger<>` (future-proof).
2. Ensure no exceptions thrown; use result status exclusively.

### Step 7: Tests Setup
1. There are distinc folders with exisintig fixtures,  all sample `.L5X`, `.Output`, `.Message.txt` used this for development and for testing.
2. Write parameterized unit tests in `L5XDecryptorTests.cs`.
3. Validate:
   - Decryption success with correct key
   - Success with warning on config=8
   - Failure on unsupported config=9
### Step 7: Tests Setup


## 📁 Project Structure
- L5XDecryptionLib/
  - Domain/
    - DecryptionResult.cs
    - L5XDecryptor.cs
    - KeyStore.cs
    - MessageCatalog.cs
  - Services/
    - CryptoService.cs
  - Extensions/
    - ResultExtensions.cs
  - Models/
    - Result<T>.cs (FluentResults or custom)
  - Interfaces/
    - IL5XDecryptor.cs

- L5XDecryptionLib.Tests/
  - Fixtures/
  - L5XDecryptorTests.cs
```

Each component is modular and serves a single responsibility. This modularity supports future enhancements and easier testing.

---

## ⚙️ Core Interfaces

### IL5XDecryptor
Interface defining the contract for L5X decryption operations.
```csharp
public interface IL5XDecryptor
{
    Task<Result<DecryptionResult>> DecryptFromStringAsync(string l5xContent);
    Task<Result<DecryptionResult>> DecryptFromFileAsync(string filePath);
}
```

### DecryptionResult
A strongly-typed output model representing the decrypted content and any associated warnings.
```csharp
public record DecryptionResult
{
    public string XmlContent { get; init; }
    public IReadOnlyList<string> Warnings { get; init; } = new List<string>();
}
```

### Result<T>
This library leverages a result-wrapping pattern (inspired by FluentResults) to ensure robust error handling:
```csharp
public class Result<T>
{
    public bool IsSuccess { get; init; }
    public T Value { get; init; }
    public List<string> Errors { get; init; } = new();

    public static Result<T> Success(T value) => new() { IsSuccess = true, Value = value };
    public static Result<T> Failure(string error) => new() { IsSuccess = false, Errors = new List<string> { error } };
    public static Result<T> Error(Exception ex) => new() { IsSuccess = false, Errors = new List<string> { ex.Message } };
    public static Result<T> Canceled() => new() { IsSuccess = false, Errors = new List<string> { "Operation was canceled." } };
}
```

---

## 🧠 Behavior by EncryptionConfig
The behavior of the decryptor changes depending on the `EncryptionConfig` value found in the `.L5X` input.

| Case                    | EncryptionConfig | Result Type    | Output Message                                      |
|-------------------------|------------------|----------------|-----------------------------------------------------|
| Supported & Decrypted   | e.g., 1–7        | `Success`       | `"Found source key: \"...\""`                        |
| Partial Support         | 8                | `Success + Warn`| `"Source key recovery is not supported for config=8"`|
| Not Supported           | 9                | `Failure`       | `"Unsupported EncryptionConfig value. Decryption not supported."` |

---

## 🧪 Testing
This project includes a full test suite designed for maintainability and readability.

### Frameworks
- `xUnit v3` for unit testing
- `Shouldly` for expressive assertions
- `Meziantou.Extensions.Logging.Xunit` for integrated test logging

### Test Examples
```csharp
[Test]
public async Task Decrypt_OpenL5X_ReturnsWarning()
{
    var decryptor = CreateDecryptor();
    var result = await decryptor.DecryptFromFileAsync("Open.L5X");

    result.IsSuccess.ShouldBeTrue();
    result.Value.Warnings.ShouldContain("EncryptionConfig=\"8\"");
}
```

### Test Data
Fixtures should include:
- Encrypted `.L5X` files
- Matching expected output XML
- Messages text to validate warnings or errors

Test case naming convention:
`<Feature>_<Scenario>_<ExpectedResult>()`

---

## 🔜 Phase 2 (Future Work)
In the next stage, we will:
- Add a MudBlazor UI for drag-and-drop decryption in-browser
- Integrate multi-format file ingestion and export
- Enhance cryptographic flexibility (e.g., supporting more algorithms)

---

## ✅ Goals
- Blazor-compatible (WASM or Server)
- Async/await usage throughout
- Minimal API surface, composable architecture
- Extendable with low coupling
- Beginner and intermediate developer friendly: modular files, clean naming, clear responsibilities, robust test support

---

## 🧰 Getting Started for Developers
1. **Clone the repo** and navigate to `L5XDecryptionLib/`.
2. **Run tests**:
   ```bash
   dotnet test
   ```
3. **Use in your app**:
   ```csharp
   var decryptor = new L5XDecryptor(new CryptoService(), new KeyStore(keyList));
   var result = await decryptor.DecryptFromStringAsync(inputString);
   ```
4. **Inspect result**:
   ```csharp
   if (result.IsSuccess)
   {
       Console.WriteLine(result.Value.XmlContent);
       foreach (var warning in result.Value.Warnings)
           Console.WriteLine($"Warning: {warning}");
   }
   else
   {
       Console.WriteLine($"Error: {result.Errors.First()}");
   }
   ```

> 🔎 Tip: Follow the structure and patterns in `L5XDecryptorTests.cs` to extend with your own test fixtures.

---
