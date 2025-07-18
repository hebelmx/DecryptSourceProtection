using LogyxSource.Domain;
using LogyxSource.Models;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Threading.Tasks;

namespace RoutineNameSaltTest
{
    public class ConsoleLogger : ILogger<L5XDecryptor>
    {
        public IDisposable BeginScope<TState>(TState state) => null;
        public bool IsEnabled(LogLevel logLevel) => true;
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception exception, Func<TState, Exception, string> formatter)
        {
            Console.WriteLine($"[{logLevel}] {formatter(state, exception)}");
        }
    }

    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("🧂 Testing Routine Name-Based Salting for V9 Cryptanalysis");
            Console.WriteLine("=" + new string('=', 60));

            var logger = new ConsoleLogger();
            var keyStore = new KeyStore();
            var decryptor = new L5XDecryptor(logger, keyStore);

            // Test with S025_SkidIndexInVDL.L5X (the working file)
            var testFile = "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/S025_SkidIndexInVDL.L5X";
            
            if (File.Exists(testFile))
            {
                Console.WriteLine($"📄 Testing file: {Path.GetFileName(testFile)}");
                Console.WriteLine($"📄 This file should contain routine name 'S025_SkidIndexInVDL'");
                Console.WriteLine();
                
                var result = await decryptor.DecryptFromFileAsync(testFile);
                
                Console.WriteLine($"✅ Result: {result.IsSuccess}");
                if (result.IsSuccess)
                {
                    Console.WriteLine($"📝 Content length: {result.Value.XmlContent.Length}");
                    Console.WriteLine($"⚠️  Warnings: {result.Value.Warnings.Count}");
                    foreach (var warning in result.Value.Warnings)
                    {
                        Console.WriteLine($"   - {warning}");
                    }
                }
                else
                {
                    Console.WriteLine($"❌ Errors: {string.Join(", ", result.Errors)}");
                }
            }
            else
            {
                Console.WriteLine($"❌ Test file not found: {testFile}");
            }

            Console.WriteLine();
            Console.WriteLine("🔍 Test completed - check the logs above for routine name salting attempts!");
        }
    }
}