using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

class RSLogixDictionaryAttack
{
    static void Main(string[] args)
    {
        Console.WriteLine("🎯 RSLOGIX DICTIONARY ATTACK - KEYWORD VALIDATION APPROACH");
        Console.WriteLine("=" + new string('=', 70));
        Console.WriteLine("🔍 Strategy: Look for partial success using RSLogix keywords");
        Console.WriteLine("📊 Approach: Dictionary + Salted/Hashed keys vs known algorithms");
        Console.WriteLine();

        // Step 1: Extract RSLogix keywords from existing files
        var dictionary = ExtractRSLogixKeywords();
        Console.WriteLine($"📚 Extracted {dictionary.Count} RSLogix keywords for validation");
        
        // Step 2: Test files
        var testFiles = new[]
        {
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S025_SkidIndexInVDL.L5X"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33/", "S005_STP1Advance.L5X"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_050_SP_MANFREM.L5X"),
            ("/mnt/e/Dynamic/Source/DecryptSourceProtection/UnknowFixture V30/", "_051_PPLAASEUD.L5X")
        };

        foreach (var (basePath, fileName) in testFiles)
        {
            Console.WriteLine($"\n🔍 Testing: {fileName}");
            Console.WriteLine("-" + new string('-', 50));
            
            try
            {
                var filePath = Path.Combine(basePath, fileName);
                if (!File.Exists(filePath)) continue;
                
                var encryptedBytes = ExtractEncryptedBytes(filePath);
                if (encryptedBytes == null) continue;
                
                Console.WriteLine($"📦 Encrypted bytes: {encryptedBytes.Length:N0}");
                
                // Test with comprehensive dictionary attack
                TestDictionaryAttack(encryptedBytes, dictionary, fileName);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Error testing {fileName}: {ex.Message}");
            }
        }
    }

    static HashSet<string> ExtractRSLogixKeywords()
    {
        var keywords = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        
        // 1. Extract from unprotected L5X files
        var unprotectedPath = "/mnt/e/Dynamic/Source/DecryptSourceProtection/Know Fixture V33 Not encrypted/";
        if (Directory.Exists(unprotectedPath))
        {
            foreach (var file in Directory.GetFiles(unprotectedPath, "*.L5X"))
            {
                try
                {
                    var content = File.ReadAllText(file);
                    ExtractKeywordsFromContent(content, keywords);
                    Console.WriteLine($"📄 Extracted keywords from: {Path.GetFileName(file)}");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"⚠️  Error reading {file}: {ex.Message}");
                }
            }
        }

        // 2. Add well-known RSLogix keywords
        AddWellKnownRSLogixKeywords(keywords);
        
        // 3. Add PLC/Industrial keywords  
        AddIndustrialKeywords(keywords);
        
        return keywords;
    }

    static void ExtractKeywordsFromContent(string content, HashSet<string> keywords)
    {
        // Extract XML tags
        var xmlTags = Regex.Matches(content, @"</?(\w+)[^>]*>", RegexOptions.IgnoreCase);
        foreach (Match match in xmlTags)
        {
            if (match.Groups[1].Value.Length > 2)
                keywords.Add(match.Groups[1].Value);
        }
        
        // Extract attribute names
        var attributes = Regex.Matches(content, @"(\w+)=""[^""]*""", RegexOptions.IgnoreCase);
        foreach (Match match in attributes)
        {
            if (match.Groups[1].Value.Length > 2)
                keywords.Add(match.Groups[1].Value);
        }
        
        // Extract common programming keywords
        var programmingKeywords = Regex.Matches(content, @"\b(MOV|XIO|XIC|OTE|OTL|OTU|ADD|SUB|MUL|DIV|EQU|NEQ|GRT|LES|GEQ|LEQ|AND|OR|NOT|JMP|JSR|RET|FOR|WHILE|IF|ELSE|CASE|TIMER|COUNTER|PID|SCALE|MOVE|COPY|FILL|SIZE|UPPER|LOWER|MID|FIND|REPLACE|CONCAT|INSERT|DELETE|SORT|BOOL|SINT|INT|DINT|LINT|USINT|UINT|UDINT|ULINT|REAL|LREAL|STRING|WSTRING|TIME|DATE|TOD|DT|ARRAY|STRUCT|UNION|ENUM|ALIAS|ROUTINE|PROGRAM|TASK|MODULE|DEVICE|NETWORK|MOTION|AXIS|SERVO|DRIVE|ENCODER|SENSOR|ACTUATOR|VALVE|PUMP|MOTOR|CONVEYOR|ROBOT|HMI|SCADA|HISTORIAN|ALARM|EVENT|TREND|RECIPE|BATCH|SEQUENCE|INTERLOCK|SAFETY|ESTOP|GUARD|LIGHT|HORN|BEACON|INDICATOR|BUTTON|SWITCH|RELAY|CONTACTOR|BREAKER|FUSE|DISCONNECT|TRANSFORMER|INVERTER|RECTIFIER|FILTER|ISOLATOR|JUNCTION|TERMINAL|CABINET|PANEL|ENCLOSURE|CONDUIT|CABLE|WIRE|CONNECTOR|PLUG|SOCKET|ADAPTER|CONVERTER|REPEATER|AMPLIFIER|SPLITTER|MERGER|BUFFER|QUEUE|STACK|HEAP|POOL|CACHE|REGISTER|MEMORY|STORAGE|DATABASE|FILE|FOLDER|DIRECTORY|PATH|URL|URI|IP|TCP|UDP|HTTP|HTTPS|FTP|SFTP|SSH|TELNET|SNMP|MODBUS|ETHERNET|SERIAL|CAN|PROFIBUS|PROFINET|DEVICENET|CONTROLNET|FOUNDATION|HART|WIRELESS|BLUETOOTH|WIFI|CELLULAR|SATELLITE|GPS|COMPASS|GYROSCOPE|ACCELEROMETER|MAGNETOMETER|BAROMETER|THERMOMETER|HYGROMETER|ANEMOMETER|LUXMETER|DOSIMETER|SPECTROMETER|OSCILLOSCOPE|MULTIMETER|CLAMP|PROBE|LOGGER|RECORDER|ANALYZER|CALIBRATOR|SIMULATOR|EMULATOR|DEBUGGER|MONITOR|VIEWER|EDITOR|COMPILER|INTERPRETER|RUNTIME|FIRMWARE|SOFTWARE|HARDWARE|MIDDLEWARE|DRIVER|LIBRARY|FRAMEWORK|TOOLKIT|UTILITY|APPLICATION|SERVICE|DAEMON|PROCESS|THREAD|TASK|QUEUE|SEMAPHORE|MUTEX|LOCK|UNLOCK|WAIT|SIGNAL|NOTIFY|BROADCAST|MULTICAST|UNICAST|PUBLISH|SUBSCRIBE|REQUEST|RESPONSE|QUERY|COMMAND|STATUS|STATE|MODE|PHASE|STEP|STAGE|LEVEL|GRADE|RANK|PRIORITY|WEIGHT|FACTOR|RATIO|PERCENTAGE|FRACTION|DECIMAL|BINARY|OCTAL|HEXADECIMAL|ASCII|UNICODE|UTF8|UTF16|UTF32|BASE64|MD5|SHA1|SHA256|SHA512|AES|DES|RSA|ECC|HMAC|HASH|ENCRYPT|DECRYPT|SIGN|VERIFY|CERTIFICATE|KEY|TOKEN|PASSWORD|USERNAME|ACCOUNT|PROFILE|ROLE|PERMISSION|ACCESS|AUTHORIZATION|AUTHENTICATION|SESSION|COOKIE|CACHE|LOG|AUDIT|TRACE|DEBUG|INFO|WARN|ERROR|FATAL|EXCEPTION|FAULT|FAILURE|SUCCESS|COMPLETE|INCOMPLETE|PENDING|ACTIVE|INACTIVE|ENABLED|DISABLED|ONLINE|OFFLINE|CONNECTED|DISCONNECTED|AVAILABLE|UNAVAILABLE|READY|BUSY|IDLE|RUNNING|STOPPED|PAUSED|SUSPENDED|RESUMED|STARTED|FINISHED|CANCELLED|ABORTED|TIMEOUT|RETRY|REPEAT|CONTINUE|BREAK|RETURN|EXIT|QUIT|SHUTDOWN|RESTART|RESET|INITIALIZE|CONFIGURE|SETUP|INSTALL|UNINSTALL|UPDATE|UPGRADE|DOWNGRADE|BACKUP|RESTORE|EXPORT|IMPORT|SAVE|LOAD|OPEN|CLOSE|CREATE|DELETE|MODIFY|CHANGE|EDIT|COPY|PASTE|CUT|MOVE|RENAME|SEARCH|FIND|REPLACE|SORT|FILTER|GROUP|MERGE|SPLIT|JOIN|SEPARATE|COMBINE|INTEGRATE|SYNCHRONIZE|COORDINATE|ORCHESTRATE|AUTOMATE|SCHEDULE|PLAN|EXECUTE|MONITOR|CONTROL|MANAGE|ADMINISTER|OPERATE|MAINTAIN|SERVICE|SUPPORT|HELP|ASSIST|GUIDE|INSTRUCT|TEACH|LEARN|TRAIN|PRACTICE|TEST|VALIDATE|VERIFY|CONFIRM|APPROVE|REJECT|ACCEPT|DENY|ALLOW|BLOCK|PERMIT|PROHIBIT|RESTRICT|LIMIT|BOUND|RANGE|SCOPE|SCALE|SIZE|DIMENSION|MEASURE|CALCULATE|COMPUTE|PROCESS|ANALYZE|EVALUATE|ASSESS|JUDGE|DECIDE|CHOOSE|SELECT|PICK|OPTION|ALTERNATIVE|PREFERENCE|SETTING|PARAMETER|ARGUMENT|VARIABLE|CONSTANT|FIELD|PROPERTY|ATTRIBUTE|CHARACTERISTIC|FEATURE|FUNCTION|METHOD|PROCEDURE|OPERATION|ACTION|ACTIVITY|BEHAVIOR|RESPONSE|REACTION|INTERACTION|COMMUNICATION|TRANSMISSION|RECEPTION|SENDING|RECEIVING|BROADCASTING|MULTICASTING|UNICASTING|ADDRESSING|ROUTING|SWITCHING|BRIDGING|GATEWAYING|PROXYING|FILTERING|BLOCKING|FORWARDING|REDIRECTING|TRANSLATING|CONVERTING|TRANSFORMING|MAPPING|BINDING|LINKING|CONNECTING|DISCONNECTING|ATTACHING|DETACHING|MOUNTING|UNMOUNTING|LOADING|UNLOADING|INSTALLING|UNINSTALLING|REGISTERING|UNREGISTERING|SUBSCRIBING|UNSUBSCRIBING|PUBLISHING|UNPUBLISHING|ADVERTISING|DISCOVERING|LOCATING|FINDING|SEARCHING|BROWSING|NAVIGATING|EXPLORING|INVESTIGATING|EXAMINING|INSPECTING|CHECKING|TESTING|VALIDATING|VERIFYING|CONFIRMING|APPROVING|REJECTING|ACCEPTING|DENYING|ALLOWING|BLOCKING|PERMITTING|PROHIBITING|RESTRICTING|LIMITING|BOUNDING|RANGING|SCOPING|SCALING|SIZING|DIMENSIONING|MEASURING|CALCULATING|COMPUTING|PROCESSING|ANALYZING|EVALUATING|ASSESSING|JUDGING|DECIDING|CHOOSING|SELECTING|PICKING)\b", RegexOptions.IgnoreCase);
        foreach (Match match in programmingKeywords)
        {
            if (match.Groups[1].Value.Length > 2)
                keywords.Add(match.Groups[1].Value);
        }
    }

    static void AddWellKnownRSLogixKeywords(HashSet<string> keywords)
    {
        // RSLogix 5000 specific keywords
        var rslogixKeywords = new[]
        {
            // Basic Instructions
            "MOV", "XIO", "XIC", "OTE", "OTL", "OTU", "ONS", "OSR", "OSF",
            "ADD", "SUB", "MUL", "DIV", "MOD", "SQR", "SQRT", "ABS", "NEG",
            "EQU", "NEQ", "GRT", "LES", "GEQ", "LEQ", "LIM", "MEQ", "MASK",
            "AND", "OR", "XOR", "NOT", "BTD", "BIT", "SHL", "SHR", "ROL", "ROR",
            
            // Timer/Counter
            "TON", "TOF", "RTO", "CTU", "CTD", "RES",
            
            // Program Control
            "JMP", "LBL", "JSR", "RET", "SBR", "MCR", "END", "NOP", "AFI",
            "FOR", "NEXT", "WHILE", "ENDWHILE", "IF", "ELSE", "ENDIF", "CASE", "ENDCASE",
            
            // Data Types
            "BOOL", "SINT", "INT", "DINT", "LINT", "USINT", "UINT", "UDINT", "ULINT",
            "REAL", "LREAL", "STRING", "WSTRING", "TIME", "DATE", "TOD", "DT",
            
            // File Operations
            "COP", "CPS", "FLL", "FAL", "FSC", "DDT", "DCD", "ENC", "SEL",
            "AVE", "STD", "SRT", "SIZE", "BSL", "BSR", "FIFO", "LIFO",
            
            // Math/Trig
            "SIN", "COS", "TAN", "ASN", "ACS", "ATN", "LN", "LOG", "XPY",
            "DEG", "RAD", "TRN", "SCL", "SCP",
            
            // Motion/PID
            "PID", "PIDE", "PMUL", "PRNP", "PCLR", "PXRQ", "POVR", "PATT",
            "AXIS", "SERVO", "MOTION", "HOME", "JOG", "MOVE", "STOP",
            
            // Communication
            "MSG", "DTOS", "STOD", "RTOS", "STOR", "UPPER", "LOWER", "MID",
            "FIND", "REPLACE", "CONCAT", "INSERT", "DELETE",
            
            // System
            "GSV", "SSV", "IOT", "IIT", "OTL", "OTU", "OSR", "OSF", "TONR", "TOFR",
            
            // XML Structure
            "RSLogix5000Content", "Controller", "Programs", "Program", "Routines", "Routine",
            "RLLContent", "Rung", "Text", "Comment", "Tag", "DataType", "Module",
            "EncodedData", "EncryptionConfig", "TargetName", "TargetType",
            
            // Attributes
            "Name", "Type", "Class", "Use", "Radix", "Dimension", "Hidden", "ExternalAccess",
            "Description", "SchemaRevision", "SoftwareRevision", "ContainsContext"
        };
        
        foreach (var keyword in rslogixKeywords)
        {
            keywords.Add(keyword);
        }
    }

    static void AddIndustrialKeywords(HashSet<string> keywords)
    {
        // Industrial automation keywords
        var industrialKeywords = new[]
        {
            "INTERLOCK", "SAFETY", "ESTOP", "GUARD", "ALARM", "EVENT", "TREND",
            "RECIPE", "BATCH", "SEQUENCE", "VALVE", "PUMP", "MOTOR", "CONVEYOR",
            "SENSOR", "ACTUATOR", "ENCODER", "DRIVE", "INVERTER", "HMI", "SCADA",
            "MODBUS", "ETHERNET", "PROFIBUS", "PROFINET", "DEVICENET", "CONTROLNET",
            "FOUNDATION", "HART", "WIRELESS", "BLUETOOTH", "WIFI", "CELLULAR",
            "TEMPERATURE", "PRESSURE", "FLOW", "LEVEL", "POSITION", "SPEED",
            "TORQUE", "FORCE", "VIBRATION", "CURRENT", "VOLTAGE", "POWER",
            "ENERGY", "FREQUENCY", "PHASE", "ANGLE", "DISTANCE", "WEIGHT",
            "DENSITY", "VISCOSITY", "CONDUCTIVITY", "PH", "OXYGEN", "CARBON",
            "NITROGEN", "HYDROGEN", "METHANE", "PROPANE", "BUTANE", "ETHANE"
        };
        
        foreach (var keyword in industrialKeywords)
        {
            keywords.Add(keyword);
        }
    }

    static byte[] ExtractEncryptedBytes(string filePath)
    {
        try
        {
            var content = File.ReadAllText(filePath);
            
            // Extract encrypted data
            var encodedMatch = Regex.Match(content, @"<EncodedData[^>]*>(.*?)</EncodedData>", RegexOptions.Singleline);
            if (!encodedMatch.Success) return null;
            
            var encodedContent = encodedMatch.Groups[1].Value;
            encodedContent = Regex.Replace(encodedContent, @"<!\[CDATA\[(.*?)\]\]>", "$1", RegexOptions.Singleline);
            
            // Clean Base64
            var cleanedBase64 = CleanBase64String(encodedContent);
            return Convert.FromBase64String(cleanedBase64);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error extracting encrypted bytes: {ex.Message}");
            return null;
        }
    }

    static string CleanBase64String(string base64String)
    {
        if (string.IsNullOrEmpty(base64String)) return base64String;

        var cleaned = base64String
            .Replace("\r", "").Replace("\n", "").Replace("\t", "").Replace(" ", "")
            .Trim();

        var validBase64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        var result = new StringBuilder(cleaned.Length);
        
        foreach (char c in cleaned)
        {
            if (validBase64Chars.Contains(c))
                result.Append(c);
        }

        cleaned = result.ToString().TrimEnd('=');
        int paddingCount = 4 - (cleaned.Length % 4);
        if (paddingCount != 4)
            cleaned += new string('=', paddingCount);

        return cleaned;
    }

    static void TestDictionaryAttack(byte[] encryptedBytes, HashSet<string> dictionary, string fileName)
    {
        Console.WriteLine($"🎯 Dictionary Attack on {fileName}");
        Console.WriteLine($"📚 Testing {dictionary.Count} keywords as validation");
        
        var baseKeys = new[] { "Stana7", "Visual2025", "RSLogix5000", "defaultkey", "testkey" };
        var salts = new[] { fileName, "RSLogix", "V9", "encryption", "" };
        
        var algorithms = new[]
        {
            ("AES-ECB", new Func<byte[], byte[], (bool, string)>((data, key) => TryAESDecrypt(data, key, CipherMode.ECB))),
            ("AES-CBC", new Func<byte[], byte[], (bool, string)>((data, key) => TryAESDecrypt(data, key, CipherMode.CBC))),
            ("RC4", new Func<byte[], byte[], (bool, string)>((data, key) => TryRC4Decrypt(data, key)))
        };
        
        var suspects = new List<(string algorithm, string keyDerivation, int keywordMatches, string sample)>();
        
        foreach (var baseKey in baseKeys)
        {
            foreach (var salt in salts)
            {
                // Generate different key derivations
                var keyDerivations = new[]
                {
                    ("Direct", Encoding.UTF8.GetBytes(baseKey)),
                    ("MD5", MD5.HashData(Encoding.UTF8.GetBytes(baseKey + salt))),
                    ("SHA1", SHA1.HashData(Encoding.UTF8.GetBytes(baseKey + salt))),
                    ("SHA256", SHA256.HashData(Encoding.UTF8.GetBytes(baseKey + salt))),
                    ("SHA256-Reverse", SHA256.HashData(Encoding.UTF8.GetBytes(salt + baseKey))),
                    ("SHA256-Separated", SHA256.HashData(Encoding.UTF8.GetBytes(baseKey + "|" + salt)))
                };
                
                foreach (var (derivationName, keyBytes) in keyDerivations)
                {
                    foreach (var (algorithmName, decryptFunc) in algorithms)
                    {
                        try
                        {
                            var (success, decryptedText) = decryptFunc(encryptedBytes, keyBytes);
                            if (success && !string.IsNullOrEmpty(decryptedText))
                            {
                                var keywordMatches = CountKeywordMatches(decryptedText, dictionary);
                                if (keywordMatches > 0)
                                {
                                    var sample = decryptedText.Length > 100 ? decryptedText.Substring(0, 100) : decryptedText;
                                    suspects.Add((algorithmName, $"{derivationName}({baseKey}+{salt})", keywordMatches, sample));
                                    
                                    Console.WriteLine($"🎯 SUSPECT: {algorithmName} with {derivationName}({baseKey}+{salt})");
                                    Console.WriteLine($"   Keywords found: {keywordMatches}");
                                    Console.WriteLine($"   Sample: {sample.Replace("\n", " ").Replace("\r", " ")}");
                                    Console.WriteLine();
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            // Silently continue - many combinations will fail
                        }
                    }
                }
            }
        }
        
        // Report results
        if (suspects.Count > 0)
        {
            Console.WriteLine($"🎉 FOUND {suspects.Count} SUSPECT CANDIDATES!");
            var bestSuspect = suspects.OrderByDescending(s => s.keywordMatches).First();
            Console.WriteLine($"🏆 BEST CANDIDATE: {bestSuspect.algorithm} with {bestSuspect.keyDerivation}");
            Console.WriteLine($"   Keywords: {bestSuspect.keywordMatches}");
            Console.WriteLine($"   Sample: {bestSuspect.sample}");
        }
        else
        {
            Console.WriteLine("❌ No suspects found with RSLogix keywords");
        }
    }

    static int CountKeywordMatches(string text, HashSet<string> dictionary)
    {
        var matches = 0;
        var upperText = text.ToUpper();
        
        foreach (var keyword in dictionary)
        {
            if (upperText.Contains(keyword.ToUpper()))
            {
                matches++;
            }
        }
        
        return matches;
    }

    static (bool Success, string Content) TryAESDecrypt(byte[] encryptedBytes, byte[] key, CipherMode mode)
    {
        try
        {
            using var aes = Aes.Create();
            aes.Mode = mode;
            aes.Padding = PaddingMode.PKCS7;
            
            var keyBytes = new byte[32];
            Array.Copy(key, keyBytes, Math.Min(key.Length, 32));
            aes.Key = keyBytes;
            
            if (mode == CipherMode.CBC)
            {
                var iv = new byte[16];
                Array.Copy(key, iv, Math.Min(key.Length, 16));
                aes.IV = iv;
            }
            
            using var decryptor = aes.CreateDecryptor();
            var decryptedBytes = decryptor.TransformFinalBlock(encryptedBytes, 0, encryptedBytes.Length);
            var decryptedText = Encoding.UTF8.GetString(decryptedBytes);
            
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }

    static (bool Success, string Content) TryRC4Decrypt(byte[] encryptedBytes, byte[] key)
    {
        try
        {
            // Simple RC4 implementation
            var s = new byte[256];
            var keyBytes = new byte[256];
            
            for (int i = 0; i < 256; i++)
            {
                s[i] = (byte)i;
                keyBytes[i] = key[i % key.Length];
            }
            
            int j = 0;
            for (int i = 0; i < 256; i++)
            {
                j = (j + s[i] + keyBytes[i]) % 256;
                (s[i], s[j]) = (s[j], s[i]);
            }
            
            var result = new byte[encryptedBytes.Length];
            int x = 0, y = 0;
            
            for (int i = 0; i < encryptedBytes.Length; i++)
            {
                x = (x + 1) % 256;
                y = (y + s[x]) % 256;
                (s[x], s[y]) = (s[y], s[x]);
                result[i] = (byte)(encryptedBytes[i] ^ s[(s[x] + s[y]) % 256]);
            }
            
            var decryptedText = Encoding.UTF8.GetString(result);
            return (true, decryptedText);
        }
        catch
        {
            return (false, "");
        }
    }
}