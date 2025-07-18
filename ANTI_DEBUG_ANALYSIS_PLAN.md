# 🛡️ Anti-Debugging Analysis Plan

## 🎯 **Target: RSLogix V9 Decryption Functions**

### **Primary Challenge:**
- RSLogix detects debugger presence and crashes intentionally
- Need to bypass anti-debugging to access `logixac_dec_cWatchPaneGrid::DoesAppendRowCreateTag+B0D0`

## 🔍 **Critical DLLs Identified:**

### **1. LogixAC.dll (Primary Target)**
- **V30**: 6,368,560 bytes (Nov 15, 2017)
- **V33**: 5,864,288 bytes (Sep 20, 2020) 
- **Contains**: `logixac_dec_` decryption methods
- **Function**: Main application component with V9 decryption logic

### **2. FTAStub.dll (Crypto Interface)**
- **V30**: 1,377,072 bytes (Feb 12, 2016)
- **V33**: 1,588,040 bytes (Jan 25, 2018)
- **Likely Role**: Crypto API interface/wrapper
- **Size Increase**: +210KB suggests enhanced crypto functionality

### **3. GPBServices.dll (Data Handler)**
- **Role**: Protocol buffer serialization
- **Connection**: Handles data before/after encryption

## 🛠️ **Anti-Debugging Bypass Strategies:**

### **Strategy 1: Static Analysis (Recommended)**
```bash
# Use IDA Pro without attaching to running process
# Load LogixAC.dll directly for analysis
# Search for string "logixac_dec_" and "DoesAppendRowCreateTag"
# Extract crypto functions without triggering protection
```

### **Strategy 2: ScyllaHide + IDA Pro**
```
Configuration for RSLogix bypass:
- Hide PEB debugging flags
- Block IsDebuggerPresent() API
- Patch NtQueryInformationProcess
- Hide from thread creation callbacks
- Block SetUnhandledExceptionFilter
```

### **Strategy 3: DLL Hijacking**
```bash
# Create wrapper DLLs that log crypto calls
# Replace FTAStub.dll with logging version
# Capture decryption parameters during normal execution
```

### **Strategy 4: Memory Dumping**
```bash
# Use ProcessHacker or similar to dump memory
# Capture process when V9 file is loaded
# Extract decryption keys from memory without debugging
```

## 🎯 **Search Targets in LogixAC.dll:**

### **Function Signatures to Find:**
- `logixac_dec_cWatchPaneGrid::DoesAppendRowCreateTag`
- `logixac_dec_*` (any function starting with this pattern)
- V9 encryption configuration handlers
- Key derivation functions
- ARC4/RC4 implementation

### **String Searches:**
- "EncryptionConfig"
- "V9"
- "ARC4"
- "RC4"
- "decrypt"
- "cipher"
- "key"

## 📊 **Version Comparison Analysis:**

### **Key Differences V30 → V33:**
1. **LogixAC.dll**: Decreased by ~500KB (possibly optimization or removed features)
2. **FTAStub.dll**: Increased by +210KB (enhanced crypto functionality?)
3. **Both support V9**: Same encryption algorithm, possibly different implementations

### **Analysis Priority:**
1. **V30 LogixAC.dll**: Larger size might have more debug symbols
2. **V33 FTAStub.dll**: Enhanced version might have cleaner crypto API
3. **Cross-version comparison**: Identify what changed in V9 implementation

## 🚀 **Next Steps When DLLs Are Ready:**

### **Immediate Actions:**
1. **Load LogixAC.dll in IDA Pro** (static analysis)
2. **Search for `logixac_dec_` functions**
3. **Extract V9 decryption algorithm**
4. **Compare implementations between V30/V33**

### **Advanced Analysis:**
1. **Reverse engineer exact ARC4 implementation**
2. **Extract key derivation methods**
3. **Identify differences that affect V30 vs V33 files**
4. **Build standalone decryption tool**

## 🎯 **Expected Outcomes:**

### **If Static Analysis Succeeds:**
- **Extract exact V9 algorithm** without triggering anti-debug
- **Identify key derivation method** used for each file type
- **Build universal V9 decryptor** that works on all files

### **If Anti-Debug Bypass Needed:**
- **Live debugging of decryption process**
- **Key capture during runtime**
- **Real-time algorithm analysis**

---

**Status**: Ready for DLL analysis when files are uploaded
**Priority**: LogixAC.dll static analysis first, then FTAStub.dll comparison
**Goal**: Extract V9 decryption algorithm and crack all protected files