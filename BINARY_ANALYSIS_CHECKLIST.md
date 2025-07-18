# 🔍 Binary Analysis Checklist - Tonight's Investigation

## 🎯 **Quick Action Items for Tonight**

### **📋 Phase 1: Initial Binary Survey (15 minutes)**
- [ ] **Extract all binaries** to analysis folder
- [ ] **Run `strings` command** on main executable
- [ ] **Search for crypto keywords**: "AES", "RC4", "SHA", "MD5", "EncryptionConfig", "V9"
- [ ] **Check dependencies**: Look for crypto DLLs loaded by main program
- [ ] **Inventory sw/v30 and sw/v33 directories**

### **📋 Phase 2: Crypto DLL Hunt (20 minutes)**
- [ ] **System.Security.Cryptography.dll** present?
- [ ] **bcrypt.dll** or Windows crypto APIs?
- [ ] **Custom crypto libraries** with suspicious names?
- [ ] **OpenSSL** or third-party crypto?
- [ ] **Search for hex constants**: `0DEB1CAE2A6D8A89`, `0009`

### **📋 Phase 3: XML Traces Investigation (15 minutes)**
- [ ] **Examine sw/v30/** directory for XML files
- [ ] **Examine sw/v33/** directory for XML files
- [ ] **Look for debug logs** or trace files
- [ ] **Search for encryption parameters** in XML
- [ ] **Compare V30 vs V33 trace differences**

### **📋 Phase 4: Debugger Setup (if time permits)**
- [ ] **Attach debugger** to main program
- [ ] **Set breakpoints** on crypto API calls
- [ ] **Monitor file I/O** during encryption
- [ ] **Trace V9 encryption path**

---

## 🎯 **High-Priority Search Strings**

### **Crypto Keywords**
```
"EncryptionConfig"
"V9"
"EncodedData"
"Stana7"
"RSLogix"
"AES"
"RC4"
"SHA256"
"MD5"
```

### **Header Patterns**
```
"0DEB1CAE2A6D8A89"
"0009"
"D360F10430F4D8FC"
"D29227489DD7B122"
```

### **Routine Names**
```
"S025_SkidIndexInVDL"
"_050_SP_MANFREM"
"RoutineName"
"TargetName"
```

---

## 🔍 **What We're Looking For**

### **🎯 Priority 1: V9 Encryption Function**
```csharp
// Target code pattern:
if (encryptionConfig == 9) {
    // This is what we need!
    return EncryptV9(data, key, routineName);
}
```

### **🎯 Priority 2: Header Generation**
```csharp
// Why V33 vs V30 headers differ:
var header = GenerateHeader(version, encryptionConfig);
// V33: 0DEB1CAE2A6D8A89...
// V30: 0009...
```

### **🎯 Priority 3: Key Derivation**
```csharp
// How keys are created:
var key = DeriveKey("Stana7", routineName, encryptionConfig);
```

---

## 📊 **Expected Findings**

Based on our entropy analysis showing **7.85-7.91 vs 7.93-7.94** similarity:

### **🎯 Likely Algorithm**
- **Base**: AES or similar strong encryption
- **Key Derivation**: SHA256 or MD5 with salt
- **Mode**: ECB, CBC, or custom
- **Compression**: Possible GZip/Deflate preprocessing

### **🎯 Header Pattern Explanation**
- **V33**: `0DEB1CAE2A6D8A89...` = Version 33 identifier
- **V30**: `0009...` = Version 30 identifier
- **Same encryption, different headers**

### **🎯 Size Difference (V30 = 60% of V33)**
- **Different compression algorithms**
- **Different header/footer sizes**
- **Different XML preprocessing**

---

## 🚀 **Success Criteria**

### **🎯 Mission Success = Find Any Of These:**
1. **V9 encryption function** implementation
2. **Key derivation algorithm** source code
3. **Header generation logic** for V30 vs V33
4. **Compression method** used before encryption
5. **Configuration parameters** for V9

### **📋 Document Everything Found:**
- **File locations** of crypto code
- **Function names** for V9 encryption
- **Parameter values** used
- **API calls** made during encryption

---

## 🎯 **Quick Win Strategy**

**If short on time tonight:**
1. **Strings search** for crypto keywords (5 min)
2. **sw/v30 vs sw/v33** directory comparison (10 min)
3. **DLL dependency** check (5 min)

**This 20-minute investigation could provide the breakthrough we need!**

---

**🎯 The entropy similarity (7.85-7.91 vs 7.93-7.94) proves we're VERY close to the correct algorithm. Binary analysis should reveal the exact implementation we need to crack V9 encryption!**

*Good luck tonight! The breakthrough is within reach!* 🚀