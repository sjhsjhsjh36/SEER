# 🔐 SEER: Secure and Efficient Encryption-based Erasure via Ransomware

**SEER** is a provably secure file destruction system that repurposes resilient ransomware encryption mechanisms (specifically from the Babuk family) for legitimate, verifiable data erasure. This project implements the encryption core in C++, with support for recursive file discovery and real-time performance statistics.

> ⚠️ This tool is intended for academic research and educational purposes only.

📖 [中文文档 | Chinese README](./README_zh.md)
📘 README curated and written with ❤️ by Lucy (Luning Zhang)

---

## 📌 Features

- 💡 Based on Babuk ransomware's core encryption logic (Curve25519 + SHA256 + Sosemanuk)
- 🔁 Recursively encrypts all files in a target directory (skipping already encrypted ones)
- 🧹 Effectively erases original content by overwriting and renaming
- ⏱️ Measures encryption performance (time + file count + total bytes)
- 🧪 Matches the original ransomware's byte-level behavior (verified via hash consistency)

---

## 🔧 Usage

### 🖥️ Compile

```bash
g++ -o seer general-new.cpp -std=c++11
```

### 🚀 Run

```bash
./seer /path/to/target-directory
```

All eligible files will be:
- Encrypted in-place using the derived session key
- Renamed with a `.encrypted` suffix
- Logged to the terminal with status updates

---

## 🔐 How It Works

SEER adopts a 3-stage architecture:

1. **Key Generation**  
   - Curve25519-based ephemeral key pair
   - Shared secret derived and hashed via SHA256

2. **Encryption**  
   - Uses Sosemanuk stream cipher for fast symmetric encryption
   - Original content is overwritten in-place

3. **Cleanup & Tagging**  
   - Keys are wiped from memory with `memset`
   - File is renamed to `*.encrypted` for tracking

> ✅ The entire encryption pipeline ensures that once the key is destroyed, the original data becomes mathematically unrecoverable.

---

## 📂 Project Structure

```bash
.
├── general-new.cpp     # Main implementation
```

---

## ✅ Validation

The encryption module in this project has been verified to be **byte-level consistent** with the original Babuk ransomware implementation. After transforming and integrating the core logic, we re-hashed the compiled segment and matched it against the original leaked code.  
> 🔎 Full code available for inspection at: [https://github.com/sjhsjhsjh36/SEER](https://github.com/sjhsjhsjh36/SEER)

---

## ⚠️ Disclaimer

This project is strictly for academic and research purposes. The authors are not responsible for any misuse of the code.

---

## 📄 License

MIT License 

---

## 👩‍💻 Author

- **Jiahui Shang**, Communication University of China  
  Contact: [hui@cuc.edu.cn](mailto:hui@cuc.edu.cn)
- Luning Zhang, Communication University of China  
  Contact: [lucyline@cuc.edu.cn](mailto:lucyline@cuc.edu.cn)
