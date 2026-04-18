# 🔐 Security Package

A C# library of well-known cryptographic and network security algorithms, prepared for the **Computer and Networks Security** course at **Ain Shams University**.

---

## 📦 Project Structure

```
Security-Package/
├── securitylibrary/        # Core algorithm implementations
├── securitypackagetest/    # Unit tests for all algorithms
└── SecurityPackage.sln     # Visual Studio solution file
```

---

## 🧩 Implemented Algorithms

### Classical Ciphers
| Algorithm | Type |
|-----------|------|
| Caesar Cipher | Substitution |
| Monoalphabetic Cipher | Substitution |
| Playfair Cipher | Substitution |
| Hill Cipher | Substitution |
| Polyalphabetic Cipher (Vigenère) | Substitution |
| Rail Fence Cipher | Transposition |
| Columnar Transposition | Transposition |

### Modern Symmetric Encryption
| Algorithm | Type |
|-----------|------|
| AES (Advanced Encryption Standard) | Block Cipher |
| DES (Data Encryption Standard) | Block Cipher |
| RC4 | Stream Cipher |

### Asymmetric & Key Exchange
| Algorithm | Type |
|-----------|------|
| RSA | Public-Key Encryption |
| Diffie-Hellman Key Exchange | Key Exchange Protocol |
| ElGamal Cryptographic System | Public-Key Encryption |

---

## 🚀 Getting Started

### Prerequisites

- [Visual Studio 2013 or later](https://visualstudio.microsoft.com/)
- .NET Framework 4.5+

### Running the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/ibrahimmohamedkmal/Security-Package.git
   ```
2. Open `SecurityPackage.sln` in Visual Studio.
3. Build the solution (`Ctrl + Shift + B`).
4. Run the tests via **Test → Run All Tests** or use the Test Explorer.

---

## 🧪 Testing

Unit tests are located in the `securitypackagetest` project and cover encryption and decryption for each implemented algorithm.

---

## 🎓 Academic Context

This project was developed as part of the **Computer and Networks Security** course at the Faculty of Computer and Information Sciences, **Ain Shams University**, Cairo, Egypt.

---

## 📄 License

This project is intended for educational purposes.
