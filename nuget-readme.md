## About

Managed .Net (Standard 2.0 and .NET 6) compatible [AES-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) cipher written in C# (using [AesManaged](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged?view=netstandard-2.0) for AES operations)

## How to use

```csharp
using CS_AES_CTR;

byte[] mySimpleTextAsBytes = Encoding.ASCII.GetBytes("Plain text I want to encrypt");

// In real world, generate these with cryptographically secure pseudo-random number generator (CSPRNG)
byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

// Encrypt
AES_CTR forEncrypting = new AES_CTR(key, initialCounter);			
byte[] encryptedContent = new byte[mySimpleTextAsBytes.Length];
forEncrypting.EncryptBytes(encryptedContent, mySimpleTextAsBytes);

// Decrypt
AES_CTR forDecrypting = new AES_CTR(key, initialCounter);
byte[] decryptedContent = new byte[encryptedContent.Length];
forDecrypting.DecryptBytes(decryptedContent, encryptedContent);

```

You can try out the code in [.NET Fiddle](https://dotnetfiddle.net/mtvYHv)
