# CSharp-AES-CTR-NetStandard

Managed .Net 8 compatible [AES-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) cipher written in C# (using [AesManaged](https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aesmanaged?view=netstandard-2.0) for AES operations)

## GitHub
[CSharp-AES-CTR-NetStandard](https://github.com/mcraiha/CSharp-AES-CTR-NetStandard)

## Documentation
[Documentation](api/) 

## How do I use this?
Either copy the [CSAES-CTR.cs](src/CSAES-CTR.cs) to your project or use [LibAES-CTR](https://www.nuget.org/packages/LibAES-CTR/) nuget package

Then do code like
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

## License

All the code in [src](src) and [tests](tests) folders are licensed under [Unlicense](LICENSE). SO sample [code file](benchmarks/SO_AES.cs) (which is only used during benchmarking) is licensed under cc-wiki (aka cc-by-sa) license, see https://stackoverflow.blog/2009/06/25/attribution-required/