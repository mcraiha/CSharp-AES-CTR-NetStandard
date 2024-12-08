# CSharp-AES-CTR-NetStandard

Managed .Net (.NET 8) compatible [AES-CTR](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)) cipher written in C# (using [Aes.Create](hhttps://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes.create?view=net-8.0#system-security-cryptography-aes-create) for AES operations)

## Build status

![.NET](https://github.com/mcraiha/CSharp-AES-CTR-NetStandard/workflows/.NET/badge.svg)
[![Codacy Badge](https://app.codacy.com/project/badge/Coverage/0b754630aa9b47109afbd7d0a7f3c10e)](https://www.codacy.com/gh/mcraiha/CSharp-AES-CTR-NetStandard/dashboard?utm_source=github.com&utm_medium=referral&utm_content=mcraiha/CSharp-AES-CTR-NetStandard&utm_campaign=Badge_Coverage)

## Why?

Because I needed this for my personal project

## Older versions

YOu can find OLD .NET Standard and .NET 6 compatible version from [older branch](https://github.com/mcraiha/CSharp-AES-CTR-NetStandard/tree/netstandard20andnet6)

## Documentation

[Docs](https://mcraiha.github.io/CSharp-AES-CTR-NetStandard/api/index.html)


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

## Test cases

You can run test cases by moving to **tests** folder and running following command
```bash
dotnet test
```

## Benchmarks

You can run benchmarks (which compare this implementation to the original version) by moving to **benchmarks** folder and running following command
```bash
dotnet run -c Release
```

there are three different input sizes (64 bytes, 1024 bytes and 1 MiB) and comparisons are done between code from [Stack Overflow](https://stackoverflow.com/a/51188472/4886769) (made by **Martin Prikryl**) and this project

## License

All the code in [src](src) and [tests](tests) folders are licensed under [Unlicense](LICENSE). SO sample [code file](benchmarks/SO_AES.cs) (which is only used during benchmarking) is licensed under cc-wiki (aka cc-by-sa) license, see https://stackoverflow.blog/2009/06/25/attribution-required/