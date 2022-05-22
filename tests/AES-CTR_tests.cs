using NUnit.Framework;
using System.IO;
using CS_AES_CTR;
using System;
using System.Threading.Tasks;
using System.Linq;

namespace Tests
{
	public class ValidityTests
	{
		[SetUp]
		public void Setup()
		{

		}


		[Test]
		public void Known_CTR_AES128EncryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[16] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToEncrypt1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] expectedOutput1 = new byte[] { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce };
			byte[] actualOutput1 = new byte[bytesToEncrypt1.Length];

			byte[] bytesToEncrypt2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] expectedOutput2 = new byte[] { 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff };
			byte[] actualOutput2 = new byte[bytesToEncrypt2.Length];

			byte[] bytesToEncrypt3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] expectedOutput3 = new byte[] { 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab };
			byte[] actualOutput3 = new byte[bytesToEncrypt3.Length];

			byte[] bytesToEncrypt4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] expectedOutput4 = new byte[] { 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee };
			byte[] actualOutput4 = new byte[bytesToEncrypt4.Length];

			#if NET6_0_OR_GREATER
			byte[] actualOutput1DifferentConstructor = new byte[bytesToEncrypt1.Length];
			byte[] actualOutput2DifferentConstructor = new byte[bytesToEncrypt2.Length];
			byte[] actualOutput3DifferentConstructor = new byte[bytesToEncrypt3.Length];
			byte[] actualOutput4DifferentConstructor = new byte[bytesToEncrypt4.Length];
			#endif // NET6_0_OR_GREATER

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.EncryptBytes(actualOutput1, bytesToEncrypt1, bytesToEncrypt1.Length);
			aesCtr.EncryptBytes(actualOutput2, bytesToEncrypt2, bytesToEncrypt2.Length);
			aesCtr.EncryptBytes(actualOutput3, bytesToEncrypt3, bytesToEncrypt3.Length);
			aesCtr.EncryptBytes(actualOutput4, bytesToEncrypt4, bytesToEncrypt4.Length);

			#if NET6_0_OR_GREATER
			AES_CTR aesCtrDifferentConstructor = new AES_CTR(new ReadOnlySpan<byte>(key), new ReadOnlySpan<byte>(initialCounter));
			aesCtrDifferentConstructor.EncryptBytes(actualOutput1DifferentConstructor, bytesToEncrypt1, bytesToEncrypt1.Length);
			aesCtrDifferentConstructor.EncryptBytes(actualOutput2DifferentConstructor, bytesToEncrypt2, bytesToEncrypt2.Length);
			aesCtrDifferentConstructor.EncryptBytes(actualOutput3DifferentConstructor, bytesToEncrypt3, bytesToEncrypt3.Length);
			aesCtrDifferentConstructor.EncryptBytes(actualOutput4DifferentConstructor, bytesToEncrypt4, bytesToEncrypt4.Length);
			#endif // NET6_0_OR_GREATER

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);

			#if NET6_0_OR_GREATER
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1DifferentConstructor);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2DifferentConstructor);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3DifferentConstructor);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4DifferentConstructor);
			#endif // NET6_0_OR_GREATER
		}

		[Test]
		public void Known_CTR_AES128DecryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[16] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToDecrypt1 = new byte[] { 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce };
			byte[] expectedOutput1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] actualOutput1 = new byte[bytesToDecrypt1.Length];

			byte[] bytesToDecrypt2 = new byte[] { 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff };
			byte[] expectedOutput2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] actualOutput2 = new byte[bytesToDecrypt2.Length];

			byte[] bytesToDecrypt3 = new byte[] { 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab };
			byte[] expectedOutput3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] actualOutput3 = new byte[bytesToDecrypt3.Length];

			byte[] bytesToDecrypt4 = new byte[] { 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee };
			byte[] expectedOutput4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] actualOutput4 = new byte[bytesToDecrypt4.Length];

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.DecryptBytes(actualOutput1, bytesToDecrypt1, bytesToDecrypt1.Length);
			aesCtr.DecryptBytes(actualOutput2, bytesToDecrypt2, bytesToDecrypt2.Length);
			aesCtr.DecryptBytes(actualOutput3, bytesToDecrypt3, bytesToDecrypt3.Length);
			aesCtr.DecryptBytes(actualOutput4, bytesToDecrypt4, bytesToDecrypt4.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);
		}

		[Test]
		public void Known_CTR_AES192EncryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[24] { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToEncrypt1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] expectedOutput1 = new byte[] { 0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b };
			byte[] actualOutput1 = new byte[bytesToEncrypt1.Length];

			byte[] bytesToEncrypt2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] expectedOutput2 = new byte[] { 0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94 };
			byte[] actualOutput2 = new byte[bytesToEncrypt2.Length];

			byte[] bytesToEncrypt3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] expectedOutput3 = new byte[] { 0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7 };
			byte[] actualOutput3 = new byte[bytesToEncrypt3.Length];

			byte[] bytesToEncrypt4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] expectedOutput4 = new byte[] { 0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50 };
			byte[] actualOutput4 = new byte[bytesToEncrypt4.Length];

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.EncryptBytes(actualOutput1, bytesToEncrypt1, bytesToEncrypt1.Length);
			aesCtr.EncryptBytes(actualOutput2, bytesToEncrypt2, bytesToEncrypt2.Length);
			aesCtr.EncryptBytes(actualOutput3, bytesToEncrypt3, bytesToEncrypt3.Length);
			aesCtr.EncryptBytes(actualOutput4, bytesToEncrypt4, bytesToEncrypt4.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);
		}

		[Test]
		public void Known_CTR_AES192DecryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[24] { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToDecrypt1 = new byte[] { 0x1a, 0xbc, 0x93, 0x24, 0x17, 0x52, 0x1c, 0xa2, 0x4f, 0x2b, 0x04, 0x59, 0xfe, 0x7e, 0x6e, 0x0b };
			byte[] expectedOutput1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] actualOutput1 = new byte[bytesToDecrypt1.Length];

			byte[] bytesToDecrypt2 = new byte[] { 0x09, 0x03, 0x39, 0xec, 0x0a, 0xa6, 0xfa, 0xef, 0xd5, 0xcc, 0xc2, 0xc6, 0xf4, 0xce, 0x8e, 0x94 };
			byte[] expectedOutput2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] actualOutput2 = new byte[bytesToDecrypt2.Length];

			byte[] bytesToDecrypt3 = new byte[] { 0x1e, 0x36, 0xb2, 0x6b, 0xd1, 0xeb, 0xc6, 0x70, 0xd1, 0xbd, 0x1d, 0x66, 0x56, 0x20, 0xab, 0xf7 };
			byte[] expectedOutput3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] actualOutput3 = new byte[bytesToDecrypt3.Length];

			byte[] bytesToDecrypt4 = new byte[] { 0x4f, 0x78, 0xa7, 0xf6, 0xd2, 0x98, 0x09, 0x58, 0x5a, 0x97, 0xda, 0xec, 0x58, 0xc6, 0xb0, 0x50 };
			byte[] expectedOutput4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] actualOutput4 = new byte[bytesToDecrypt4.Length];

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.DecryptBytes(actualOutput1, bytesToDecrypt1, bytesToDecrypt1.Length);
			aesCtr.DecryptBytes(actualOutput2, bytesToDecrypt2, bytesToDecrypt2.Length);
			aesCtr.DecryptBytes(actualOutput3, bytesToDecrypt3, bytesToDecrypt3.Length);
			aesCtr.DecryptBytes(actualOutput4, bytesToDecrypt4, bytesToDecrypt4.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);
		}

		[Test]
		public void Known_CTR_AES256EncryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[32] { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToEncrypt1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] expectedOutput1 = new byte[] { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28 };
			byte[] actualOutput1 = new byte[bytesToEncrypt1.Length];

			byte[] bytesToEncrypt2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] expectedOutput2 = new byte[] { 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5 };
			byte[] actualOutput2 = new byte[bytesToEncrypt2.Length];

			byte[] bytesToEncrypt3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] expectedOutput3 = new byte[] { 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d };
			byte[] actualOutput3 = new byte[bytesToEncrypt3.Length];

			byte[] bytesToEncrypt4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] expectedOutput4 = new byte[] { 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
			byte[] actualOutput4 = new byte[bytesToEncrypt4.Length];

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.EncryptBytes(actualOutput1, bytesToEncrypt1, bytesToEncrypt1.Length);
			aesCtr.EncryptBytes(actualOutput2, bytesToEncrypt2, bytesToEncrypt2.Length);
			aesCtr.EncryptBytes(actualOutput3, bytesToEncrypt3, bytesToEncrypt3.Length);
			aesCtr.EncryptBytes(actualOutput4, bytesToEncrypt4, bytesToEncrypt4.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);
		}

		[Test]
		public void Known_CTR_AES256DecryptTest()
		{
			// Arrange

			// These are from https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf (F.5 CTR Example Vectors )
			byte[] key = new byte[32] { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			byte[] bytesToDecrypt1 = new byte[] { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28 };
			byte[] expectedOutput1 = new byte[] { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
			byte[] actualOutput1 = new byte[bytesToDecrypt1.Length];

			byte[] bytesToDecrypt2 = new byte[] { 0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5 };
			byte[] expectedOutput2 = new byte[] { 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 };
			byte[] actualOutput2 = new byte[bytesToDecrypt2.Length];

			byte[] bytesToDecrypt3 = new byte[] { 0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d };
			byte[] expectedOutput3 = new byte[] { 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef };
			byte[] actualOutput3 = new byte[bytesToDecrypt3.Length];

			byte[] bytesToDecrypt4 = new byte[] { 0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };
			byte[] expectedOutput4 = new byte[] { 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
			byte[] actualOutput4 = new byte[bytesToDecrypt4.Length];

			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.DecryptBytes(actualOutput1, bytesToDecrypt1, bytesToDecrypt1.Length);
			aesCtr.DecryptBytes(actualOutput2, bytesToDecrypt2, bytesToDecrypt2.Length);
			aesCtr.DecryptBytes(actualOutput3, bytesToDecrypt3, bytesToDecrypt3.Length);
			aesCtr.DecryptBytes(actualOutput4, bytesToDecrypt4, bytesToDecrypt4.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput1, actualOutput1);
			CollectionAssert.AreEqual(expectedOutput2, actualOutput2);
			CollectionAssert.AreEqual(expectedOutput3, actualOutput3);
			CollectionAssert.AreEqual(expectedOutput4, actualOutput4);
		}

		[Test]
		public void Known_Text_CTR_AES128Test()
		{
			// Arrange
			// These values are from https://github.com/ricmoo/aes-js/blob/master/README.md
			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };
			
			byte[] bytesToEncrypt = System.Text.Encoding.UTF8.GetBytes("Text may be any length you wish, no padding is required.");
			byte[] expectedOutput = new byte[] { 0xa3, 0x38, 0xed, 0xa3, 0x87, 0x4e, 0xd8, 0x84, 0xb6, 0x19, 0x91, 0x50, 0xd3, 0x6f, 0x49, 0x98, 0x8c, 0x90, 0xf5, 0xc4, 0x7f, 0xe7, 0x79, 0x2b, 0x0c, 0xf8, 0xc7, 0xf7, 0x7e, 0xef, 0xfd, 0x87, 0xea, 0x14, 0x5b, 0x73, 0xe8, 0x2a, 0xef, 0xcf, 0x20, 0x76, 0xf8, 0x81, 0xc8, 0x88, 0x79, 0xe4, 0xe2, 0x5b, 0x1d, 0x7b, 0x24, 0xba, 0x27, 0x88 };
			byte[] actualOutput = new byte[expectedOutput.Length];
			// Act
			AES_CTR aesCtr = new AES_CTR(key, initialCounter);
			aesCtr.EncryptBytes(actualOutput, bytesToEncrypt, bytesToEncrypt.Length);

			// Assert
			CollectionAssert.AreEqual(expectedOutput, actualOutput);
		}

		[Test]
		public void TestOverloads()
		{
			// Arrange
			Random rng = new Random(Seed: 1337);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			byte[] encryptedContent2 = null;
			byte[] decryptedContent2 = null;

			byte[] encryptedContent3 = null;
			byte[] decryptedContent3 = null;

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			AES_CTR forEncrypting2 = null;
			AES_CTR forDecrypting2 = null;

			AES_CTR forEncrypting3 = null;
			AES_CTR forDecrypting3 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			forEncrypting2 = new AES_CTR(key, initialCounter);
			forDecrypting2 = new AES_CTR(key, initialCounter);

			forEncrypting3 = new AES_CTR(key, initialCounter);
			forDecrypting3 = new AES_CTR(key, initialCounter);

			forEncrypting1.EncryptBytes(encryptedContent1, randomContent);
			forDecrypting1.DecryptBytes(decryptedContent1, encryptedContent1);

			encryptedContent2 = forEncrypting2.EncryptBytes(randomContent, randomContent.Length);
			decryptedContent2 = forDecrypting2.DecryptBytes(encryptedContent2, encryptedContent2.Length);

			encryptedContent3 = forEncrypting3.EncryptBytes(randomContent);
			decryptedContent3 = forDecrypting3.DecryptBytes(encryptedContent3);

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);

			CollectionAssert.AreEqual(randomContent, decryptedContent2);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent2);

			CollectionAssert.AreEqual(randomContent, decryptedContent3);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent3);
		}

		[Test]
		public void TestOverloadsNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 1337);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 13339;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			byte[] encryptedContent2 = null;
			byte[] decryptedContent2 = null;

			byte[] encryptedContent3 = null;
			byte[] decryptedContent3 = null;

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			AES_CTR forEncrypting2 = null;
			AES_CTR forDecrypting2 = null;

			AES_CTR forEncrypting3 = null;
			AES_CTR forDecrypting3 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			forEncrypting2 = new AES_CTR(key, initialCounter);
			forDecrypting2 = new AES_CTR(key, initialCounter);

			forEncrypting3 = new AES_CTR(key, initialCounter);
			forDecrypting3 = new AES_CTR(key, initialCounter);

			forEncrypting1.EncryptBytes(encryptedContent1, randomContent);
			forDecrypting1.DecryptBytes(decryptedContent1, encryptedContent1);

			encryptedContent2 = forEncrypting2.EncryptBytes(randomContent, randomContent.Length);
			decryptedContent2 = forDecrypting2.DecryptBytes(encryptedContent2, encryptedContent2.Length);

			encryptedContent3 = forEncrypting3.EncryptBytes(randomContent);
			decryptedContent3 = forDecrypting3.DecryptBytes(encryptedContent3);

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);

			CollectionAssert.AreEqual(randomContent, decryptedContent2);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent2);

			CollectionAssert.AreEqual(randomContent, decryptedContent3);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent3);
		}

		[Test]
		public void TestStreamEncryptDecrypt()
		{
			// Arrange
			Random rng = new Random(Seed: 1339);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			forEncrypting1.EncryptStream(new MemoryStream(encryptedContent1), new MemoryStream(randomContent));
			forDecrypting1.DecryptStream(new MemoryStream(decryptedContent1), new MemoryStream(encryptedContent1));

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);
		}

		[Test]
		public void TestStreamEncryptDecryptNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 1339);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 21111;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			forEncrypting1.EncryptStream(new MemoryStream(encryptedContent1), new MemoryStream(randomContent));
			forDecrypting1.DecryptStream(new MemoryStream(decryptedContent1), new MemoryStream(encryptedContent1));

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);
		}

		[Test]
		public async Task AsyncTestStreamEncryptDecrypt()
		{
			// Arrange
			Random rng = new Random(Seed: 1339);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 4096;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			await forEncrypting1.EncryptStreamAsync(new MemoryStream(encryptedContent1), new MemoryStream(randomContent));
			await forDecrypting1.DecryptStreamAsync(new MemoryStream(decryptedContent1), new MemoryStream(encryptedContent1));

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);
		}

		[Test]
		public async Task AsyncTestStreamEncryptDecryptNonPowerOfTwo()
		{
			// Arrange
			Random rng = new Random(Seed: 1339);

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			const int lengthOfData = 21111;
			byte[] randomContent = new byte[lengthOfData];
			
			byte[] encryptedContent1 = new byte[lengthOfData];
			byte[] decryptedContent1 = new byte[lengthOfData];

			AES_CTR forEncrypting1 = null;
			AES_CTR forDecrypting1 = null;

			// Act
			rng.NextBytes(randomContent);

			forEncrypting1 = new AES_CTR(key, initialCounter);
			forDecrypting1 = new AES_CTR(key, initialCounter);

			await forEncrypting1.EncryptStreamAsync(new MemoryStream(encryptedContent1), new MemoryStream(randomContent));
			await forDecrypting1.DecryptStreamAsync(new MemoryStream(decryptedContent1), new MemoryStream(encryptedContent1));

			// Assert
			CollectionAssert.AreEqual(randomContent, decryptedContent1);
			CollectionAssert.AreNotEqual(randomContent, encryptedContent1);
		}

		[Test]
		public void TestStringToUTF8BytesAndBack()
		{
			// Arrange
			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			string testContent = "this is test content 😊";

			AES_CTR forEncrypting1 = new AES_CTR(key, initialCounter);
			AES_CTR forDecrypting1 = new AES_CTR(key, initialCounter);

			// Act
			byte[] encryptedContent = forEncrypting1.EncryptString(testContent);
			string decryptedString = forDecrypting1.DecryptUTF8ByteArray(encryptedContent);

			// Assert
			Assert.AreEqual(testContent, decryptedString);
		}

		[Test]
		public void TestLittleEndianRoundtrip()
		{
			// Arrange
			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounterLittle = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFE };

			string testContent = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean varius tristique convallis. Fusce finibus pharetra aliquam. Vivamus eleifend sapien ut enim efficitur, sed auctor tortor aliquam. Aliquam eget rutrum tortor. Cras eget nisi commodo, commodo lorem quis, aliquam arcu. Nulla facilisis purus ligula, sit amet gravida nibh ultricies eu.";

			AES_CTR forEncryptingLittle = new AES_CTR(key, initialCounterLittle, littleEndian: true);
			AES_CTR forDecryptingLittle = new AES_CTR(key, initialCounterLittle, littleEndian: true);

			// Act
			byte[] encryptedContentLittle = forEncryptingLittle.EncryptString(testContent);
			string decryptedStringLittle = forDecryptingLittle.DecryptUTF8ByteArray(encryptedContentLittle);

			// Assert
			Assert.AreEqual(testContent, decryptedStringLittle);
		}

		[Test]
		public void TestLittleEndianProduceDifferentResults()
		{
			// Arrange
			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounterBig = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			byte[] initialCounterLittle = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

			byte[] input = new byte[32] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 }; 

			AES_CTR forEncryptingBig = new AES_CTR(key, initialCounterBig);
			AES_CTR forDecryptingBig = new AES_CTR(key, initialCounterBig);

			AES_CTR forEncryptingLittle = new AES_CTR(key, initialCounterLittle, littleEndian: true);
			AES_CTR forDecryptingLittle = new AES_CTR(key, initialCounterLittle, littleEndian: true);

			// Act
			byte[] encryptedContentBig = forEncryptingBig.EncryptBytes(input);
			byte[] decryptedContentBig = forDecryptingBig.DecryptBytes(encryptedContentBig);

			byte[] encryptedContentLittle = forEncryptingLittle.EncryptBytes(input);
			byte[] decryptedContentLittle = forDecryptingLittle.DecryptBytes(encryptedContentLittle);

			// Assert
			CollectionAssert.AreEqual(input, decryptedContentBig);
			CollectionAssert.AreEqual(input, decryptedContentLittle);
			CollectionAssert.AreEqual(encryptedContentBig.Take(16), encryptedContentLittle.Take(16), "First 16 bytes should be equal");
			CollectionAssert.AreNotEqual(encryptedContentBig.Skip(16).Take(16), encryptedContentLittle.Skip(16).Take(16), "Last 16 bytes should not be equal since counter byte array increases from different positions");
		}

		[Test]
		public void TestDisposable()
		{
			// Arrange
			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			byte[] content = new byte[] { 11, 24, 22, 134, 234, 33, 4, 14, 34, 56, 23 };
			int contentLength = content.Length;

			byte[] encrypted = new byte[contentLength];
			byte[] decrypted = new byte[contentLength];

			// Act
			using (AES_CTR forEncrypting = new AES_CTR(key, initialCounter))
			{
				forEncrypting.EncryptBytes(encrypted, content, contentLength);
			}

			using (AES_CTR forDecrypting = new AES_CTR(key, initialCounter))
			{
				forDecrypting.DecryptBytes(decrypted, encrypted, contentLength);
			}

			// Assert
			CollectionAssert.AreEqual(content, decrypted);
		}
	}
}