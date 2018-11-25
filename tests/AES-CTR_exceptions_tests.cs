using NUnit.Framework;
using System.IO;
using CS_AES_CTR;
using System;

namespace Tests
{
	public class ExceptionTests
	{
		[SetUp]
		public void Setup()
		{

		}


		[Test]
		public void InvalidConstructorKeysTest()
		{
			// Arrange
			byte[] invalidKey1 = null;
			byte[] invalidKey2 = new byte[0];
			byte[] invalidKey3 = new byte[1];
			byte[] invalidKey4 = new byte[15];
			byte[] invalidKey5 = new byte[33];
			byte[] invalidKey6 = new byte[1024];

			byte[] initialCounterValid = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			// Act

			// Assert
			Assert.That(() => new AES_CTR(invalidKey1, initialCounterValid), Throws.ArgumentNullException);
			Assert.That(() => new AES_CTR(invalidKey2, initialCounterValid), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(invalidKey3, initialCounterValid), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(invalidKey4, initialCounterValid), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(invalidKey5, initialCounterValid), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(invalidKey6, initialCounterValid), Throws.ArgumentException);
		}

		[Test]
		public void InvalidConstructorCounterTest()
		{
			// Arrange
			byte[] key = new byte[16] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };

			byte[] initialCounterInvalid1 = null;
			byte[] initialCounterInvalid2 = new byte[0];
			byte[] initialCounterInvalid3 = new byte[15];
			byte[] initialCounterInvalid4 = new byte[24];

			// Act

			// Assert
			Assert.That(() => new AES_CTR(key, initialCounterInvalid1), Throws.ArgumentNullException);
			Assert.That(() => new AES_CTR(key, initialCounterInvalid2), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(key, initialCounterInvalid3), Throws.ArgumentException);
			Assert.That(() => new AES_CTR(key, initialCounterInvalid4), Throws.ArgumentException);
		}

		[Test]
		public void FailedInputOrOutput()
		{
			// Arrange
			byte[] key = new byte[16] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
			byte[] initialCounter = new byte[] { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

			const int lengthOfData = 128;

			byte[] validOutputArray = new byte[lengthOfData];
			byte[] validInputArray = new byte[lengthOfData];
			
			byte[] invalidInput1 = null;
			byte[] invalidOutput1 = null;

			AES_CTR nullInput = new AES_CTR(key, initialCounter);
			AES_CTR nullOutput = new AES_CTR(key, initialCounter);

			// Act

			// Assert
			Assert.That(() => nullInput.EncryptBytes(validOutputArray, invalidInput1, lengthOfData), Throws.ArgumentNullException);
			Assert.That(() => nullInput.EncryptBytes(invalidOutput1, validInputArray, lengthOfData), Throws.ArgumentNullException);

			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(validOutputArray, validInputArray, -1));
			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(validOutputArray, validInputArray, lengthOfData + 1));
			Assert.Throws<ArgumentOutOfRangeException>(() => nullInput.EncryptBytes(new byte[lengthOfData/2], validInputArray, lengthOfData));
		}
	}
}