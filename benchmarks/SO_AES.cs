// This code is copied from https://stackoverflow.com/a/51188472/4886769
// It is licensed under cc-wiki (aka cc-by-sa) license, see https://stackoverflow.blog/2009/06/25/attribution-required/
using System;
using System.IO; // For Streams
using System.Security.Cryptography;
using System.Collections.Generic;

namespace SO_AES
{
	public class SO_AES_CTR
	{
		public static void AesCtrTransform(byte[] key, byte[] salt, Stream inputStream, Stream outputStream)
		{
			SymmetricAlgorithm aes =
				new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };

			int blockSize = aes.BlockSize / 8;

			if (salt.Length != blockSize)
			{
				throw new ArgumentException(
					string.Format(
						"Salt size must be same as block size (actual: {0}, expected: {1})",
						salt.Length, blockSize));
			}

			byte[] counter = (byte[])salt.Clone();

			Queue<byte> xorMask = new Queue<byte>();

			var zeroIv = new byte[blockSize];
			ICryptoTransform counterEncryptor = aes.CreateEncryptor(key, zeroIv);

			int b;
			while ((b = inputStream.ReadByte()) != -1)
			{
				if (xorMask.Count == 0)
				{
					var counterModeBlock = new byte[blockSize];

					counterEncryptor.TransformBlock(
						counter, 0, counter.Length, counterModeBlock, 0);

					for (var i2 = counter.Length - 1; i2 >= 0; i2--)
					{
						if (++counter[i2] != 0)
						{
							break;
						}
					}

					foreach (var b2 in counterModeBlock)
					{
						xorMask.Enqueue(b2);
					}
				}

				var mask = xorMask.Dequeue();
				outputStream.WriteByte((byte)(((byte)b) ^ mask));
			}
		}
	}
}