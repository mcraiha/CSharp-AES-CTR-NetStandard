using System;
using System.IO;
using System.Security.Cryptography;

namespace CS_AES_CTR
{
	public sealed class AES_CTR
	{
		/// <summary>
		/// What are allowed key lengths (128, 192 and 256 bits)
		/// </summary>
		/// <value></value>
		public static readonly int[] allowedKeyLengths = new int[3] { 16, 24, 32 };

		/// <summary>
		/// What is allowed initial counter length
		/// </summary>
		public const int allowedCounterLength = 16;

		/// <summary>
		/// Only allowed Initialization vector length
		/// </summary>
		private const int ivLength = 16;

		/// <summary>
		/// How many bytes are processed at time
		/// </summary>
		private const int processBytesAtTime = 16;

		/// <summary>
		/// Internal counter
		/// </summary>
		private byte[] counter = new byte[allowedCounterLength];

		/// <summary>
		/// Internal transformer for doing encrypt/decrypt transforming
		/// </summary>
		private readonly ICryptoTransform counterEncryptor;

		/// <summary>
		/// AES_CTR constructor
		/// </summary>
		/// <param name="key">Key as byte array</param>
		/// <param name="initialCounter">Initial counter as byte array</param>
		public AES_CTR(byte[] key, byte[] initialCounter)
		{
			if (key == null) 
			{
				throw new ArgumentNullException("Key is null");
			}

			if (!Array.Exists(allowedKeyLengths, allowed => allowed == key.Length))
			{
				throw new ArgumentException($"Key length must be {allowedKeyLengths[0]}, {allowedKeyLengths[1]} or {allowedKeyLengths[2]} bytes. Actual: {key.Length}");
			}

			if (initialCounter == null)
			{
				throw new ArgumentNullException("Initial counter is null");
			}

			if (allowedCounterLength != initialCounter.Length)
			{
				throw new ArgumentException($"Initial counter must be {allowedCounterLength} bytes");
			}

			SymmetricAlgorithm aes = new AesManaged { Mode = CipherMode.ECB, Padding = PaddingMode.None };
			
			// Create copy of initial counter since state is kept during the lifetime of AES_CTR
			Buffer.BlockCopy(initialCounter, 0, this.counter, 0, allowedCounterLength);

			// Initialization vector is always full of zero bytes in CTR mode
			var zeroIv = new byte[ivLength];
			this.counterEncryptor = aes.CreateEncryptor(key, zeroIv);
		}

		#region Encrypt

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		public void EncryptBytes(byte[] output, byte[] input, int numBytes)
		{
			WorkBytes(output, input, numBytes);
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		public void EncryptBytes(byte[] output, byte[] input)
		{
			WorkBytes(output, input, input.Length);
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptBytes(byte[] input, int numBytes)
		{
			byte[] returnArray = new byte[numBytes];
			WorkBytes(returnArray, input, numBytes);
			return returnArray;
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptBytes(byte[] input)
		{
			byte[] returnArray = new byte[input.Length];
			WorkBytes(returnArray, input, input.Length);
			return returnArray;
		}

		/// <summary>
		/// Encrypt string as UTF8 byte array, returns byte array that is allocated by method.
		/// </summary>
		/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
		/// <param name="input">Input string</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptString(string input)
		{
			byte[] utf8Bytes = System.Text.Encoding.UTF8.GetBytes(input);
			byte[] returnArray = new byte[utf8Bytes.Length];

			WorkBytes(returnArray, utf8Bytes, utf8Bytes.Length);
			return returnArray;
		}

		#endregion // Encrypt


		#region Decrypt

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		public void DecryptBytes(byte[] output, byte[] input, int numBytes)
		{
			WorkBytes(output, input, numBytes);
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		public void DecryptBytes(byte[] output, byte[] input)
		{
			WorkBytes(output, input, input.Length);
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		/// <returns>Byte array that contains decrypted bytes</returns>
		public byte[] DecryptBytes(byte[] input, int numBytes)
		{
			byte[] returnArray = new byte[numBytes];
			WorkBytes(returnArray, input, numBytes);
			return returnArray;
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <returns>Byte array that contains decrypted bytes</returns>
		public byte[] DecryptBytes(byte[] input)
		{
			byte[] returnArray = new byte[input.Length];
			WorkBytes(returnArray, input, input.Length);
			return returnArray;
		}

		/// <summary>
		/// Decrypt UTF8 byte array to string.
		/// </summary>
		/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
		/// <param name="input">Byte array</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public string DecryptUTF8ByteArray(byte[] input)
		{
			byte[] tempArray = new byte[input.Length];

			WorkBytes(tempArray, input, input.Length);
			return System.Text.Encoding.UTF8.GetString(tempArray);
		}

		#endregion // Decrypt

		private void WorkBytes(byte[] output, byte[] input, int numBytes)
		{
			// Check parameters
			if (input == null)
			{
				throw new ArgumentNullException("input", "Input cannot be null");
			}

			if (output == null)
			{
				throw new ArgumentNullException("output", "Output cannot be null");
			}

			if (numBytes < 0 || numBytes > input.Length) 
			{
				throw new ArgumentOutOfRangeException("numBytes", "The number of bytes to read must be between [0..input.Length]");
			}

			if (output.Length < numBytes)
			{
				throw new ArgumentOutOfRangeException("output", $"Output byte array should be able to take at least {numBytes}");
			}

			int outputOffset = 0;
			int inputOffset = 0;

			while (numBytes > 0)
			{
				// Generate new XOR mask for next processBytesAtTime
				var tmp = new byte[allowedCounterLength];
				counterEncryptor.TransformBlock(counter, 0, counter.Length, tmp, 0);

				// Increase counter (basically this increases the last index first and continues to one before that if 255 -> 0, better solution would be to use uint128, but it does not exist yet)
				for (int i = counter.Length - 1; i >= 0; i--)
				{
					if (++counter[i] != 0)
					{
						break;
					}
				}

				// Last bytes
				if (numBytes <= processBytesAtTime) 
				{
					for (int i = 0; i < numBytes; i++) 
					{
						output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
					}
					return;
				}

				for (int i = 0; i < processBytesAtTime; i++ ) 
				{
					output[i + outputOffset] = (byte) (input[i + inputOffset] ^ tmp[i]);
				}

				numBytes -= processBytesAtTime;
				outputOffset += processBytesAtTime;
				inputOffset += processBytesAtTime;
			}
		}
	}
}
