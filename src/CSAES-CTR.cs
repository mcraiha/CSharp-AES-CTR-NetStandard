using System;
using System.Security.Cryptography;

namespace CS_AES_CTR
{
	/// <summary>
	/// Class that can be used for AES CTR encryption / decryption
	/// </summary>
	public sealed class AES_CTR : IDisposable
	{
		/// <summary>
		/// What are allowed key lengths in bytes (128, 192 and 256 bits)
		/// </summary>
		/// <value></value>
		public static readonly int[] allowedKeyLengths = new int[3] { 16, 24, 32 };

		/// <summary>
		/// What is allowed initial counter length in bytes
		/// </summary>
		public const int allowedCounterLength = 16;

		/// <summary>
		/// Only allowed Initialization vector length in bytes
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
		/// Determines if the objects in this class have been disposed of. Set to true by the Dispose() method.
		/// </summary>
		private bool isDisposed;

		/// <summary>
		/// AES_CTR constructor
		/// </summary>
		/// <param name="key">Key as byte array. (128, 192 or 256 bits)</param>
		/// <param name="initialCounter">Initial counter as byte array. 16 bytes</param>
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

			this.isDisposed = false;

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

			if (isDisposed) 
			{
				throw new ObjectDisposedException("state", "AES_CTR has already been disposed");
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


		#region Destructor and Disposer

		/// <summary>
		/// Clear and dispose of the internal variables. The finalizer is only called if Dispose() was never called on this cipher.
		/// </summary>
		~AES_CTR() 
		{
			Dispose(false);
		}

		/// <summary>
		/// Clear and dispose of the internal state. Also request the GC not to call the finalizer, because all cleanup has been taken care of.
		/// </summary>
		public void Dispose() 
		{
			Dispose(true);
			/*
			 * The Garbage Collector does not need to invoke the finalizer because Dispose(bool) has already done all the cleanup needed.
			 */
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// This method should only be invoked from Dispose() or the finalizer. This handles the actual cleanup of the resources.
		/// </summary>
		/// <param name="disposing">
		/// Should be true if called by Dispose(); false if called by the finalizer
		/// </param>
		private void Dispose(bool disposing) 
		{
			if (!isDisposed) 
			{
				if (disposing) 
				{
					/* Cleanup managed objects by calling their Dispose() methods */
					if (this.counterEncryptor != null)
					{
						this.counterEncryptor.Dispose();
					}
				}

				/* Cleanup here */
				if (this.counter != null) 
				{
					Array.Clear(this.counter, 0, this.counter.Length);
				}

				this.counter = null;				
			}

			isDisposed = true;
		}

		#endregion // Destructor and Disposer
	}
}
