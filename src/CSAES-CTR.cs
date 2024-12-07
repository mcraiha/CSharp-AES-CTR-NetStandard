using System;
using System.IO;
using System.Collections.Immutable;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.Intrinsics;
using System.Runtime.CompilerServices; // For MethodImplOptions.AggressiveInlining

namespace CS_AES_CTR;

/// <summary>
/// Class that can be used for AES CTR encryption / decryption
/// </summary>
public sealed class AES_CTR : IDisposable
{
	/// <summary>
	/// What are allowed key lengths in bytes (128, 192 and 256 bits)
	/// </summary>
	/// <value></value>
	public static readonly ImmutableArray<int> allowedKeyLengths = [16, 24, 32];

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
	private readonly byte[] counter = new byte[allowedCounterLength];

	/// <summary>
	/// Internal transformer for doing encrypt/decrypt transforming
	/// </summary>
	private readonly ICryptoTransform counterEncryptor;

	/// <summary>
	/// Determines if the objects in this class have been disposed of. Set to true by the Dispose() method.
	/// </summary>
	private bool isDisposed;

	/// <summary>
	/// Changes counter behaviour according endianess.
	/// </summary>
	private readonly bool isLittleEndian;

	/// <summary>
	/// AES_CTR constructor
	/// </summary>
	/// <param name="key">Key as readonlyspan. (128, 192 or 256 bits)</param>
	/// <param name="initialCounter">Initial counter as readonlyspan. 16 bytes</param>
	/// <param name="littleEndian">Is initial counter little endian (default false)</param>
	/// <returns></returns>
	public AES_CTR(ReadOnlySpan<byte> key, ReadOnlySpan<byte> initialCounter, bool littleEndian = false) : this(key.ToArray(), initialCounter.ToArray(), littleEndian)
	{

	}

	/// <summary>
	/// AES_CTR constructor
	/// </summary>
	/// <param name="key">Key as byte array. (128, 192 or 256 bits)</param>
	/// <param name="initialCounter">Initial counter as byte array. 16 bytes</param>
	/// <param name="littleEndian">Is initial counter little endian (default false)</param>
	public AES_CTR(byte[] key, byte[] initialCounter, bool littleEndian = false)
	{
		if (key == null) 
		{
			throw new ArgumentNullException("Key is null");
		}

		if (!allowedKeyLengths.Contains(key.Length))
		{
			throw new ArgumentException($"Key length must be either {allowedKeyLengths[0]}, {allowedKeyLengths[1]} or {allowedKeyLengths[2]} bytes. Actual: {key.Length}");
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

		SymmetricAlgorithm aes = Aes.Create();
		aes.Mode = CipherMode.ECB;
		aes.Padding = PaddingMode.None;
		
		// Create copy of initial counter since state is kept during the lifetime of AES_CTR
		Buffer.BlockCopy(initialCounter, 0, this.counter, 0, allowedCounterLength);

		this.isLittleEndian = littleEndian;

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
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void EncryptBytes(byte[] output, byte[] input, int numBytes, bool useSIMD = true)
	{
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

		this.WorkBytes(output, input, numBytes, useSIMD);
	}

	/// <summary>
	/// Encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
	/// </summary>
	/// <param name="output">Output stream</param>
	/// <param name="input">Input stream</param>
	/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void EncryptStream(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024, bool useSIMD = true)
	{
		this.WorkStreams(output, input, useSIMD, howManyBytesToProcessAtTime);
	}

	/// <summary>
	/// Async encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
	/// </summary>
	/// <param name="output">Output stream</param>
	/// <param name="input">Input stream</param>
	/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns></returns>
	public async Task EncryptStreamAsync(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024, bool useSIMD = true)
	{
		await this.WorkStreamsAsync(output, input, useSIMD, howManyBytesToProcessAtTime);
	}

	/// <summary>
	/// Encrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="output">Output byte array, must have enough bytes</param>
	/// <param name="input">Input byte array</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void EncryptBytes(byte[] output, byte[] input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		if (output == null)
		{
			throw new ArgumentNullException("output", "Output cannot be null");
		}

		this.WorkBytes(output, input, input.Length, useSIMD);
	}

	/// <summary>
	/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="input">Input byte array</param>
	/// <param name="numBytes">Number of bytes to encrypt</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains encrypted bytes</returns>
	public byte[] EncryptBytes(byte[] input, int numBytes, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		if (numBytes < 0 || numBytes > input.Length) 
		{
			throw new ArgumentOutOfRangeException("numBytes", "The number of bytes to read must be between [0..input.Length]");
		}

		byte[] returnArray = new byte[numBytes];
		this.WorkBytes(returnArray, input, numBytes, useSIMD);
		return returnArray;
	}

	/// <summary>
	/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="input">Input byte array</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains encrypted bytes</returns>
	public byte[] EncryptBytes(byte[] input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		byte[] returnArray = new byte[input.Length];
		this.WorkBytes(returnArray, input, input.Length, useSIMD);
		return returnArray;
	}

	/// <summary>
	/// Encrypt string as UTF8 byte array, returns byte array that is allocated by method.
	/// </summary>
	/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
	/// <param name="input">Input string</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains encrypted bytes</returns>
	public byte[] EncryptString(string input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		byte[] utf8Bytes = System.Text.Encoding.UTF8.GetBytes(input);
		byte[] returnArray = new byte[utf8Bytes.Length];

		this.WorkBytes(returnArray, utf8Bytes, utf8Bytes.Length, useSIMD);
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
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void DecryptBytes(byte[] output, byte[] input, int numBytes, bool useSIMD = true)
	{
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

		this.WorkBytes(output, input, numBytes, useSIMD);
	}

	/// <summary>
	/// Decrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
	/// </summary>
	/// <param name="output">Output stream</param>
	/// <param name="input">Input stream</param>
	/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void DecryptStream(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024, bool useSIMD = true)
	{
		this.WorkStreams(output, input, useSIMD, howManyBytesToProcessAtTime);
	}

	/// <summary>
	/// Async decrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
	/// </summary>
	/// <param name="output">Output stream</param>
	/// <param name="input">Input stream</param>
	/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns></returns>
	public async Task DecryptStreamAsync(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024, bool useSIMD = true)
	{
		await this.WorkStreamsAsync(output, input, useSIMD, howManyBytesToProcessAtTime);
	}

	/// <summary>
	/// Decrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="output">Output byte array, must have enough bytes</param>
	/// <param name="input">Input byte array</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	public void DecryptBytes(byte[] output, byte[] input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		if (output == null)
		{
			throw new ArgumentNullException("output", "Output cannot be null");
		}

		this.WorkBytes(output, input, input.Length, useSIMD);
	}

	/// <summary>
	/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="input">Input byte array</param>
	/// <param name="numBytes">Number of bytes to encrypt</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains decrypted bytes</returns>
	public byte[] DecryptBytes(byte[] input, int numBytes, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		if (numBytes < 0 || numBytes > input.Length) 
		{
			throw new ArgumentOutOfRangeException("numBytes", "The number of bytes to read must be between [0..input.Length]");
		}

		byte[] returnArray = new byte[numBytes];
		this.WorkBytes(returnArray, input, numBytes, useSIMD);
		return returnArray;
	}

	/// <summary>
	/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
	/// </summary>
	/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
	/// <param name="input">Input byte array</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains decrypted bytes</returns>
	public byte[] DecryptBytes(byte[] input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		byte[] returnArray = new byte[input.Length];
		this.WorkBytes(returnArray, input, input.Length, useSIMD);
		return returnArray;
	}

	/// <summary>
	/// Decrypt UTF8 byte array to string.
	/// </summary>
	/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
	/// <param name="input">Byte array</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <returns>Byte array that contains encrypted bytes</returns>
	public string DecryptUTF8ByteArray(byte[] input, bool useSIMD = true)
	{
		if (input == null)
		{
			throw new ArgumentNullException("input", "Input cannot be null");
		}

		byte[] tempArray = new byte[input.Length];

		this.WorkBytes(tempArray, input, input.Length, useSIMD);
		return System.Text.Encoding.UTF8.GetString(tempArray);
	}

	#endregion // Decrypt

	/// <summary>
	/// Decrypt / Encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
	/// </summary>
	/// <param name="output">Output stream</param>
	/// <param name="input">Input stream</param>
	/// <param name="useSIMD">Use SIMD (true by default)</param>
	/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
	private void WorkStreams(Stream output, Stream input, bool useSIMD, int howManyBytesToProcessAtTime = 1024)
	{
		int readBytes;

		byte[] inputBuffer = new byte[howManyBytesToProcessAtTime];
		byte[] outputBuffer = new byte[howManyBytesToProcessAtTime];

		while ((readBytes = input.Read(inputBuffer, 0, howManyBytesToProcessAtTime)) > 0)
		{
			// Encrypt or decrypt
			this.WorkBytes(output: outputBuffer, input: inputBuffer, numBytes: readBytes, useSIMD);

			// Write buffer
			output.Write(outputBuffer, 0, readBytes);
		}
	}

	private async Task WorkStreamsAsync(Stream output, Stream input, bool useSIMD, int howManyBytesToProcessAtTime = 1024)
	{
		byte[] readBytesBuffer = new byte[howManyBytesToProcessAtTime];
		byte[] writeBytesBuffer = new byte[howManyBytesToProcessAtTime];
		int howManyBytesWereRead = await input.ReadAsync(readBytesBuffer, 0, howManyBytesToProcessAtTime);

		while (howManyBytesWereRead > 0)
		{
			// Encrypt or decrypt
			this.WorkBytes(output: writeBytesBuffer, input: readBytesBuffer, numBytes: howManyBytesWereRead, useSIMD);

			// Write
			await output.WriteAsync(writeBytesBuffer, 0, howManyBytesWereRead);

			// Read more
			howManyBytesWereRead = await input.ReadAsync(readBytesBuffer, 0, howManyBytesToProcessAtTime);
		}		
	}

	private void WorkBytes(byte[] output, byte[] input, int numBytes, bool useSIMD)
	{
		if (isDisposed) 
		{
			throw new ObjectDisposedException("state", "AES_CTR has already been disposed");
		}

		int offset = 0;

		var tmp = new byte[allowedCounterLength];

		int howManyFullLoops = numBytes / processBytesAtTime;
		int tailByteCount = numBytes - (howManyFullLoops * processBytesAtTime);

		for (int loop = 0; loop < howManyFullLoops; loop++) 
		{
			// Generate new XOR mask for next processBytesAtTime
			this.counterEncryptor.TransformBlock(counter, 0, allowedCounterLength, tmp, 0);

			this.IncreaseCounter();

			if (useSIMD)
			{
				// 1 x 16 bytes
				Vector128<byte> inputV = Vector128.Create(input, offset);
				Vector128<byte> tmpV = Vector128.Create(tmp, 0);
				Vector128<byte> outputV = inputV ^ tmpV;
				outputV.CopyTo(output, offset);
			}
			else
			{

				for (int i = 0; i < processBytesAtTime; i++) 
				{
					output[i + offset] = (byte) (input[i + offset] ^ tmp[i]);
				}
			}

			offset += processBytesAtTime;
		}

		// In case there are some bytes left
		if (tailByteCount > 0)
		{
			// Generate new XOR mask for next processBytesAtTime
			this.counterEncryptor.TransformBlock(counter, 0, allowedCounterLength, tmp, 0);

			this.IncreaseCounter();

			for (int i = 0; i < tailByteCount; i++) 
			{
				output[i + offset] = (byte) (input[i + offset] ^ tmp[i]);
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void IncreaseCounter()
	{
		// Increase counter (basically this increases the last index first and continues to one before that if 255 -> 0, better solution would be to use uint128, but it does not exist yet)
		if (this.isLittleEndian)
		{
			// LittleEndian
			for (int i = 0; i < allowedCounterLength; i++)
			{
				if (++counter[i] != 0)
				{
					break;
				}
			}
		}
		else
		{
			// BigEndian
			for (int i = allowedCounterLength - 1; i >= 0; i--)
			{
				if (++counter[i] != 0)
				{
					break;
				}
			}
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
			Array.Clear(this.counter, 0, allowedCounterLength);	
		}

		isDisposed = true;
	}

	#endregion // Destructor and Disposer
}
