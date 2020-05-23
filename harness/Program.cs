using System;
using System.IO;
using System.Diagnostics;
using CS_AES_CTR;

namespace harness
{
	class Program
	{
		static void Main(string[] args)
		{
			TextWriter errorWriter = Console.Error;

			int limit = 0;

			if(args.Length > 1 && !int.TryParse(args[1], out limit))
			{
				errorWriter.WriteLine($"{args[1]} is not a valid integer");
				return;
			}

			errorWriter.WriteLine("Starting throughput harness...");

			if (limit > 0)
			{
				errorWriter.WriteLine($"Limit is {limit} bytes");
			}
			else
			{
				errorWriter.WriteLine($"No byte limit");
			}

			byte[] key = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
			byte[] initialCounter = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05 };

			int bufferSize = 1024;

			int bytesProcessed = 0;

			byte[] buffer = new byte[bufferSize];

			Stopwatch stopwatch = new Stopwatch();
			stopwatch.Start();

			using (AES_CTR forEncrypting = new AES_CTR(key, initialCounter))
			{
				// Read from input stream as long as there is something
				using (Stream inputStream = Console.OpenStandardInput())
				{
					// Write to output stream
					using (Stream outputStream = Console.OpenStandardOutput())
					{
						int readAmount = inputStream.Read(buffer, 0, bufferSize);
						while (readAmount > 0 && limit > -1)
						{
							outputStream.Write(forEncrypting.EncryptBytes(buffer, readAmount));

							if (limit > 0)
							{
								limit -= readAmount;
							}

							bytesProcessed += readAmount;

							readAmount = inputStream.Read(buffer, 0, bufferSize);
						}
					}
				}
			}

			stopwatch.Stop();
			errorWriter.WriteLine($"Processed {bytesProcessed} bytes in {stopwatch.Elapsed.TotalSeconds} seconds");
		}
	}
}
