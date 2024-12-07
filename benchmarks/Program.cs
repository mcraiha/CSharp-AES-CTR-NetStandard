using System;
using System.IO; // For memorystreams

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using CS_AES_CTR;

namespace benchmarks
{
	[MemoryDiagnoser]
	public class OriginalVsAdjusted
	{
		private const int dataLength1 = 64;
		private const int dataLength2 = 1024;
		private const int dataLength3 = 1024*1024;

		private readonly byte[] data1;
		private readonly byte[] data2;
		private readonly byte[] data3;

		private readonly AES_CTR thisProjectNoSimd1 = null;
		private readonly AES_CTR thisProjectNoSimd2 = null;
		private readonly AES_CTR thisProjectNoSimd3 = null;

		private readonly AES_CTR thisProjectSimd1 = null;
		private readonly AES_CTR thisProjectSimd2 = null;
		private readonly AES_CTR thisProjectSimd3 = null;

		private static readonly byte[] key = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
		
		private static readonly byte[] initialCounter = new byte[16] { 0x00, 0x09, 0x00, 0x00, 0xFF, 0x20, 0x12, 0x00, 0x00, 0x8b, 0x00, 0x02, 0x0c, 0x06, 0x07, 0x01};
		

		private byte[] outputForStackOverflow1;
		private byte[] outputForStackOverflow2;
		private byte[] outputForStackOverflow3;

		private byte[] outputForthisProjectNoSimd1;
		private byte[] outputForthisProjectNoSimd2;
		private byte[] outputForthisProjectNoSimd3;

		private byte[] outputForthisProjectSimd1;
		private byte[] outputForthisProjectSimd2;
		private byte[] outputForthisProjectSimd3;

		public OriginalVsAdjusted()
		{
			// Arrays for outputs
			this.outputForStackOverflow1 = new byte[dataLength1];
			this.outputForStackOverflow2 = new byte[dataLength2];
			this.outputForStackOverflow3 = new byte[dataLength3];

			this.outputForthisProjectNoSimd1 = new byte[dataLength1];
			this.outputForthisProjectNoSimd2 = new byte[dataLength2];
			this.outputForthisProjectNoSimd3 = new byte[dataLength3];

			this.outputForthisProjectSimd1 = new byte[dataLength1];
			this.outputForthisProjectSimd2 = new byte[dataLength2];
			this.outputForthisProjectSimd3 = new byte[dataLength3];

			// Generate inputs
			Random rng = new Random(Seed: 1337);

			this.data1 = new byte[dataLength1];
			rng.NextBytes(this.data1);

			this.data2 = new byte[dataLength2];
			rng.NextBytes(this.data2);

			this.data3 = new byte[dataLength3];
			rng.NextBytes(this.data3);

			// Set encrypters
			this.thisProjectNoSimd1 = new AES_CTR(key, initialCounter);
			this.thisProjectNoSimd2 = new AES_CTR(key, initialCounter);
			this.thisProjectNoSimd3 = new AES_CTR(key, initialCounter);

			this.thisProjectSimd1 = new AES_CTR(key, initialCounter);
			this.thisProjectSimd2 = new AES_CTR(key, initialCounter);
			this.thisProjectSimd3 = new AES_CTR(key, initialCounter);
		}

	#region 64 bytes
		[Benchmark]
		public void SO_64_Bytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow1), new MemoryStream(this.data1));

		[Benchmark]
		public void This_Project_No_Simd_64_Bytes() => this.thisProjectNoSimd1.EncryptBytes(this.outputForthisProjectNoSimd1, this.data1, dataLength1, useSIMD: false);

		[Benchmark]
		public void This_Project_Simd_64_Bytes() => this.thisProjectSimd1.EncryptBytes(this.outputForthisProjectSimd1, this.data1, dataLength1, useSIMD: true);

	#endregion // 64 bytes

	#region 1024 bytes
		[Benchmark]
		public void SO1024Bytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow2), new MemoryStream(this.data2));

		[Benchmark]
		public void This_Project_No_Simd_1024_Bytes() => this.thisProjectNoSimd2.EncryptBytes(this.outputForthisProjectNoSimd2, this.data2, dataLength2, useSIMD: false);

		[Benchmark]
		public void This_Project_Simd_1024_Bytes() => this.thisProjectSimd2.EncryptBytes(this.outputForthisProjectSimd2, this.data2, dataLength2, useSIMD: true);

	#endregion // 1024 bytes

	#region 1 MiB
		[Benchmark]
		public void SO1MiBBytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow3), new MemoryStream(this.data3));

		[Benchmark]
		public void This_Project_No_Simd_1_Mib_Bytes() => this.thisProjectNoSimd3.EncryptBytes(this.outputForthisProjectNoSimd3, this.data3, dataLength3, useSIMD: false);

		[Benchmark]
		public void This_Project_Simd_1_Mib_Bytes() => this.thisProjectSimd3.EncryptBytes(this.outputForthisProjectSimd3, this.data3, dataLength3, useSIMD: true);

	#endregion // 1 MiB
	}

	class Program
	{
		static void Main(string[] args)
		{
			var summary = BenchmarkRunner.Run<OriginalVsAdjusted>();
		}
	}
}
