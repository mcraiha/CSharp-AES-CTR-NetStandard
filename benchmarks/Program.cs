using System;
using System.IO; // For memorystreams

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

using CS_AES_CTR;

namespace benchmarks
{
    public class OriginalVsAdjusted
    {
        private const int dataLength1 = 64;
        private const int dataLength2 = 1024;
        private const int dataLength3 = 1024*1024;

        private readonly byte[] data1;
        private readonly byte[] data2;
        private readonly byte[] data3;

        private readonly AES_CTR thisProject1 = null;
        private readonly AES_CTR thisProject2 = null;
        private readonly AES_CTR thisProject3 = null;

        private static readonly byte[] key = new byte[16] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
        
        private static readonly byte[] initialCounter = new byte[16] { 0x00, 0x09, 0x00, 0x00, 0xFF, 0x20, 0x12, 0x00, 0x00, 0x8b, 0x00, 0x02, 0x0c, 0x06, 0x07, 0x01};
        

        private byte[] outputForStackOverflow1;
        private byte[] outputForStackOverflow2;
        private byte[] outputForStackOverflow3;

        private byte[] outputForthisProject1;
        private byte[] outputForthisProject2;
        private byte[] outputForthisProject3;

        public OriginalVsAdjusted()
        {
            // Arrays for outputs
            this.outputForStackOverflow1 = new byte[dataLength1];
            this.outputForStackOverflow2 = new byte[dataLength2];
            this.outputForStackOverflow3 = new byte[dataLength3];

            this.outputForthisProject1 = new byte[dataLength1];
            this.outputForthisProject2 = new byte[dataLength2];
            this.outputForthisProject3 = new byte[dataLength3];

            // Generate inputs
            Random rng = new Random(Seed: 1337);

            this.data1 = new byte[dataLength1];
            rng.NextBytes(this.data1);

            this.data2 = new byte[dataLength2];
            rng.NextBytes(this.data2);

            this.data3 = new byte[dataLength3];
            rng.NextBytes(this.data3);

            // Set encrypters
            this.thisProject1 = new AES_CTR(key, initialCounter);
            this.thisProject2 = new AES_CTR(key, initialCounter);
            this.thisProject3 = new AES_CTR(key, initialCounter);
        }

    #region 64 bytes
        [Benchmark]
        public void SO64Bytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow1), new MemoryStream(this.data1));

        [Benchmark]
        public void ThisProject64Bytes() => this.thisProject1.EncryptBytes(this.outputForthisProject1, this.data1, dataLength1);

    #endregion // 64 bytes

    #region 1024 bytes
        [Benchmark]
        public void SO1024Bytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow2), new MemoryStream(this.data2));

        [Benchmark]
        public void ThisProject1024Bytes() => this.thisProject2.EncryptBytes(this.outputForthisProject2, this.data2, dataLength2);

    #endregion // 1024 bytes

    #region 1 MiB
        [Benchmark]
        public void SO1MiBBytes() => SO_AES.SO_AES_CTR.AesCtrTransform(key, initialCounter, new MemoryStream(this.outputForStackOverflow3), new MemoryStream(this.data3));

        [Benchmark]
        public void ThisProject1MibBytes() => this.thisProject3.EncryptBytes(this.outputForthisProject3, this.data3, dataLength3);

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
