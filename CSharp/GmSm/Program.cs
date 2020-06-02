using System;
using System.Text;
using GmSm.Lib;
using Org.BouncyCastle.Utilities.Encoders;

namespace GmSm
{
    class Program
    {
        private static string PubKey =
            "02ab645aa3ecac7845a5fcf6d68953ea613b2d586e2cddd7026ef9ac87d2996e10";

        private static string PriKey = "2c4b9600224612effa2461c5d37bca68dba83f256a4b8830742fce0cca8a9115";

      
        static void Main(string[] args)
        {
            TestSm2Enc();
        }
        public static void TestSm2Enc()
        {
            string testStr = "hello world";
            Console.WriteLine("原始数据 : " + testStr);
            byte[] sourceData = Encoding.ASCII.GetBytes(testStr);
            byte[] pubKey = HexStringToByteArray(PubKey);
            string encStr = SM2Utils.Encrypt(pubKey, sourceData);

            Console.WriteLine("加密后数据 : " + encStr);

            byte[] prik =HexStringToByteArray(PriKey);
            var data = Hex.Decode(Encoding.ASCII.GetBytes(encStr));
            var decodedData = SM2Utils.Decrypt(prik, data);

            var decodedStr = Encoding.ASCII.GetString(decodedData);
            Console.WriteLine("解密后数据 : " + decodedStr);
        }
        private static byte[] HexStringToByteArray(string s)
        {
            s = s.Replace(" ", "");
            byte[] buffer = new byte[s.Length / 2];
            for (int i = 0; i < s.Length; i += 2)
            {
                buffer[i / 2] = (byte)Convert.ToByte(s.Substring(i, 2), 16);
            }
     
            return buffer;
        }
    }
   
}