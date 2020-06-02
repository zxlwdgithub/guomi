using System;
using System.Text;
using GmSm.Lib;
using Org.BouncyCastle.Utilities.Encoders;

namespace GmSm
{
    class Program
    {
        private static string PubKey =
            "041E353292615666BB47F6358D3E893394D34AF30D64875E2E422182C15885D3ECA697C345EED99268D3CAC5F6054780C34433E1BF12EBFF1F744B67A2F6863CFB";

        private static string PriKey = "00FAB34B54C026D158B54C88BC0463CB79B22661C7C870AD2A0455300E05471CE1";

        // 报送文件加密用公钥1 测试阶段无需修改，生产接入时另行发放
        public static readonly string PUB_X_KEY = "dc5f89775f11266dbb166638710463db31a91f7b3061aeddb69444d5ec748929";

        // 报送文件加密用公钥2 测试阶段无需修改，生产接入时另行发放
        public static readonly string PUB_Y_KEY = "740e50cb6e6e04003029a66920d1ba4bc39519035ea423bf0079ef58128202fb";

        // 反馈文件解密用私钥 测试阶段无需修改，生产接入时另行发放
        public static readonly string PRV_KEY = "9401d5a563967f8bd39fbd81d5dedea4e552bf97f5dd8cab95749421a477e7d0";
        
        static void Main(string[] args)
        {
            TestSm2Enc();
        }
        public static void TestSm2Enc()
        {
            string testStr = "hello world";
            Console.WriteLine("原始数据 : " + testStr);
            byte[] sourceData = Encoding.ASCII.GetBytes(testStr);
            byte[] pubk = Encoding.ASCII.GetBytes(PubKey);
            string encStr = SM2Utils.Encrypt(Hex.Decode(pubk), sourceData);

            Console.WriteLine("加密后数据 : " + encStr);

            byte[] prik = Encoding.ASCII.GetBytes(PriKey);
            var data = Hex.Decode(Encoding.ASCII.GetBytes(encStr));
            var decodedData = SM2Utils.Decrypt(Hex.Decode(prik), data);

            var decodedStr = Encoding.ASCII.GetString(decodedData);
            Console.WriteLine("解密后数据 : " + decodedStr);
        }
    }
    
}