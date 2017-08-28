using System.Security.Cryptography;

namespace RedZoneTests
{
    internal static partial class ECDiffieHellmanFactory
    {
        public static ECDiffieHellman Create()
        {
            return new ECDiffieHellmanCng();
        }

        public static ECDiffieHellman Create(int keySize)
        {
            return new ECDiffieHellmanCng(keySize);
        }

        public static ECDiffieHellman Create(ECCurve curve)
        {
            var ecdh = new ECDiffieHellmanCng();
            ecdh.GenerateKey(curve);
            return ecdh;
        }

        public static bool AreExplicitCurvesSupported
        {
            get { return ECDsaFactory.AreExplicitCurvesSupported; }
        }
    }
}