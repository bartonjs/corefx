using System.Collections.Generic;
using System.Security.Cryptography;
using Xunit;

namespace RedZoneTests
{
    public partial class ECDiffieHellmanTests
    {
        public static IEnumerable<object[]> XmlParameterCases
        {
            get
            {
                foreach (XmlParameters xmlParameters in BuildXmlParameterCases("ECDHKeyValue"))
                {
                    yield return new object[] { xmlParameters };
                }
            }
        }

        [Theory, MemberData("XmlParameterCases")]
        public static void RoundTripXml(XmlParameters testCase)
        {
            if (testCase.AdvancedSupportRequired &&
                !ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            string xmlOut;

            // ECDiffieHellmanCng doesn't support AsymmetricAlgorithm.FromXmlString,
            // it requires an overload to be called.  These tests would need to be
            // restructured a bit to support a second provider.
            using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng())
            {
                ecdh.FromXmlString(testCase.XmlString, ECKeyXmlFormat.Rfc4050);

                ECParameters parameters = ecdh.ExportParameters(false);
                AssertEqual(testCase.ECParameters, parameters);

                xmlOut = ecdh.ToXmlString(ECKeyXmlFormat.Rfc4050);
            }

            using (ECDiffieHellmanCng ecdh = new ECDiffieHellmanCng())
            {
                ecdh.FromXmlString(xmlOut, ECKeyXmlFormat.Rfc4050);

                ECParameters parameters = ecdh.ExportParameters(false);
                AssertEqual(testCase.ECParameters, parameters);

                string xmlOut2 = ecdh.ToXmlString(ECKeyXmlFormat.Rfc4050);

                // Import, Export, Import. If we export the same thing we're stable.
                //
                // We can't just compare this to the original because our writer emits
                // xsi:type information, but our reader doesn't require it, and the
                // W3C example doesn't have it.
                Assert.Equal(xmlOut, xmlOut2);
            }
        }
    }
}