using System;
using System.Security.Cryptography;
using Xunit;

namespace RedZoneTests
{
    partial class ECDiffieHellmanTests
    {
        [Theory, MemberData("TestCurvesFull")]
        public static void TestNamedCurves(CurveDef curveDef)
        {
            using (ECDiffieHellman ec1 = ECDiffieHellmanFactory.Create(curveDef.Curve))
            {
                ECParameters param1 = ec1.ExportParameters(curveDef.IncludePrivate);
                VerifyNamedCurve(param1, ec1, curveDef.KeySize, curveDef.IncludePrivate);

                using (ECDiffieHellman ec2 = ECDiffieHellmanFactory.Create())
                {
                    ec2.ImportParameters(param1);
                    ECParameters param2 = ec2.ExportParameters(curveDef.IncludePrivate);
                    VerifyNamedCurve(param2, ec2, curveDef.KeySize, curveDef.IncludePrivate);

                    AssertEqual(param1, param2);
                }
            }
        }

        [Theory, MemberData("TestInvalidCurves")]
        public static void TestNamedCurvesNegative(CurveDef curveDef)
        {
            // An exception may be thrown during Create() if the Oid is bad, or later during native calls
            Assert.Throws<PlatformNotSupportedException>(() => ECDiffieHellmanFactory.Create(curveDef.Curve).ExportParameters(false));
        }

        [Theory, MemberData("TestCurvesFull")]
        public static void TestExplicitCurves(CurveDef curveDef)
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ec1 = ECDiffieHellmanFactory.Create(curveDef.Curve))
            {
                ECParameters param1 = ec1.ExportExplicitParameters(curveDef.IncludePrivate);
                VerifyExplicitCurve(param1, ec1, curveDef);

                using (ECDiffieHellman ec2 = ECDiffieHellmanFactory.Create())
                {
                    ec2.ImportParameters(param1);
                    ECParameters param2 = ec2.ExportExplicitParameters(curveDef.IncludePrivate);
                    VerifyExplicitCurve(param1, ec1, curveDef);

                    AssertEqual(param1, param2);
                }
            }
        }

        [Theory, MemberData("TestCurves")]
        public static void TestExplicitCurvesKeyAgree(CurveDef curveDef)
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ecdh1Named = ECDiffieHellmanFactory.Create(curveDef.Curve))
            {
                ECParameters ecdh1ExplicitParameters = ecdh1Named.ExportExplicitParameters(true);

                using (ECDiffieHellman ecdh1Explicit = ECDiffieHellmanFactory.Create())
                using (ECDiffieHellman ecdh2 = ECDiffieHellmanFactory.Create(ecdh1ExplicitParameters.Curve))
                {
                    ecdh1Explicit.ImportParameters(ecdh1ExplicitParameters);

                    using (ECDiffieHellmanPublicKey ecdh1NamedPub = ecdh1Named.PublicKey)
                    using (ECDiffieHellmanPublicKey ecdh1ExplicitPub = ecdh1Explicit.PublicKey)
                    using (ECDiffieHellmanPublicKey ecdh2Pub = ecdh2.PublicKey)
                    {
                        HashAlgorithmName hash = HashAlgorithmName.SHA256;

                        byte[] dh1NamedExp = ecdh1Named.DeriveKeyFromHash(ecdh1ExplicitPub, hash);
                        byte[] dh1ExpNamed = ecdh1Explicit.DeriveKeyFromHash(ecdh1NamedPub, hash);

                        Assert.Equal(dh1ExpNamed, dh1ExpNamed);

                        byte[] dh1NamedDh2 = ecdh1Named.DeriveKeyFromHash(ecdh2Pub, hash);
                        byte[] dh2Dh1Exp = ecdh2.DeriveKeyFromHash(ecdh1ExplicitPub, hash);

                        Assert.Equal(dh1NamedDh2, dh2Dh1Exp);
                    }
                }
            }
        }

        [Fact]
        public static void TestNamedCurveNegative()
        {
            Assert.Throws<PlatformNotSupportedException>(() => ECDiffieHellmanFactory.Create(ECCurve.CreateFromFriendlyName("Invalid")).ExportExplicitParameters(false));
            Assert.Throws<PlatformNotSupportedException>(() => ECDiffieHellmanFactory.Create(ECCurve.CreateFromValue("Invalid")).ExportExplicitParameters(false));
        }

        [Fact]
        public static void TestKeySizeCreateKey()
        {
            using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create(ECCurve.NamedCurves.nistP256))
            {
                // Ensure the handle is created
                Assert.Equal(256, ec.KeySize);
                ec.Exercise();

                CompareCurve(ECCurve.NamedCurves.nistP256, ec.ExportParameters(false).Curve);

                ec.KeySize = 521; //nistP521
                Assert.Equal(521, ec.KeySize);
                ec.Exercise();

                CompareCurve(ECCurve.NamedCurves.nistP521, ec.ExportParameters(false).Curve);

                Assert.ThrowsAny<CryptographicException>(() => ec.KeySize = 9999);
            }
        }

        [Fact]
        public static void TestExplicitImportValidationNegative()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            unchecked
            {
                using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create())
                {
                    ECParameters p = ECDsaTestData.GetNistP256ExplicitTestData();
                    Assert.True(p.Curve.IsPrime);
                    ec.ImportParameters(p);

                    ECParameters temp = p;
                    temp.Q.X = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = (byte[])p.Q.X.Clone(); --temp.Q.X[0]; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Q.Y = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = (byte[])p.Q.Y.Clone(); --temp.Q.Y[0]; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Curve.A = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.A = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.A = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.A = (byte[])p.Curve.A.Clone(); --temp.Curve.A[0]; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Curve.B = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.B = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.B = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.B = (byte[])p.Curve.B.Clone(); --temp.Curve.B[0]; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Curve.Order = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.Order = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Curve.Prime = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.Prime = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.Prime = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Curve.Prime = (byte[])p.Curve.Prime.Clone(); --temp.Curve.Prime[0]; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                }
            }
        }

        [Fact]
        public static void ImportExplicitWithSeedButNoHash()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create())
            {
                ECCurve curve = GetNistP256ExplicitCurve();
                Assert.NotNull(curve.Hash);
                ec.GenerateKey(curve);

                ECParameters parameters = ec.ExportExplicitParameters(true);
                Assert.NotNull(parameters.Curve.Seed);
                parameters.Curve.Hash = null;

                ec.ImportParameters(parameters);
                ec.Exercise();
            }
        }

        [Fact]
        public static void ImportExplicitWithHashButNoSeed()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create())
            {
                ECCurve curve = GetNistP256ExplicitCurve();
                Assert.NotNull(curve.Hash);
                ec.GenerateKey(curve);

                ECParameters parameters = ec.ExportExplicitParameters(true);
                Assert.NotNull(parameters.Curve.Hash);
                parameters.Curve.Seed = null;

                ec.ImportParameters(parameters);
                ec.Exercise();
            }
        }

        [Fact]
        public static void TestNamedImportValidationNegative()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            unchecked
            {
                using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create())
                {
                    ECParameters p = ECDsaTestData.GetNistP224KeyTestData();
                    Assert.True(p.Curve.IsNamed);
                    var q = p.Q;
                    var c = p.Curve;
                    ec.ImportParameters(p);

                    ECParameters temp = p;
                    temp.Q.X = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.X = (byte[])p.Q.X.Clone(); temp.Q.X[0]--; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p;
                    temp.Q.Y = null; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = new byte[] { }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = new byte[1] { 0x10 }; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));
                    temp.Q.Y = (byte[])p.Q.Y.Clone(); temp.Q.Y[0]--; Assert.ThrowsAny<CryptographicException>(() => ec.ImportParameters(temp));

                    temp = p; temp.Curve = ECCurve.CreateFromOid(new Oid("Invalid", "Invalid")); Assert.ThrowsAny<PlatformNotSupportedException>(() => ec.ImportParameters(temp));
                }
            }
        }

        [Fact]
        public static void TestGeneralExportWithExplicitParameters()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ecdsa = ECDiffieHellmanFactory.Create())
            {
                ECParameters param = ECDsaTestData.GetNistP256ExplicitTestData();
                param.Validate();
                ecdsa.ImportParameters(param);
                Assert.True(param.Curve.IsExplicit);

                param = ecdsa.ExportParameters(false);
                param.Validate();

                // We should have explicit values, not named, as this curve has no name.
                Assert.True(param.Curve.IsExplicit);
            }
        }

        [Fact]
        public static void TestExplicitCurveImportOnUnsupportedPlatform()
        {
            if (ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ecdsa = ECDiffieHellmanFactory.Create())
            {
                ECParameters param = ECDsaTestData.GetNistP256ExplicitTestData();
                Assert.Throws<PlatformNotSupportedException>(() => ecdsa.ImportParameters(param));
            }
        }

        [Fact]
        public static void TestNamedCurveWithExplicitKey()
        {
            if (!ECDiffieHellmanFactory.AreExplicitCurvesSupported)
            {
                return;
            }

            using (ECDiffieHellman ec = ECDiffieHellmanFactory.Create())
            {
                ECParameters parameters = ECDsaTestData.GetNistP224KeyTestData();
                ec.ImportParameters(parameters);
                VerifyNamedCurve(parameters, ec, 224, true);
            }
        }

        private static void VerifyNamedCurve(ECParameters parameters, ECDiffieHellman ec, int keySize, bool includePrivate)
        {
            parameters.Validate();
            Assert.True(parameters.Curve.IsNamed);
            Assert.Equal(keySize, ec.KeySize);
            Assert.True(
                includePrivate && parameters.D.Length > 0 ||
                !includePrivate && parameters.D == null);

            if (includePrivate)
                ec.Exercise();

            // Ensure the key doesn't get regenerated after export
            ECParameters paramSecondExport = ec.ExportParameters(includePrivate);
            paramSecondExport.Validate();
            AssertEqual(parameters, paramSecondExport);
        }

        private static void VerifyExplicitCurve(ECParameters parameters, ECDiffieHellman ec, CurveDef curveDef)
        {
            Assert.True(parameters.Curve.IsExplicit);
            ECCurve curve = parameters.Curve;


            Assert.True(curveDef.IsCurveTypeEqual(curve.CurveType));
            Assert.True(
                curveDef.IncludePrivate && parameters.D.Length > 0 ||
                !curveDef.IncludePrivate && parameters.D == null);
            Assert.Equal(curveDef.KeySize, ec.KeySize);

            Assert.Equal(curve.A.Length, parameters.Q.X.Length);
            Assert.Equal(curve.A.Length, parameters.Q.Y.Length);
            Assert.Equal(curve.A.Length, curve.B.Length);
            Assert.Equal(curve.A.Length, curve.G.X.Length);
            Assert.Equal(curve.A.Length, curve.G.Y.Length);
            Assert.True(curve.Seed == null || curve.Seed.Length > 0);
            Assert.True(curve.Order == null || curve.Order.Length > 0);
            if (curve.IsPrime)
            {
                Assert.Equal(curve.A.Length, curve.Prime.Length);
            }

            if (curveDef.IncludePrivate)
                ec.Exercise();

            // Ensure the key doesn't get regenerated after export
            ECParameters paramSecondExport = ec.ExportExplicitParameters(curveDef.IncludePrivate);
            AssertEqual(parameters, paramSecondExport);
        }
    }
}