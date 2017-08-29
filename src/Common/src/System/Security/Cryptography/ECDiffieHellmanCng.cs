// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Diagnostics.Contracts;
using static Internal.NativeCrypto.BCryptNative;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        /// <summary>
        ///     Key derivation functions used to transform the raw secret agreement into key material
        /// </summary>
        public enum ECDiffieHellmanKeyDerivationFunction
        {
            Hash,
            Hmac,
            Tls
        }

        /// <summary>
        ///     Wrapper for CNG's implementation of elliptic curve Diffie-Hellman key exchange
        /// </summary>
        public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
        {
            private static KeySizes[] s_legalKeySizes = new KeySizes[] { new KeySizes(256, 384, 128), new KeySizes(521, 521, 0) };

            private byte[] _hmacKey;
            private ECDiffieHellmanKeyDerivationFunction _kdf = ECDiffieHellmanKeyDerivationFunction.Hash;
            private byte[] _label;
            private byte[] _secretAppend;
            private byte[] _secretPrepend;
            private byte[] _seed;

            public ECDiffieHellmanCng() : this(521) { }

            public ECDiffieHellmanCng(int keySize)
            {
                KeySize = keySize;
            }

            public ECDiffieHellmanCng(ECCurve curve)
            {
                // GenerateKey will already do all of the validation we need.
                GenerateKey(curve);
            }

            public override int KeySize
            {
                get
                {
                    return base.KeySize;
                }
                set
                {
                    if (KeySize == value)
                    {
                        return;
                    }

                    // Set the KeySize before DisposeKey so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    DisposeKey();

                    // Key will be lazily re-created
                }
            }

            /// <summary>
            ///     Key used with the HMAC KDF
            /// </summary>
            public byte[] HmacKey
            {
                get { return _hmacKey; }
                set { _hmacKey = value; }
            }

            /// <summary>
            ///     KDF used to transform the secret agreement into key material
            /// </summary>
            public ECDiffieHellmanKeyDerivationFunction KeyDerivationFunction
            {
                get
                {
                    Contract.Ensures(Contract.Result<ECDiffieHellmanKeyDerivationFunction>() >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                                     Contract.Result<ECDiffieHellmanKeyDerivationFunction>() <= ECDiffieHellmanKeyDerivationFunction.Tls);

                    return _kdf;
                }

                set
                {
                    Contract.Ensures(_kdf >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                                            _kdf <= ECDiffieHellmanKeyDerivationFunction.Tls);

                    if (value < ECDiffieHellmanKeyDerivationFunction.Hash || value > ECDiffieHellmanKeyDerivationFunction.Tls)
                    {
                        throw new ArgumentOutOfRangeException("value");
                    }

                    _kdf = value;
                }
            }

            /// <summary>
            ///     Label bytes used for the TLS KDF
            /// </summary>
            public byte[] Label
            {
                get { return _label; }
                set { _label = value; }
            }

            /// <summary>
            ///     Bytes to append to the raw secret agreement before processing by the KDF
            /// </summary>
            public byte[] SecretAppend
            {
                get { return _secretAppend; }
                set { _secretAppend = value; }
            }

            /// <summary>
            ///     Bytes to prepend to the raw secret agreement before processing by the KDF
            /// </summary>
            public byte[] SecretPrepend
            {
                get { return _secretPrepend; }
                set { _secretPrepend = value; }
            }

            /// <summary>
            ///     Seed bytes used for the TLS KDF
            /// </summary>
            public byte[] Seed
            {
                get { return _seed; }
                set { _seed = value; }
            }

            /// <summary>
            ///     Use the secret agreement as the HMAC key rather than supplying a seperate one
            /// </summary>
            public bool UseSecretAgreementAsHmacKey
            {
                get { return HmacKey == null; }
            }

            /// <summary>
            /// Set the KeySize without validating against LegalKeySizes.
            /// </summary>
            /// <param name="newKeySize">The value to set the KeySize to.</param>
            private void ForceSetKeySize(int newKeySize)
            {
                // In the event that a key was loaded via ImportParameters, curve name, or an IntPtr/SafeHandle
                // it could be outside of the bounds that we currently represent as "legal key sizes".
                // Since that is our view into the underlying component it can be detached from the
                // component's understanding.  If it said it has opened a key, and this is the size, trust it.
                KeySizeValue = newKeySize;
            }

            public override KeySizes[] LegalKeySizes
            {
                get
                {
                    // Return the three sizes that can be explicitly set (for backwards compatibility)
                    return new[] {
                        new KeySizes(minSize: 256, maxSize: 384, skipSize: 128),
                        new KeySizes(minSize: 521, maxSize: 521, skipSize: 0),
                    };
                }
            }

            internal static bool IsECNamedCurve(string algorithm)
            {
                return (algorithm == AlgorithmName.ECDH ||
                    algorithm == AlgorithmName.ECDsa);
            }

            /// <summary>
            /// Maps algorithm to curve name accounting for the special nist curves
            /// </summary>
            internal static string SpecialNistAlgorithmToCurveName(string algorithm)
            {
                if (algorithm == AlgorithmName.ECDHP256 ||
                    algorithm == AlgorithmName.ECDsaP256)
                {
                    return "nistP256";
                }

                if (algorithm == AlgorithmName.ECDHP384 ||
                    algorithm == AlgorithmName.ECDsaP384)
                {
                    return "nistP384";
                }

                if (algorithm == AlgorithmName.ECDHP521 ||
                    algorithm == AlgorithmName.ECDsaP521)
                {
                    return "nistP521";
                }

                Debug.Fail(string.Format("Unknown curve {0}", algorithm));
                throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, algorithm));
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
