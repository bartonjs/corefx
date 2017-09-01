// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.IO;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanOpenSsl : ECDiffieHellman
        {
            internal const string ECDSA_P256_OID_VALUE = "1.2.840.10045.3.1.7"; // Also called nistP256 or secP256r1
            internal const string ECDSA_P384_OID_VALUE = "1.3.132.0.34"; // Also called nistP384 or secP384r1
            internal const string ECDSA_P521_OID_VALUE = "1.3.132.0.35"; // Also called nistP521or secP521r1

            private Lazy<SafeEcKeyHandle> _key;

            /// <summary>
            /// Create an ECDiffieHellmanOpenSsl algorithm with a named curve.
            /// </summary>
            /// <param name="curve">The <see cref="ECCurve"/> representing the curve.</param>
            /// <exception cref="ArgumentNullException">if <paramref name="curve" /> is null.</exception>
            public ECDiffieHellmanOpenSsl(ECCurve curve)
            {
                GenerateKey(curve);
            }

            /// <summary>
            ///     Create an ECDiffieHellmanOpenSsl algorithm with a random 521 bit key pair.
            /// </summary>
            public ECDiffieHellmanOpenSsl()
                : this(521)
            {
            }

            /// <summary>
            ///     Creates a new ECDiffieHellmanOpenSsl object that will use a randomly generated key of the specified size.
            /// </summary>
            /// <param name="keySize">Size of the key to generate, in bits.</param>
            public ECDiffieHellmanOpenSsl(int keySize)
            {
                KeySize = keySize;
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

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    FreeKey();
                }

                base.Dispose(disposing);
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
                        return;

                    // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    FreeKey();
                    _key = new Lazy<SafeEcKeyHandle>(GenerateKeyLazy);
                }
            }

            public override void GenerateKey(ECCurve curve)
            {
                curve.Validate();
                FreeKey();

                if (curve.IsNamed)
                {
                    string oid = null;
                    // Use oid Value first if present, otherwise FriendlyName because Oid maintains a hard-coded
                    // cache that may have different casing for FriendlyNames than OpenSsl
                    oid = !string.IsNullOrEmpty(curve.Oid.Value) ? curve.Oid.Value : curve.Oid.FriendlyName;

                    SafeEcKeyHandle key = Interop.Crypto.EcKeyCreateByOid(oid);

                    if (key == null || key.IsInvalid)
                        throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, oid));

                    if (!Interop.Crypto.EcKeyGenerateKey(key))
                        throw Interop.Crypto.CreateOpenSslCryptographicException();

                    SetKey(key);
                }
                else if (curve.IsExplicit)
                {
                    SafeEcKeyHandle key = Interop.Crypto.EcKeyCreateByExplicitCurve(curve);

                    if (!Interop.Crypto.EcKeyGenerateKey(key))
                        throw Interop.Crypto.CreateOpenSslCryptographicException();

                    SetKey(key);
                }
                else
                {
                    throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, curve.CurveType.ToString()));
                }
            }

            private SafeEcKeyHandle GenerateKeyLazy()
            {
                string oid = null;
                switch (KeySize)
                {
                    case 256: oid = ECDSA_P256_OID_VALUE; break;
                    case 384: oid = ECDSA_P384_OID_VALUE; break;
                    case 521: oid = ECDSA_P521_OID_VALUE; break;
                    default:
                        // Only above three sizes supported for backwards compatibility; named curves should be used instead
                        throw new InvalidOperationException(SR.Cryptography_InvalidKeySize); 
                }

                SafeEcKeyHandle key = Interop.Crypto.EcKeyCreateByOid(oid);

                if (key == null || key.IsInvalid)
                    throw new PlatformNotSupportedException(string.Format(SR.Cryptography_CurveNotSupported, oid));

                if (!Interop.Crypto.EcKeyGenerateKey(key))
                    throw Interop.Crypto.CreateOpenSslCryptographicException();

                return key;
            }

            private void FreeKey()
            {
                if (_key != null)
                {
                    if (_key.IsValueCreated)
                    {
                        SafeEcKeyHandle handle = _key.Value;
                        if (handle != null)
                            handle.Dispose();
                    }
                    _key = null;
                }
            }

            private void SetKey(SafeEcKeyHandle newKey)
            {
                // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
                // with the already loaded key.
                ForceSetKeySize(Interop.Crypto.EcKeyGetSize(newKey));

                _key = new Lazy<SafeEcKeyHandle>(newKey);
            }

            public override ECDiffieHellmanPublicKey PublicKey
            {
                get
                {
                    return new ECDiffieHellmanOpenSslPublicKey(ExportParameters(false), ExportExplicitParameters(false));
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
