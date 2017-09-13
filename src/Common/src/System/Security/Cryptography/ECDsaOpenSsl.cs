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
    internal static partial class ECDsaImplementation
    {
#endif
        public sealed partial class ECDsaOpenSsl : ECDsa
        {
            private Lazy<SafeEcKeyHandle> _key;

            /// <summary>
            /// Create an ECDsaOpenSsl algorithm with a named curve.
            /// </summary>
            /// <param name="curve">The <see cref="ECCurve"/> representing the curve.</param>
            /// <exception cref="ArgumentNullException">if <paramref name="curve" /> is null.</exception>
            public ECDsaOpenSsl(ECCurve curve)
            {
                GenerateKey(curve);
            }

            /// <summary>
            ///     Create an ECDsaOpenSsl algorithm with a random 521 bit key pair.
            /// </summary>
            public ECDsaOpenSsl()
                : this(521)
            {
            }

            /// <summary>
            ///     Creates a new ECDsaOpenSsl object that will use a randomly generated key of the specified size.
            /// </summary>
            /// <param name="keySize">Size of the key to generate, in bits.</param>
            public ECDsaOpenSsl(int keySize)
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

            public override byte[] SignHash(byte[] hash)
            {
                if (hash == null)
                    throw new ArgumentNullException(nameof(hash));

                SafeEcKeyHandle key = _key.Value;
                int signatureLength = Interop.Crypto.EcDsaSize(key);
                byte[] signature = new byte[signatureLength];
                if (!Interop.Crypto.EcDsaSign(hash, hash.Length, signature, ref signatureLength, key))
                    throw Interop.Crypto.CreateOpenSslCryptographicException();

                byte[] converted = AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(signature, 0, signatureLength, KeySize);

                return converted;
            }

            public override bool TrySignHash(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten)
            {
                SafeEcKeyHandle key = _key.Value;

                byte[] converted;
                int signatureLength = Interop.Crypto.EcDsaSize(key);
                byte[] signature = ArrayPool<byte>.Shared.Rent(signatureLength);
                try
                {
                    if (!Interop.Crypto.EcDsaSign(source, source.Length, new Span<byte>(signature, 0, signatureLength), ref signatureLength, key))
                    {
                        throw Interop.Crypto.CreateOpenSslCryptographicException();
                    }

                    converted = AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(signature, 0, signatureLength, KeySize);
                }
                finally
                {
                    Array.Clear(signature, 0, signatureLength);
                    ArrayPool<byte>.Shared.Return(signature);
                }

                if (converted.Length <= destination.Length)
                {
                    new ReadOnlySpan<byte>(converted).CopyTo(destination);
                    bytesWritten = converted.Length;
                    return true;
                }
                else
                {
                    bytesWritten = 0;
                    return false;
                }
            }

            public override bool VerifyHash(byte[] hash, byte[] signature)
            {
                if (hash == null)
                    throw new ArgumentNullException(nameof(hash));
                if (signature == null)
                    throw new ArgumentNullException(nameof(signature));

                return VerifyHash((ReadOnlySpan<byte>)hash, (ReadOnlySpan<byte>)signature);
            }

            public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
            {
                // The signature format for .NET is r.Concat(s). Each of r and s are of length BitsToBytes(KeySize), even
                // when they would have leading zeroes.  If it's the correct size, then we need to encode it from
                // r.Concat(s) to SEQUENCE(INTEGER(r), INTEGER(s)), because that's the format that OpenSSL expects.
                int expectedBytes = 2 * AsymmetricAlgorithmHelpers.BitsToBytes(KeySize);
                if (signature.Length != expectedBytes)
                {
                    // The input isn't of the right length, so we can't sensibly re-encode it.
                    return false;
                }

                byte[] openSslFormat = AsymmetricAlgorithmHelpers.ConvertIeee1363ToDer(signature);

                SafeEcKeyHandle key = _key.Value;
                int verifyResult = Interop.Crypto.EcDsaVerify(hash, hash.Length, openSslFormat, openSslFormat.Length, key);
                return verifyResult == 1;
            }

            protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
                AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

            protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
                AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

            protected override bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
                AsymmetricAlgorithmHelpers.TryHashData(source, destination, hashAlgorithm, out bytesWritten);

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

            private SafeEcKeyHandle GenerateKeyLazy() => ECOpenSsl.GenerateKeyByKeySize(KeySize);

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

                    /// <summary>
            ///         ImportParameters will replace the existing key that ECDsaOpenSsl is working with by creating a
            ///         new key. If the parameters contains only Q, then only a public key will be imported.
            ///         If the parameters also contains D, then a full key pair will be imported. 
            ///         The parameters Curve value specifies the type of the curve to import.
            /// </summary>
            /// <param name="parameters">The curve parameters.</param>
            /// <exception cref="CryptographicException">
            ///     if <paramref name="parameters" /> does not contain valid values.
            /// </exception>
            /// <exception cref="NotSupportedException">
            ///     if <paramref name="parameters" /> references a curve that cannot be imported.
            /// </exception>
            /// <exception cref="PlatformNotSupportedException">
            ///     if <paramref name="parameters" /> references a curve that is not supported by this platform.
            /// </exception>
            public override void ImportParameters(ECParameters parameters) => SetKey(ECOpenSsl.ImportParameters(parameters));

            /// <summary>
            ///     Exports the key and explicit curve parameters used by the ECC object into an <see cref="ECParameters"/> object.
            /// </summary>
            /// <exception cref="CryptographicException">
            ///     if there was an issue obtaining the curve values.
            /// </exception>
            /// <returns>The key and explicit curve parameters used by the ECC object.</returns>
            public override ECParameters ExportExplicitParameters(bool includePrivateParameters) => ECOpenSsl.ExportExplicitParameters(_key.Value, includePrivateParameters);

            /// <summary>
            ///     Exports the key used by the ECC object into an <see cref="ECParameters"/> object.
            ///     If the curve has a name, the Curve property will contain named curve parameters otherwise it will contain explicit parameters.
            /// </summary>
            /// <exception cref="CryptographicException">
            ///     if there was an issue obtaining the curve values.
            /// </exception>
            /// <returns>The key and named curve parameters used by the ECC object.</returns>
            public override ECParameters ExportParameters(bool includePrivateParameters) => ECOpenSsl.ExportParameters(_key.Value, includePrivateParameters);

    }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
