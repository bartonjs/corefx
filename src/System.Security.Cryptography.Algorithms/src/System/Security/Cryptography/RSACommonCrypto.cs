// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Security.Cryptography.Apple;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    public partial class RSA : AsymmetricAlgorithm
    {
        public static RSA Create()
        {
            return new RSAImplementation.RSASecurityTransforms();
        }
    }

    internal static partial class RSAImplementation
    {
        // TODO: Name this for real.
        public sealed partial class RSASecurityTransforms : RSA
        {
            private KeyPair _keys;

            public RSASecurityTransforms()
                : this(2048)
            {
            }

            public RSASecurityTransforms(int keySize)
            {
                KeySize = keySize;
            }

            public override KeySizes[] LegalKeySizes
            {
                get
                {
                    // See https://msdn.microsoft.com/en-us/library/windows/desktop/bb931354(v=vs.85).aspx
                    return new KeySizes[]
                    {
                        // All values are in bits.
                        new KeySizes(minSize: 512, maxSize: 16384, skipSize: 64),
                    };
                }
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

                    // Set the KeySize before freeing the key so that an invalid value doesn't throw away the key
                    base.KeySize = value;

                    _keys?.Dispose();
                    _keys = null;
                }
            }

            public override RSAParameters ExportParameters(bool includePrivateParameters)
            {
                KeyPair keys = GetKeys();

                SafeSecKeyRefHandle keyHandle = includePrivateParameters ? keys.PrivateKey : keys.PublicKey;

                if (keyHandle == null)
                {
                    throw new CryptographicException("No key handle allocated");
                }

                DerSequenceReader keyReader = Interop.AppleCrypto.SecKeyExport(keyHandle, includePrivateParameters);
                RSAParameters parameters = new RSAParameters();

                if (includePrivateParameters)
                {
                    keyReader.ReadPkcs8Blob(ref parameters);
                }
                else
                {
                    keyReader.ReadSubjectPublicKeyInfo(ref parameters);
                }

                return parameters;
            }

            public override void ImportParameters(RSAParameters parameters)
            {
                bool isPrivateKey = parameters.D != null;

                if (isPrivateKey)
                {
                    // Start with the private key, in case some of the private key fields
                    // don't match the public key fields.
                    //
                    // Public import should go off without a hitch.
                    SafeSecKeyRefHandle privateKey = ImportKey(parameters);

                    RSAParameters publicOnly = new RSAParameters
                    {
                        Modulus = parameters.Modulus,
                        Exponent = parameters.Exponent,
                    };

                    SafeSecKeyRefHandle publicKey;
                    try
                    {
                        publicKey = ImportKey(publicOnly);
                    }
                    catch
                    {
                        privateKey.Dispose();
                        throw;
                    }

                    SetKey(KeyPair.PublicPrivatePair(publicKey, privateKey));
                }
                else
                {
                    SafeSecKeyRefHandle publicKey = ImportKey(parameters);
                    SetKey(KeyPair.PublicOnly(publicKey));
                }
            }

            public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
            {
                return Interop.AppleCrypto.RsaEncrypt(GetKeys().PublicKey, data, padding);
            }

            public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
            {
                KeyPair keys = GetKeys();

                if (keys.PrivateKey == null)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }

                return Interop.AppleCrypto.RsaDecrypt(keys.PrivateKey, data, padding);
            }

            public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
            {
                if (padding != RSASignaturePadding.Pkcs1)
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);

                KeyPair keys = GetKeys();

                if (keys.PrivateKey == null)
                {
                    throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                }

                return Interop.AppleCrypto.RsaSign(
                    keys.PrivateKey,
                    hash,
                    PalAlgorithmFromAlgorithmName(hashAlgorithm));
            }

            public override bool VerifyHash(
                byte[] hash,
                byte[] signature,
                HashAlgorithmName hashAlgorithm,
                RSASignaturePadding padding)
            {
                if (padding != RSASignaturePadding.Pkcs1)
                    throw new CryptographicException(SR.Cryptography_InvalidPaddingMode);

                return Interop.AppleCrypto.RsaVerify(
                    GetKeys().PublicKey,
                    hash,
                    signature,
                    PalAlgorithmFromAlgorithmName(hashAlgorithm));
            }

            protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
            {
                return OpenSslAsymmetricAlgorithmCore.HashData(data, offset, count, hashAlgorithm);
            }

            protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
            {
                return OpenSslAsymmetricAlgorithmCore.HashData(data, hashAlgorithm);
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _keys?.Dispose();
                    _keys = null;
                }

                base.Dispose(disposing);
            }

            private static Interop.AppleCrypto.PAL_HashAlgorithm PalAlgorithmFromAlgorithmName(
                HashAlgorithmName hashAlgorithmName)
            {
                if (hashAlgorithmName == HashAlgorithmName.MD5)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Md5;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA1)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha1;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA256)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha256;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA384)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha384;
                }
                else if (hashAlgorithmName == HashAlgorithmName.SHA512)
                {
                    return Interop.AppleCrypto.PAL_HashAlgorithm.Sha512;
                }

                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }

            private KeyPair GetKeys()
            {
                KeyPair current = _keys;

                if (current != null)
                {
                    return current;
                }

                SafeSecKeyRefHandle publicKey;
                SafeSecKeyRefHandle privateKey;
                int osStatus;

                int gen = Interop.AppleCrypto.RsaGenerateKey(KeySizeValue, out publicKey, out privateKey, out osStatus);

                if (gen != 1)
                {
                    throw new CryptographicException($"RsaGenerateKey returned {gen} | {osStatus}");
                }

                current = KeyPair.PublicPrivatePair(publicKey, privateKey);
                _keys = current;
                return current;
            }

            private void SetKey(KeyPair newKeyPair)
            {
                KeyPair current = _keys;
                _keys = newKeyPair;
                current?.Dispose();

                if (newKeyPair != null)
                {
                    KeySizeValue = Interop.AppleCrypto.RsaGetKeySizeInBits(newKeyPair.PublicKey);
                }
            }

            private static SafeSecKeyRefHandle ImportKey(RSAParameters parameters)
            {
                SafeSecKeyRefHandle keyHandle;
                int osStatus;
                bool isPrivateKey = parameters.D != null;
                byte[] pkcs1Blob = parameters.ToPkcs1Blob();

                int ret = Interop.AppleCrypto.RsaImportEphemeralKey(
                    pkcs1Blob,
                    pkcs1Blob.Length,
                    isPrivateKey,
                    out keyHandle,
                    out osStatus);

                if (ret == 1 && !keyHandle.IsInvalid)
                {
                    return keyHandle;
                }

                if (ret == 0)
                {
                    // TODO: Is there a better OSStatus lookup?
                    throw Interop.AppleCrypto.CreateExceptionForCCError(osStatus, "OSStatus");
                }

                Debug.Fail($"RsaImportEphemeralKey returned {ret}");
                throw new CryptographicException();
            }
        }
    }

    internal sealed class KeyPair : IDisposable
    {
        internal SafeSecKeyRefHandle PublicKey { get; private set; }
        internal SafeSecKeyRefHandle PrivateKey { get; private set; }

        private KeyPair(SafeSecKeyRefHandle publicKey, SafeSecKeyRefHandle privateKey)
        {
            PublicKey = publicKey;
            PrivateKey = privateKey;
        }

        public void Dispose()
        {
            PrivateKey?.Dispose();
            PrivateKey = null;
            PublicKey?.Dispose();
            PublicKey = null;
        }

        internal static KeyPair PublicPrivatePair(SafeSecKeyRefHandle publicKey, SafeSecKeyRefHandle privateKey)
        {
            if (publicKey == null || publicKey.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(publicKey));
            if (privateKey == null || privateKey.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(privateKey));

            return new KeyPair(publicKey, privateKey);
        }

        internal static KeyPair PublicOnly(SafeSecKeyRefHandle publicKey)
        {
            if (publicKey == null || publicKey.IsInvalid)
                throw new ArgumentException(SR.Cryptography_OpenInvalidHandle, nameof(publicKey));

            return new KeyPair(publicKey, null);
        }
    }

    internal static class Pkcs1BlobHelpers
    {
        // The PKCS#1 version blob for an RSA key based on 2 primes.
        private static readonly byte[] s_versionNumberBytes = { 0 };

        internal static byte[] ToPkcs1Blob(this RSAParameters parameters)
        {
            if (parameters.Exponent == null || parameters.Modulus == null)
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);

            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
                }

                return DerEncoder.ConstructSequence(
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                    DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent));
            }

            if (parameters.P == null ||
                parameters.DP == null ||
                parameters.Q == null ||
                parameters.DQ == null ||
                parameters.InverseQ == null)
            {
                throw new CryptographicException(SR.Cryptography_InvalidRsaParameters);
            }

            return DerEncoder.ConstructSequence(
                DerEncoder.SegmentedEncodeUnsignedInteger(s_versionNumberBytes),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Modulus),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Exponent),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.D),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.P),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.Q),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DP),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.DQ),
                DerEncoder.SegmentedEncodeUnsignedInteger(parameters.InverseQ));
        }

        internal static void ReadPkcs8Blob(this DerSequenceReader reader, ref RSAParameters parameters)
        {
            // OneAsymmetricKey ::= SEQUENCE {
            //   version                   Version,
            //   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
            //   privateKey                PrivateKey,
            //   attributes            [0] Attributes OPTIONAL,
            //   ...,
            //   [[2: publicKey        [1] PublicKey OPTIONAL ]],
            //   ...
            // }
            //
            // PrivateKeyInfo ::= OneAsymmetricKey
            //
            // PrivateKey ::= OCTET STRING

            int version = reader.ReadInteger();

            // We understand both version 0 and 1 formats,
            // which are now known as v1 and v2, respectively.
            if (version > 1)
            {
                throw new CryptographicException();
            }

            {
                // Ensure we're reading RSA
                DerSequenceReader algorithm = reader.ReadSequence();

                string algorithmOid = algorithm.ReadOidAsString();

                if (algorithmOid != "1.2.840.113549.1.1.1")
                {
                    throw new CryptographicException();
                }
            }

            byte[] privateKeyBytes = reader.ReadOctetString();
            // Because this wsa an RSA private key, the key format is PKCS#1.
            ReadPkcs1Blob(privateKeyBytes, ref parameters);

            // We don't care about the rest of the blob here, but it's expected to not exist.
        }

        internal static void ReadSubjectPublicKeyInfo(this DerSequenceReader keyInfo, ref RSAParameters parameters)
        {
            // SubjectPublicKeyInfo::= SEQUENCE  {
            //    algorithm AlgorithmIdentifier,
            //    subjectPublicKey     BIT STRING  }
            DerSequenceReader algorithm = keyInfo.ReadSequence();
            string algorithmOid = algorithm.ReadOidAsString();

            if (algorithmOid != "1.2.840.113549.1.1.1")
            {
                throw new CryptographicException();
            }

            byte[] subjectPublicKeyBytes = keyInfo.ReadBitString();

            DerSequenceReader subjectPublicKey = new DerSequenceReader(subjectPublicKeyBytes);

            parameters.Modulus = TrimPaddingByte(subjectPublicKey.ReadIntegerBytes());
            parameters.Exponent = TrimPaddingByte(subjectPublicKey.ReadIntegerBytes());

            if (subjectPublicKey.HasData)
                throw new CryptographicException();
        }

        private static void ReadPkcs1Blob(byte[] privateKeyBytes, ref RSAParameters parameters)
        {
            // RSAPrivateKey::= SEQUENCE {
            //    version Version,
            //    modulus           INTEGER,  --n
            //    publicExponent INTEGER,  --e
            //    privateExponent INTEGER,  --d
            //    prime1 INTEGER,  --p
            //    prime2 INTEGER,  --q
            //    exponent1 INTEGER,  --d mod(p - 1)
            //    exponent2 INTEGER,  --d mod(q - 1)
            //    coefficient INTEGER,  --(inverse of q) mod p
            //    otherPrimeInfos OtherPrimeInfos OPTIONAL
            // }
            DerSequenceReader privateKey = new DerSequenceReader(privateKeyBytes);
            int version = privateKey.ReadInteger();

            if (version != 0)
            {
                throw new CryptographicException();
            }

            parameters.Modulus = TrimPaddingByte(privateKey.ReadIntegerBytes());
            parameters.Exponent = TrimPaddingByte(privateKey.ReadIntegerBytes());

            int modulusLen = parameters.Modulus.Length;
            int halfModulus = modulusLen / 2;

            parameters.D = PadOrTrim(privateKey.ReadIntegerBytes(), modulusLen);
            parameters.P = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.Q = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DP = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.DQ = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);
            parameters.InverseQ = PadOrTrim(privateKey.ReadIntegerBytes(), halfModulus);

            if (privateKey.HasData)
            {
                throw new CryptographicException();
            }
        }

        private static byte[] TrimPaddingByte(byte[] data)
        {
            if (data[0] != 0)
                return data;

            byte[] newData = new byte[data.Length - 1];
            Buffer.BlockCopy(data, 1, newData, 0, newData.Length);
            return newData;
        }

        private static byte[] PadOrTrim(byte[] data, int length)
        {
            if (data.Length == length)
                return data;

            // Need to skip the sign-padding byte.
            if (data.Length == length + 1 && data[0] == 0)
            {
                return TrimPaddingByte(data);
            }

            int offset = length - data.Length;

            byte[] newData = new byte[length];
            Buffer.BlockCopy(data, 0, newData, offset, data.Length);
            return newData;
        }
    }
}
