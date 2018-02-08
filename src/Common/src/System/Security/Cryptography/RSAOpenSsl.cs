// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    public partial class RSA : AsymmetricAlgorithm
    {
        public static new RSA Create() => new RSAImplementation.RSAOpenSsl();
    }

    internal static partial class RSAImplementation
    {
#endif
    public sealed partial class RSAOpenSsl : RSA
    {
        private const int BitsPerByte = 8;

        private delegate void DepaddingMethod(ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten);
        private delegate void PaddingMethod(ReadOnlySpan<byte> source, Span<byte> destination);

        // 65537 (0x10001) in big-endian form
        private static readonly byte[] s_defaultExponent = { 0x01, 0x00, 0x01 };

        private Lazy<SafeRsaHandle> _key;

        public RSAOpenSsl()
            : this(2048)
        {
        }

        public RSAOpenSsl(int keySize)
        {
            KeySize = keySize;
            _key = new Lazy<SafeRsaHandle>(GenerateKey);
        }

        public override int KeySize
        {
            set
            {
                if (KeySize == value)
                {
                    return;
                }

                // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                base.KeySize = value;

                FreeKey();
                _key = new Lazy<SafeRsaHandle>(GenerateKey);
            }
        }

        private void ForceSetKeySize(int newKeySize)
        {
            // In the event that a key was loaded via ImportParameters or an IntPtr/SafeHandle
            // it could be outside of the bounds that we currently represent as "legal key sizes".
            // Since that is our view into the underlying component it can be detached from the
            // component's understanding.  If it said it has opened a key, and this is the size, trust it.
            KeySizeValue = newKeySize;
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                // OpenSSL seems to accept answers of all sizes.
                // Choosing a non-multiple of 8 would make some calculations misalign
                // (like assertions of (output.Length * 8) == KeySize).
                // Choosing a number too small is insecure.
                // Choosing a number too large will cause GenerateKey to take much
                // longer than anyone would be willing to wait.
                //
                // So, copying the values from RSACryptoServiceProvider
                return new[] { new KeySizes(384, 16384, 8) };
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out DepaddingMethod depaddingMethod);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            int rsaSize = Interop.Crypto.RsaSize(key);
            byte[] buf = null;

            try
            {
                buf = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> destination = new Span<byte>(buf, 0, rsaSize);

                if (!TryDecrypt(key, data, destination, rsaPadding, depaddingMethod, out int bytesWritten))
                {
                    Debug.Fail($"{nameof(TryDecrypt)} should not return false for RSA_size buffer");
                    throw new CryptographicException();
                }

                return destination.Slice(0, bytesWritten).ToArray();
            }
            finally
            {
                if (buf != null)
                {
                    Array.Clear(buf, 0, rsaSize);
                    ArrayPool<byte>.Shared.Return(buf);
                }
            }
        }

        public override bool TryDecrypt(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out DepaddingMethod depaddingMethod);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            return TryDecrypt(key, source, destination, rsaPadding, depaddingMethod, out bytesWritten);
        }

        private static bool TryDecrypt(
            SafeRsaHandle key,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            Interop.Crypto.RsaPadding rsaPadding,
            DepaddingMethod depaddingMethod,
            out int bytesWritten)
        {
            // If rsaPadding is PKCS1 or OAEP-SHA1 then no depadding method should be present.
            // If rsaPadding is NoPadding then a depadding method should be present.
            Debug.Assert(
                (rsaPadding == Interop.Crypto.RsaPadding.NoPadding) ==
                (depaddingMethod != null));

            // Caller should have already checked this.
            Debug.Assert(!key.IsInvalid);

            int rsaSize = Interop.Crypto.RsaSize(key);

            if (destination.Length < rsaSize)
            {
                bytesWritten = 0;
                return false;
            }

            Span<byte> decryptBuf = destination;
            byte[] paddingBuf = null;

            if (depaddingMethod != null)
            {
                paddingBuf = ArrayPool<byte>.Shared.Rent(rsaSize);
                decryptBuf = paddingBuf;
            }

            try
            {
                int returnValue = Interop.Crypto.RsaPrivateDecrypt(source.Length, source, decryptBuf, key, rsaPadding);
                CheckReturn(returnValue);

                if (depaddingMethod != null)
                {
                    depaddingMethod(paddingBuf, destination, out bytesWritten);
                }
                else
                {
                    // If the padding mode is RSA_NO_PADDING then the size of the decrypted block
                    // will be RSA_size. If any padding was used, then some amount (determined by the padding algorithm)
                    // will have been reduced, and only returnValue bytes were part of the decrypted
                    // body.  Either way, we can just use returnValue, but some additional bytes may have been overwritten
                    // in the destination span.
                    bytesWritten = returnValue;
                }

                return true;
            }
            finally
            {
                if (paddingBuf != null)
                {
                    Array.Clear(paddingBuf, 0, rsaSize);
                    ArrayPool<byte>.Shared.Return(paddingBuf);
                }
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            byte[] buf = new byte[Interop.Crypto.RsaSize(key)];

            int returnValue = Interop.Crypto.RsaPublicEncrypt(
                data.Length,
                data,
                buf,
                key,
                rsaPadding);

            CheckReturn(returnValue);

            return buf;
        }

        public override bool TryEncrypt(ReadOnlySpan<byte> source, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            if (destination.Length < Interop.Crypto.RsaSize(key))
            {
                bytesWritten = 0;
                return false;
            }

            int returnValue = Interop.Crypto.RsaPublicEncrypt(source.Length, source, destination, key, rsaPadding);
            CheckReturn(returnValue);

            bytesWritten = returnValue;
            return true;
        }

        private static Interop.Crypto.RsaPadding GetInteropPadding(
            RSAEncryptionPadding padding,
            out DepaddingMethod depaddingMethod)
        {
            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                depaddingMethod = null;
                return Interop.Crypto.RsaPadding.Pkcs1;
            }

            if (padding == RSAEncryptionPadding.OaepSHA1)
            {
                depaddingMethod = null;
                return Interop.Crypto.RsaPadding.OaepSHA1;
            }

            if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                depaddingMethod = GetOaepDepadder(padding.OaepHashAlgorithm);
                return Interop.Crypto.RsaPadding.NoPadding;
            }

            throw PaddingModeNotSupported();
        }

        private static Dictionary<HashAlgorithmName, DepaddingMethod> s_oaepDepadders =
            new Dictionary<HashAlgorithmName,DepaddingMethod>();

        private static DepaddingMethod GetOaepDepadder(HashAlgorithmName hashAlgorithmName)
        {
            if (s_oaepDepadders.TryGetValue(hashAlgorithmName, out DepaddingMethod method))
            {
                return method;
            }

            lock (s_oaepDepadders)
            {
                if (s_oaepDepadders.TryGetValue(hashAlgorithmName, out method))
                {
                    return method;
                }

                byte[] hashBytes;

                try
                {
                    // Test that the algorithm is valid
                    using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithmName))
                    {
                        hashBytes = hasher.GetHashAndReset();
                    }
                }
                catch (CryptographicException)
                {
                    throw PaddingModeNotSupported();
                }

                return (ReadOnlySpan<byte> source, Span<byte> destination, out int bytesWritten) =>
                    OaepMgf1Depadder(hashAlgorithmName, hashBytes.Length, source, destination, out bytesWritten);
            }
        }

        private static void OaepMgf1Depadder(
            HashAlgorithmName hashAlgorithmName,
            int hLen,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            // https://tools.ietf.org/html/rfc3447#section-7.1.2
            using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithmName))
            {
                Span<byte> lHash = stackalloc byte[hLen];

                if (!hasher.TryGetHashAndReset(lHash, out int hLen2) || hLen2 != hLen)
                {
                    Debug.Fail("TryGetHashAndReset failed with exact-size destination");
                    throw new CryptographicException();
                }

                int y = source[0];
                ReadOnlySpan<byte> maskedSeed = source.Slice(1, hLen);
                ReadOnlySpan<byte> maskedDB = source.Slice(1 + hLen);

                Span<byte> seed = stackalloc byte[hLen];
                // seedMask = MGF(maskedDB, hLen)
                Mgf1(hasher, hLen, maskedDB, seed);

                // seed = seedMask XOR maskedSeed
                for (int i = 0; i < seed.Length; i++)
                {
                    seed[i] ^= maskedSeed[i];
                }

                byte[] tmp = ArrayPool<byte>.Shared.Rent(source.Length);

                try
                {
                    Span<byte> dbMask = new Span<byte>(tmp, 0, maskedDB.Length);
                    // dbMask = MGF(seed, k - hLen - 1)
                    Mgf1(hasher, hLen, seed, dbMask);

                    // DB = dbMask XOR maskedDB
                    for (int i = 0; i < dbMask.Length; i++)
                    {
                        dbMask[i] ^= maskedDB[i];
                    }

                    ReadOnlySpan<byte> lHashPrime = dbMask.Slice(0, hLen);

                    int separatorPos = int.MaxValue;

                    for (int i = dbMask.Length - 1; i >= hLen; i--)
                    {
                        // if dbMask[i] is 1, val is 0. otherwise val is [01,FF]
                        byte dbMinus1 = (byte)(dbMask[i] - 1);
                        int val = dbMinus1;

                        // if val is 0: FFFFFFFF & FFFFFFFF => FFFFFFFF
                        // if val is any other byte value, val-1 will be in the range 00000000 to 000000FE,
                        // and so the high bit will not be set.
                        val = (~val & (val - 1)) >> 31;

                        // if val is 0: separator = (0 & i) | (~0 & separator) => separator
                        // else: separator = (~0 & i) | (0 & separator) => i
                        //
                        // Net result: non-branching if (dbMask[i] == 1) separatorPos = i;
                        separatorPos = (val & i) | (~val & separatorPos);
                    }

                    bool lHashMatches = FixedTimeEquals(lHashPrime, lHashPrime);
                    bool yIsZero = y == 0;
                    bool separatorMadeSense = separatorPos < dbMask.Length;

                    bool shouldContinue = lHashMatches & yIsZero & separatorMadeSense;

                    if (!shouldContinue)
                    {
                        throw new CryptographicException("Padding failed.");
                    }

                    Span<byte> message = dbMask.Slice(separatorPos + 1);
                    message.CopyTo(destination);
                    bytesWritten = message.Length;
                }
                finally
                {
                    Array.Clear(tmp, 0, source.Length);
                    ArrayPool<byte>.Shared.Return(tmp);
                }
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        private static bool FixedTimeEquals(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
        {
            if (left.Length != right.Length)
            {
                return false;
            }

            int accum = 0;
            int len = left.Length;

            for (int i = 0; i < len; i++)
            {
                accum |= (left[i] - right[i]);
            }

            return accum == 0;
        }

        // https://tools.ietf.org/html/rfc3447#appendix-B.2.1
        private static void Mgf1(IncrementalHash hasher, int hLen, ReadOnlySpan<byte> mgfSeed, Span<byte> mask)
        {
            Span<byte> writePtr = mask;
            int count = 0;
            Span<byte> bigEndianCount = stackalloc byte[sizeof(int)];

            while (writePtr.Length > 0)
            {
                hasher.AppendData(mgfSeed);
                BinaryPrimitives.WriteInt32BigEndian(bigEndianCount, count);
                hasher.AppendData(bigEndianCount);

                if (writePtr.Length > hLen)
                {
                    if (!hasher.TryGetHashAndReset(writePtr, out int bytesWritten))
                    {
                        Debug.Fail($"TryGetHashAndReset failed with sufficient space");
                        throw new CryptographicException();
                    }

                    Debug.Assert(bytesWritten == hLen);
                    writePtr = writePtr.Slice(bytesWritten);
                }
                else
                {
                    Span<byte> tmp = stackalloc byte[hLen];

                    if (!hasher.TryGetHashAndReset(tmp, out int bytesWritten))
                    {
                        Debug.Fail($"TryGetHashAndReset failed with sufficient space");
                        throw new CryptographicException();
                    }

                    Debug.Assert(bytesWritten == hLen);
                    tmp.Slice(0, writePtr.Length).CopyTo(writePtr);
                    break;
                }

                count++;
            }
        }

        private static Interop.Crypto.RsaPadding GetInteropPadding(RSAEncryptionPadding padding) =>
            padding == RSAEncryptionPadding.Pkcs1 ? Interop.Crypto.RsaPadding.Pkcs1 :
            padding == RSAEncryptionPadding.OaepSHA1 ? Interop.Crypto.RsaPadding.OaepSHA1 :
            Interop.Crypto.RsaPadding.NoPadding;

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            // It's entirely possible that this line will cause the key to be generated in the first place.
            SafeRsaHandle key = _key.Value;

            CheckInvalidKey(key);

            RSAParameters rsaParameters = Interop.Crypto.ExportRsaParameters(key, includePrivateParameters);
            bool hasPrivateKey = rsaParameters.D != null;

            if (hasPrivateKey != includePrivateParameters || !HasConsistentPrivateKey(ref rsaParameters))
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            return rsaParameters;
        }
        
        public override void ImportParameters(RSAParameters parameters)
        {
            ValidateParameters(ref parameters);

            SafeRsaHandle key = Interop.Crypto.RsaCreate();
            bool imported = false;

            Interop.Crypto.CheckValidOpenSslHandle(key);

            try
            {
                Interop.Crypto.SetRsaParameters(
                    key,
                    parameters.Modulus,
                    parameters.Modulus != null ? parameters.Modulus.Length : 0,
                    parameters.Exponent,
                    parameters.Exponent != null ? parameters.Exponent.Length : 0,
                    parameters.D,
                    parameters.D != null ? parameters.D.Length : 0,
                    parameters.P,
                    parameters.P != null ? parameters.P.Length : 0,
                    parameters.DP, 
                    parameters.DP != null ? parameters.DP.Length : 0,
                    parameters.Q,
                    parameters.Q != null ? parameters.Q.Length : 0,
                    parameters.DQ, 
                    parameters.DQ != null ? parameters.DQ.Length : 0,
                    parameters.InverseQ,
                    parameters.InverseQ != null ? parameters.InverseQ.Length : 0);

                imported = true;
            }
            finally
            {
                if (!imported)
                {
                    key.Dispose();
                }
            }

            FreeKey();
            _key = new Lazy<SafeRsaHandle>(key);

            // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
            // with the already loaded key.
            ForceSetKeySize(BitsPerByte * Interop.Crypto.RsaSize(key));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                FreeKey();
            }

            base.Dispose(disposing);
        }

        private void FreeKey()
        {
            if (_key != null && _key.IsValueCreated)
            {
                SafeRsaHandle handle = _key.Value;
                handle?.Dispose();
            }
        }

        private static void ValidateParameters(ref RSAParameters parameters)
        {
            if (parameters.Modulus == null || parameters.Exponent == null)
                throw new CryptographicException(SR.Argument_InvalidValue);

            if (!HasConsistentPrivateKey(ref parameters))
                throw new CryptographicException(SR.Argument_InvalidValue);
        }

        private static bool HasConsistentPrivateKey(ref RSAParameters parameters)
        {
            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    return false;
                }
            }
            else
            {
                if (parameters.P == null ||
                    parameters.DP == null ||
                    parameters.Q == null ||
                    parameters.DQ == null ||
                    parameters.InverseQ == null)
                {
                    return false;
                }
            }

            return true;
        }

        private static void CheckInvalidKey(SafeRsaHandle key)
        {
            if (key == null || key.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }
        }

        private static void CheckReturn(int returnValue)
        {
            if (returnValue == -1)
            {
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }

        private static void CheckBoolReturn(int returnValue)
        {
            if (returnValue != 1)
            {
               throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }

        private SafeRsaHandle GenerateKey()
        {
            SafeRsaHandle key = Interop.Crypto.RsaCreate();
            bool generated = false;

            Interop.Crypto.CheckValidOpenSslHandle(key);

            try
            {
                using (SafeBignumHandle exponent = Interop.Crypto.CreateBignum(s_defaultExponent))
                {
                    // The documentation for RSA_generate_key_ex does not say that it returns only
                    // 0 or 1, so the call marshals it back as a full Int32 and checks for a value
                    // of 1 explicitly.
                    int response = Interop.Crypto.RsaGenerateKeyEx(
                        key,
                        KeySize,
                        exponent);

                    CheckBoolReturn(response);
                    generated = true;
                }
            }
            finally
            {
                if (!generated)
                {
                    key.Dispose();
                }
            }

            return key;
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

        protected override bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
            AsymmetricAlgorithmHelpers.TryHashData(source, destination, hashAlgorithm, out bytesWritten);

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw HashAlgorithmNameNullOrEmpty();
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));
            if (padding != RSASignaturePadding.Pkcs1)
                throw PaddingModeNotSupported();

            return SignHash(hash, hashAlgorithm);
        }

        private byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithmName)
        {
            int algorithmNid = GetAlgorithmNid(hashAlgorithmName);
            SafeRsaHandle rsa = _key.Value;
            byte[] signature = new byte[Interop.Crypto.RsaSize(rsa)];
            int signatureSize;

            bool success = Interop.Crypto.RsaSign(
                algorithmNid,
                hash,
                hash.Length,
                signature,
                out signatureSize,
                rsa);

            if (!success)
            {
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            Debug.Assert(
                signatureSize == signature.Length,
                "RSA_sign reported an unexpected signature size",
                "RSA_sign reported signatureSize was {0}, when {1} was expected",
                signatureSize,
                signature.Length);

            return signature;
        }

        public override bool TrySignHash(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding, out int bytesWritten)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }
            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw PaddingModeNotSupported();
            }

            int algorithmNid = GetAlgorithmNid(hashAlgorithm);
            SafeRsaHandle rsa = _key.Value;

            int bytesRequired = Interop.Crypto.RsaSize(rsa);
            if (destination.Length < bytesRequired)
            {
                bytesWritten = 0;
                return false;
            }

            int signatureSize;
            if (!Interop.Crypto.RsaSign(algorithmNid, source, source.Length, destination, out signatureSize, rsa))
            {
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }

            Debug.Assert(signatureSize == bytesRequired, $"RSA_sign reported signatureSize was {signatureSize}, when {bytesRequired} was expected");
            bytesWritten = signatureSize;
            return true;
        }

        public override bool VerifyHash(
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            return VerifyHash(new ReadOnlySpan<byte>(hash), new ReadOnlySpan<byte>(signature), hashAlgorithm, padding);
        }

        public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }
            if (padding != RSASignaturePadding.Pkcs1)
            {
                throw PaddingModeNotSupported();
            }

            int algorithmNid = GetAlgorithmNid(hashAlgorithm);
            SafeRsaHandle rsa = _key.Value;
            return Interop.Crypto.RsaVerify(algorithmNid, hash, hash.Length, signature, signature.Length, rsa);
        }

        private static int GetAlgorithmNid(HashAlgorithmName hashAlgorithmName)
        {
            // All of the current HashAlgorithmName values correspond to the SN values in OpenSSL 0.9.8.
            // If there's ever a new one that doesn't, translate it here.
            string sn = hashAlgorithmName.Name;

            int nid = Interop.Crypto.ObjSn2Nid(sn);

            if (nid == Interop.Crypto.NID_undef)
            {
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }

            return nid;
        }

        private static Exception PaddingModeNotSupported() =>
            new CryptographicException(SR.Cryptography_InvalidPaddingMode);

        private static Exception HashAlgorithmNameNullOrEmpty() =>
            new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");
    }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
