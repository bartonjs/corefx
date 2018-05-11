// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    internal static class PasswordBasedEncryption
    {
        private static ArrayPool<byte> ArrayPool => ArrayPool<byte>.Shared;

        [SuppressMessage("Microsoft.Security", "CA5350", Justification = "3DES used when specified by the input data")]
        [SuppressMessage("Microsoft.Security", "CA5351", Justification = "DES used when specified by the input data")]
        internal static unsafe int Decrypt(
            in AlgorithmIdentifierAsn algorithmIdentifier,
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            Debug.Assert(destination.Length >= encryptedData.Length);

            // Don't check that algorithmIdentifier.Parameters is set here.
            // Maybe some future PBES3 will have one with a default.

            HashAlgorithmName digestAlgorithmName;
            SymmetricAlgorithm cipher = null;

            bool pkcs12 = false;

            switch (algorithmIdentifier.Algorithm.Value)
            {
                case Oids.PbeWithMD5AndDESCBC:
                    digestAlgorithmName = HashAlgorithmName.MD5;
                    cipher = DES.Create();
                    break;
                case Oids.PbeWithMD5AndRC2CBC:
                    digestAlgorithmName = HashAlgorithmName.MD5;
                    cipher = RC2.Create();
                    break;
                case Oids.PbeWithSha1AndDESCBC:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = DES.Create();
                    break;
                case Oids.PbeWithSha1AndRC2CBC:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = RC2.Create();
                    break;
                case Oids.Pkcs12PbeWithShaAnd3Key3Des:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = TripleDES.Create();
                    pkcs12 = true;
                    break;
                case Oids.Pkcs12PbeWithShaAnd2Key3Des:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = TripleDES.Create();
                    cipher.KeySize = 128;
                    pkcs12 = true;
                    break;
                case Oids.Pkcs12PbeWithShaAnd128BitRC2:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = RC2.Create();
                    cipher.KeySize = 128;
                    pkcs12 = true;
                    break;
                case Oids.Pkcs12PbeWithShaAnd40BitRC2:
                    digestAlgorithmName = HashAlgorithmName.SHA1;
                    cipher = RC2.Create();
                    cipher.KeySize = 40;
                    pkcs12 = true;
                    break;
                case Oids.PasswordBasedEncryptionScheme2:
                    return Pbes2Decrypt(
                        algorithmIdentifier.Parameters,
                        password,
                        passwordBytes,
                        encryptedData,
                        destination);
                default:
                    throw new CryptographicException(
                        SR.Format(
                            SR.Cryptography_UnknownAlgorithmIdentifier,
                            algorithmIdentifier.Algorithm.Value));
            }

            Debug.Assert(digestAlgorithmName.Name != null);
            Debug.Assert(cipher != null);

            using (cipher)
            {
                if (pkcs12)
                {
                    if (passwordBytes.Length > 0 && password.Length == 0)
                    {
                        throw new CryptographicException(
                            $"The KDF for algorithm '{algorithmIdentifier.Algorithm}' requires a char-based password input.");
                    }

                    return Pkcs12PbeDecrypt(
                        algorithmIdentifier,
                        password,
                        digestAlgorithmName,
                        cipher,
                        encryptedData,
                        destination);
                }

                using (IncrementalHash hasher = IncrementalHash.CreateHash(digestAlgorithmName))
                {
                    Span<byte> buf = stackalloc byte[128];
                    ReadOnlySpan<byte> effectivePasswordBytes = stackalloc byte[0];
                    byte[] rented = null;
                    System.Text.Encoding encoding = null;

                    if (passwordBytes.Length > 0 || password.Length == 0)
                    {
                        effectivePasswordBytes = passwordBytes;
                    }
                    else
                    {
                        encoding = System.Text.Encoding.UTF8;
                        int byteCount = encoding.GetByteCount(password);

                        if (byteCount > buf.Length)
                        {
                            rented = ArrayPool.Rent(byteCount);
                            buf = rented.AsSpan(0, byteCount);
                        }
                        else
                        {
                            buf = buf.Slice(0, byteCount);
                        }
                    }

                    fixed (byte* maybeRentedPtr = &MemoryMarshal.GetReference(buf))
                    {
                        if (encoding != null)
                        {
                            int written = encoding.GetBytes(password, buf);
                            Debug.Assert(written == buf.Length);
                            buf = buf.Slice(0, written);
                            effectivePasswordBytes = buf;
                        }

                        try
                        {
                            return Pbes1Decrypt(
                                algorithmIdentifier.Parameters,
                                effectivePasswordBytes,
                                hasher,
                                cipher,
                                encryptedData,
                                destination);
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(buf);

                            if (rented != null)
                            {
                                ArrayPool.Return(rented);
                            }
                        }
                    }
                }
            }
        }

        internal static void InitiateEncryption(
            PbeParameters pbeParameters,
            out SymmetricAlgorithm cipher,
            out string hmacOid,
            out string encryptionAlgorithmOid,
            out bool isPkcs12)
        {
            isPkcs12 = false;

            switch (pbeParameters.EncryptionAlgorithm)
            {
                case PbeEncryptionAlgorithm.Aes128Cbc:
                    cipher = Aes.Create();
                    cipher.KeySize = 128;
                    encryptionAlgorithmOid = Oids.Aes128Cbc;
                    break;
                case PbeEncryptionAlgorithm.Aes192Cbc:
                    cipher = Aes.Create();
                    cipher.KeySize = 192;
                    encryptionAlgorithmOid = Oids.Aes192Cbc;
                    break;
                case PbeEncryptionAlgorithm.Aes256Cbc:
                    cipher = Aes.Create();
                    cipher.KeySize = 256;
                    encryptionAlgorithmOid = Oids.Aes256Cbc;
                    break;
                case PbeEncryptionAlgorithm.TripleDes3KeyPkcs12:
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
                    cipher = TripleDES.Create();
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
                    cipher.KeySize = 192;
                    encryptionAlgorithmOid = Oids.Pkcs12PbeWithShaAnd3Key3Des;
                    isPkcs12 = true;
                    break;
                default:
                    throw new CryptographicException(
                        SR.Format(
                            SR.Cryptography_UnknownAlgorithmIdentifier,
                            pbeParameters.HashAlgorithm.Name));
            }

            HashAlgorithmName prf = pbeParameters.HashAlgorithm;

            if (prf == HashAlgorithmName.SHA256)
            {
                hmacOid = Oids.HmacWithSha256;
            }
            else if (prf == HashAlgorithmName.SHA384)
            {
                hmacOid = Oids.HmacWithSha384;
            }
            else if (prf == HashAlgorithmName.SHA512)
            {
                hmacOid = Oids.HmacWithSha512;
            }
            else if (prf == HashAlgorithmName.SHA1)
            {
                hmacOid = Oids.HmacWithSha1;
            }
            else
            {
                cipher.Dispose();
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, prf.Name);
            }

            if (isPkcs12)
            {
                if (hmacOid != Oids.HmacWithSha1)
                {
                    // PKCS12 uses a combined PRF+cipher OID, no SHA-2 based OIDs are defined.
                    cipher.Dispose();
                    throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, prf.Name);
                }
            }
        }

        internal static unsafe int Encrypt(
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> passwordBytes,
            SymmetricAlgorithm cipher,
            bool isPkcs12,
            ReadOnlySpan<byte> source,
            PbeParameters pbeParameters,
            ReadOnlySpan<byte> salt,
            byte[] destination,
            Span<byte> ivDest)
        {
            byte[] pwdTmpBytes = isPkcs12 ? null : new byte[passwordBytes.Length];
            byte[] derivedKey;
            byte[] iv = cipher.IV;

            byte[] sourceRent = ArrayPool.Rent(source.Length);
            int keySizeBytes = cipher.KeySize / 8;
            int iterationCount = pbeParameters.KdfIterationCount;
            HashAlgorithmName prf = pbeParameters.HashAlgorithm;

            fixed (byte* pkcs8RentPin = sourceRent)
            fixed (byte* pwdTmpBytesPtr = pwdTmpBytes)
            {
                if (isPkcs12)
                {
                    derivedKey = new byte[keySizeBytes];
                    uint iterationCountU = checked((uint)iterationCount);

                    Pkcs12Kdf.DeriveCipherKey(
                        password,
                        prf,
                        iterationCountU,
                        salt,
                        derivedKey);

                    Pkcs12Kdf.DeriveIV(
                        password,
                        prf,
                        iterationCountU,
                        salt,
                        iv);

                    ivDest.Clear();
                }
                else
                {
                    passwordBytes.CopyTo(pwdTmpBytes);

                    using (var pbkdf2 = new Rfc2898DeriveBytes(pwdTmpBytes, salt.ToArray(), iterationCount, prf))
                    {
                        derivedKey = pbkdf2.GetBytes(keySizeBytes);
                    }

                    iv.CopyTo(ivDest);
                }

                fixed (byte* keyPtr = derivedKey)
                {
                    CryptographicOperations.ZeroMemory(pwdTmpBytes);

                    using (ICryptoTransform encryptor = cipher.CreateEncryptor(derivedKey, iv))
                    {
                        Debug.Assert(encryptor.CanTransformMultipleBlocks);

                        int blockSizeBytes = (cipher.BlockSize / 8);
                        int remaining = source.Length % blockSizeBytes;
                        int fullBlocksLength = source.Length - remaining;

                        try
                        {
                            source.CopyTo(sourceRent);

                            int written = encryptor.TransformBlock(
                                sourceRent,
                                0,
                                fullBlocksLength,
                                destination,
                                0);

                            byte[] lastBlock = encryptor.TransformFinalBlock(
                                sourceRent,
                                written,
                                remaining);

                            lastBlock.AsSpan().CopyTo(destination.AsSpan(written));
                            return written + lastBlock.Length;
                        }
                        finally
                        {
                            CryptographicOperations.ZeroMemory(sourceRent.AsSpan(0, source.Length));
                            ArrayPool.Return(sourceRent);
                        }
                    }
                }
            }
        }

        private static unsafe int Pbes2Decrypt(
            ReadOnlyMemory<byte>? algorithmParameters,
            ReadOnlySpan<char> password,
            ReadOnlySpan<byte> passwordBytes,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            Span<byte> buf = stackalloc byte[128];
            ReadOnlySpan<byte> effectivePasswordBytes = stackalloc byte[0];
            byte[] rented = null;
            System.Text.Encoding encoding = null;

            if (passwordBytes.Length > 0 || password.Length == 0)
            {
                effectivePasswordBytes = passwordBytes;
            }
            else
            {
                encoding = System.Text.Encoding.UTF8;
                int byteCount = encoding.GetByteCount(password);

                if (byteCount > buf.Length)
                {
                    rented = ArrayPool.Rent(byteCount);
                    buf = rented.AsSpan(0, byteCount);
                }
                else
                {
                    buf = buf.Slice(0, byteCount);
                }
            }

            fixed (byte* maybeRentedPtr = &MemoryMarshal.GetReference(buf))
            {
                if (encoding != null)
                {
                    int written = encoding.GetBytes(password, buf);
                    Debug.Assert(written == buf.Length);
                    buf = buf.Slice(0, written);
                    effectivePasswordBytes = buf;
                }

                return Pbes2Decrypt(
                    algorithmParameters,
                    effectivePasswordBytes,
                    encryptedData,
                    destination);
            }
        }

        private static unsafe int Pbes2Decrypt(
            ReadOnlyMemory<byte>? algorithmParameters,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            if (!algorithmParameters.HasValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            PBES2Params pbes2Params =
                AsnSerializer.Deserialize<PBES2Params>(algorithmParameters.Value, AsnEncodingRules.BER);

            if (pbes2Params.KeyDerivationFunc.Algorithm.Value != Oids.Pbkdf2)
            {
                throw new CryptographicException(
                    SR.Format(
                        SR.Cryptography_UnknownAlgorithmIdentifier,
                        pbes2Params.EncryptionScheme.Algorithm.Value));
            }

            Rfc2898DeriveBytes pbkdf2 =
                OpenPbkdf2(password, pbes2Params.KeyDerivationFunc.Parameters, out byte? requestedKeyLength);

            using (pbkdf2)
            {
                // The biggest block size (for IV) we support is AES (128-bit / 16 byte)
                Span<byte> iv = stackalloc byte[16];

                SymmetricAlgorithm cipher = OpenCipher(
                    pbes2Params.EncryptionScheme,
                    requestedKeyLength,
                    ref iv);

                byte[] key = pbkdf2.GetBytes(cipher.KeySize / 8);

                fixed (byte* keyPtr = key)
                {
                    try
                    {
                        return Decrypt(cipher, key, iv, encryptedData, destination);
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(key);
                    }
                }
            }
        }

        [SuppressMessage("Microsoft.Security", "CA5351", Justification = "DES used when specified by the input data")]
        private static SymmetricAlgorithm OpenCipher(
            AlgorithmIdentifierAsn encryptionScheme,
            byte? requestedKeyLength,
            ref Span<byte> iv)
        {
            string algId = encryptionScheme.Algorithm.Value;

            if (algId == Oids.Aes128Cbc ||
                algId == Oids.Aes192Cbc ||
                algId == Oids.Aes256Cbc)
            {
                // https://tools.ietf.org/html/rfc8018#appendix-B.2.5
                int correctKeySize;

                switch (algId)
                {
                    case Oids.Aes128Cbc:
                        correctKeySize = 16;
                        break;
                    case Oids.Aes192Cbc:
                        correctKeySize = 24;
                        break;
                    case Oids.Aes256Cbc:
                        correctKeySize = 32;
                        break;
                    default:
                        Debug.Fail("Key-sized OID included in the if, but not the switch");
                        throw new CryptographicException();
                }

                if (requestedKeyLength != null && requestedKeyLength != correctKeySize)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // The parameters field ... shall have type OCTET STRING (SIZE(16))
                // specifying the initialization vector ...

                ReadIvParameter(encryptionScheme.Parameters, 16, ref iv);

                Aes aes = Aes.Create();
                aes.KeySize = correctKeySize * 8;
                return aes;
            }

            if (algId == Oids.TripleDesCbc)
            {
                // https://tools.ietf.org/html/rfc8018#appendix-B.2.2

                // ... has a 24-octet encryption key ...
                if (requestedKeyLength != null && requestedKeyLength != 24)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // The parameters field associated with this OID ... shall have type
                // OCTET STRING (SIZE(8)) specifying the initialization vector ...
                ReadIvParameter(encryptionScheme.Parameters, 8, ref iv);
#pragma warning disable CA5350 // Input requested 3DES.
                return TripleDES.Create();
#pragma warning restore CA5350
            }

            if (algId == Oids.Rc2Cbc)
            {
                // https://tools.ietf.org/html/rfc8018#appendix-B.2.3

                if (encryptionScheme.Parameters == null)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // RC2 has a variable key size. RFC 8018 does not define a default,
                // so of PBKDF2 didn't provide it, fail.
                if (requestedKeyLength == null)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                Rc2CbcParameters rc2Parameters = AsnSerializer.Deserialize<Rc2CbcParameters>(
                    encryptionScheme.Parameters.Value,
                    AsnEncodingRules.BER);

                // iv is the eight-octet initialization vector
                if (rc2Parameters.Iv.Length != 8)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                RC2 rc2 = RC2.Create();
                rc2.KeySize = requestedKeyLength.Value * 8;
                rc2.EffectiveKeySize = rc2Parameters.GetEffectiveKeyBits();

                rc2Parameters.Iv.Span.CopyTo(iv);
                iv = iv.Slice(0, rc2Parameters.Iv.Length);
                return rc2;
            }

            if (algId == Oids.DesCbc)
            {
                // https://tools.ietf.org/html/rfc8018#appendix-B.2.1

                // ... has an eight-octet encryption key ...
                if (requestedKeyLength != null && requestedKeyLength != 8)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // The parameters field associated with this OID ... shall have type
                // OCTET STRING (SIZE(8)) specifying the initialization vector ...
                ReadIvParameter(encryptionScheme.Parameters, 8, ref iv);
                return DES.Create();
            }

            throw new CryptographicException(SR.Cryptography_UnknownAlgorithmIdentifier, algId);
        }

        private static void ReadIvParameter(
            ReadOnlyMemory<byte>? encryptionSchemeParameters,
            int length,
            ref Span<byte> iv)
        {
            if (encryptionSchemeParameters == null)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            AsnReader reader = new AsnReader(encryptionSchemeParameters.Value, AsnEncodingRules.BER);

            if (!reader.TryCopyOctetStringBytes(iv, out int bytesWritten) || bytesWritten != length)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            reader.ThrowIfNotEmpty();
            iv = iv.Slice(0, bytesWritten);
        }

        private static unsafe Rfc2898DeriveBytes OpenPbkdf2(
            ReadOnlySpan<byte> password,
            ReadOnlyMemory<byte>? parameters,
            out byte? requestedKeyLength)
        {
            if (!parameters.HasValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            Pbkdf2Params pbkdf2Params =
                AsnSerializer.Deserialize<Pbkdf2Params>(parameters.Value, AsnEncodingRules.BER);

            // No OtherSource is defined in RFC 2898 or RFC 8018, so whatever
            // algorithm was requested isn't one we know.
            if (pbkdf2Params.Salt.OtherSource != null)
            {
                throw new CryptographicException(
                    SR.Format(
                        SR.Cryptography_UnknownAlgorithmIdentifier,
                        pbkdf2Params.Salt.OtherSource.Value.Algorithm));
            }

            if (pbkdf2Params.Salt.Specified == null)
            {
                Debug.Fail($"No Specified Salt value is present, indicating a new choice was unhandled");
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            HashAlgorithmName prf;

            switch (pbkdf2Params.Prf.Algorithm.Value)
            {
                case Oids.HmacWithSha1:
                    prf = HashAlgorithmName.SHA1;
                    break;
                case Oids.HmacWithSha256:
                    prf = HashAlgorithmName.SHA256;
                    break;
                case Oids.HmacWithSha384:
                    prf = HashAlgorithmName.SHA384;
                    break;
                case Oids.HmacWithSha512:
                    prf = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new CryptographicException(
                        SR.Format(
                            SR.Cryptography_UnknownAlgorithmIdentifier,
                            pbkdf2Params.Prf.Algorithm));
            }

            // All of the PRFs that we know about have NULL parameters, so check that now that we know
            // it's not just that we don't know the algorithm.

            if (!pbkdf2Params.Prf.HasNullEquivalentParameters())
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ReadOnlyMemory<byte> saltMemory = pbkdf2Params.Salt.Specified.Value;

            byte[] tmpPassword = new byte[password.Length];
            byte[] tmpSalt = new byte[saltMemory.Length];

            fixed (byte* tmpPasswordPtr = tmpPassword)
            fixed (byte* tmpSaltPtr = tmpSalt)
            {
                password.CopyTo(tmpPassword);
                saltMemory.CopyTo(tmpSalt);

                try
                {
                    requestedKeyLength = pbkdf2Params.KeyLength;

                    return new Rfc2898DeriveBytes(
                        tmpPassword,
                        tmpSalt,
                        checked((int)pbkdf2Params.IterationCount),
                        prf);
                }
                catch (ArgumentException e)
                {
                    // Salt too small is the most likely candidate.
                    throw new CryptographicException(SR.Argument_InvalidValue, e);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tmpPassword);
                    CryptographicOperations.ZeroMemory(tmpSalt);
                }
            }
        }

        private static int Pbes1Decrypt(
            ReadOnlyMemory<byte>? algorithmParameters,
            ReadOnlySpan<byte> password,
            IncrementalHash hasher,
            SymmetricAlgorithm cipher,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            // https://tools.ietf.org/html/rfc2898#section-6.1.2

            // 1. Obtain the eight-octet salt S and iteration count c.
            if (!algorithmParameters.HasValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            PBEParameter pbeParameters =
                AsnSerializer.Deserialize<PBEParameter>(algorithmParameters.Value, AsnEncodingRules.BER);

            if (pbeParameters.Salt.Length != 8)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (pbeParameters.IterationCount < 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // 2. Apply PBKDF1<hash>(P, S, c, 16) to produce a derived key DK of length 16 octets
            Span<byte> dk = stackalloc byte[16];

            try
            {
                Pbkdf1(hasher, password, pbeParameters.Salt.Span, pbeParameters.IterationCount, dk);

                // 3. Separate the derived key DK into an encryption key K consisting of the
                // first eight octets of DK and an initialization vector IV consisting of the
                // next 8.
                Span<byte> k = dk.Slice(0, 8);
                Span<byte> iv = dk.Slice(8, 8);

                // 4 & 5 together are "use CBC with what eventually became called PKCS7 padding"
                return Decrypt(cipher, k, iv, encryptedData, destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(dk);
            }
        }

        private static unsafe int Pkcs12PbeDecrypt(
            AlgorithmIdentifierAsn algorithmIdentifier,
            ReadOnlySpan<char> password,
            HashAlgorithmName hashAlgorithm,
            SymmetricAlgorithm cipher,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            // https://tools.ietf.org/html/rfc7292#appendix-C

            if (!algorithmIdentifier.Parameters.HasValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // 3DES, "two-key" 3DES, RC2-128 and RC2-40 are the only ciphers that should be here.
            // That means 64-bit block sizes and 192-bit keys (3DES-3).  So stack allocated key/IV are safe.
            if (cipher.KeySize > 256 || cipher.BlockSize > 256)
            {
                Debug.Fail(
                    $"Unexpected cipher characteristics by {cipher.GetType().FullName}, KeySize={cipher.KeySize}, BlockSize={cipher.BlockSize}");

                throw new CryptographicException();
            }

            PBEParameter pbeParameters = AsnSerializer.Deserialize<PBEParameter>(
                algorithmIdentifier.Parameters.Value,
                AsnEncodingRules.BER);

            Span<byte> iv = stackalloc byte[cipher.BlockSize / 8];
            Span<byte> key = stackalloc byte[cipher.KeySize / 8];
            ReadOnlySpan<byte> saltSpan = pbeParameters.Salt.Span;

            try
            {
                Pkcs12Kdf.DeriveIV(
                    password,
                    hashAlgorithm,
                    pbeParameters.IterationCount,
                    saltSpan,
                    iv);

                Pkcs12Kdf.DeriveCipherKey(
                    password,
                    hashAlgorithm,
                    pbeParameters.IterationCount,
                    saltSpan,
                    key);

                return Decrypt(cipher, key, iv, encryptedData, destination);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(key);
                CryptographicOperations.ZeroMemory(iv);
            }
        }

        private static unsafe int Decrypt(
            SymmetricAlgorithm cipher,
            ReadOnlySpan<byte> key,
            ReadOnlySpan<byte> iv,
            ReadOnlySpan<byte> encryptedData,
            Span<byte> destination)
        {
            // TODO: Make some Span-based symmetric API, and use it.
            byte[] tmpKey = new byte[key.Length];
            byte[] tmpIv = new byte[iv.Length];
            byte[] rentedEncryptedData = ArrayPool.Rent(encryptedData.Length);
            byte[] rentedDestination = ArrayPool.Rent(destination.Length);

            // Keep all the arrays pinned so they can be correctly cleared
            fixed (byte* tmpKeyPtr = tmpKey)
            fixed (byte* tmpIvPtr = tmpIv)
            fixed (byte* rentedEncryptedDataPtr = rentedEncryptedData)
            fixed (byte* rentedDestinationPtr = rentedDestination)
            {
                try
                {
                    key.CopyTo(tmpKey);
                    iv.CopyTo(tmpIv);

                    using (ICryptoTransform decryptor = cipher.CreateDecryptor(tmpKey, tmpIv))
                    {
                        Debug.Assert(decryptor.CanTransformMultipleBlocks);

                        encryptedData.CopyTo(rentedEncryptedData);

                        int writeOffset = decryptor.TransformBlock(
                            rentedEncryptedData,
                            0,
                            encryptedData.Length,
                            rentedDestination,
                            0);

                        rentedDestination.AsSpan(0, writeOffset).CopyTo(destination);

                        byte[] tmpEnd = decryptor.TransformFinalBlock(Array.Empty<byte>(), 0, 0);

                        fixed (byte* tmpEndPtr = tmpEnd)
                        {
                            Span<byte> tmpEndSpan = tmpEnd.AsSpan();
                            tmpEndSpan.CopyTo(destination.Slice(writeOffset));
                            CryptographicOperations.ZeroMemory(tmpEndSpan);
                        }

                        return writeOffset + tmpEnd.Length;
                    }
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(tmpKey);
                    CryptographicOperations.ZeroMemory(tmpIv);
                    CryptographicOperations.ZeroMemory(rentedEncryptedData.AsSpan(0, encryptedData.Length));
                    CryptographicOperations.ZeroMemory(rentedDestination.AsSpan(0, destination.Length));

                    ArrayPool.Return(rentedEncryptedData);
                    ArrayPool.Return(rentedDestination);
                }
            }
        }

        private static void Pbkdf1(
            IncrementalHash hasher,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            uint iterationCount,
            Span<byte> dk)
        {
            // The only two hashes that will call into this implementation are
            // MD5 (16 bytes) and SHA-1 (20 bytes).
            Span<byte> t = stackalloc byte[20];

            // https://tools.ietf.org/html/rfc2898#section-5.1

            // T_1 = Hash(P || S)
            hasher.AppendData(password);
            hasher.AppendData(salt);

            if (!hasher.TryGetHashAndReset(t, out int tLength))
            {
                Debug.Fail("TryGetHashAndReset failed with pre-allocated input");
                throw new CryptographicException();
            }

            t = t.Slice(0, tLength);

            // T_i = H(T_(i-1))
            for (uint i = 1; i < iterationCount; i++)
            {
                hasher.AppendData(t);

                if (!hasher.TryGetHashAndReset(t, out tLength) || tLength != t.Length)
                {
                    Debug.Fail("TryGetHashAndReset failed with pre-allocated input");
                    throw new CryptographicException();
                }
            }

            // DK = T_c<0..dkLen-1>
            t.Slice(0, dk.Length).CopyTo(dk);
            CryptographicOperations.ZeroMemory(t);
        }

        internal static void WritePbeAlgorithmIdentifier(
            AsnWriter writer,
            bool isPkcs12,
            string encryptionAlgorithmOid,
            Span<byte> salt,
            int iterationCount,
            string hmacOid,
            Span<byte> iv)
        {
            writer.PushSequence();

            if (isPkcs12)
            {
                writer.WriteObjectIdentifier(encryptionAlgorithmOid);

                // pkcs-12PbeParams
                {
                    writer.PushSequence();
                    writer.WriteOctetString(salt);
                    writer.WriteInteger(iterationCount);
                    writer.PopSequence();
                }
            }
            else
            {
                writer.WriteObjectIdentifier(Oids.PasswordBasedEncryptionScheme2);

                // PBES2-params
                {
                    writer.PushSequence();

                    // keyDerivationFunc
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(Oids.Pbkdf2);

                        // PBKDF2-params
                        {
                            writer.PushSequence();

                            writer.WriteOctetString(salt);
                            writer.WriteInteger(iterationCount);

                            // prf
                            if (hmacOid != Oids.HmacWithSha1)
                            {
                                writer.PushSequence();
                                writer.WriteObjectIdentifier(hmacOid);
                                writer.WriteNull();
                                writer.PopSequence();
                            }

                            writer.PopSequence();
                        }

                        writer.PopSequence();
                    }

                    // encryptionScheme
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(encryptionAlgorithmOid);
                        writer.WriteOctetString(iv);
                        writer.PopSequence();
                    }

                    writer.PopSequence();
                }
            }

            writer.PopSequence();
        }
    }

    // https://tools.ietf.org/html/rfc2898#appendix-A.3
    //
    // PBEParameter ::= SEQUENCE {
    //   salt OCTET STRING (SIZE(8)),
    //   iterationCount INTEGER }
    //
    // The version from PKCS#12 (pkcs-12PbeParams, https://tools.ietf.org/html/rfc7292#appendix-C)
    // is the same, without limiting the size of the salt value.
    [StructLayout(LayoutKind.Sequential)]
    internal struct PBEParameter
    {
        [OctetString]
        public ReadOnlyMemory<byte> Salt;

        // The spec calls out that while there's technically no limit to IterationCount,
        // that specific platforms may have their own limits.
        //
        // This defines ours to uint.MaxValue (and, conveniently, not a negative number)
        public uint IterationCount;
    }

    // https://tools.ietf.org/html/rfc2898#appendix-A.4
    //
    // PBES2-params ::= SEQUENCE {
    //   keyDerivationFunc AlgorithmIdentifier {{PBES2-KDFs}},
    //   encryptionScheme AlgorithmIdentifier {{PBES2-Encs}} }
    //
    [StructLayout(LayoutKind.Sequential)]
    internal struct PBES2Params
    {
        public AlgorithmIdentifierAsn KeyDerivationFunc;
        public AlgorithmIdentifierAsn EncryptionScheme;
    }

    // https://tools.ietf.org/html/rfc2898#appendix-A.2
    [StructLayout(LayoutKind.Sequential)]
    internal struct Pbkdf2Params
    {
        public Pbkdf2SaltChoice Salt;

        // The spec calls out that while there's technically no limit to IterationCount,
        // that specific platforms may have their own limits.
        //
        // This defines ours to uint.MaxValue (and, conveniently, not a negative number)
        public uint IterationCount;

        // The biggest value that makes sense currently is 256/8 => 32.
        [OptionalValue]
        public byte? KeyLength;

        [DefaultValue(
            0x30, 0x0C,
            0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07,
            0x05, 0x00)]
        public AlgorithmIdentifierAsn Prf;
    }

    [Choice]
    [StructLayout(LayoutKind.Sequential)]
    internal struct Pbkdf2SaltChoice
    {
        [OctetString]
        public ReadOnlyMemory<byte>? Specified;

        public AlgorithmIdentifierAsn? OtherSource;
    }

    // https://tools.ietf.org/html/rfc3370#section-5.2 (CMS Algorithms, RC2-CBC) says
    //
    //    The AlgorithmIdentifier parameters field MUST be present, and the
    //    parameters field MUST contain a RC2CBCParameter:
    //
    // RC2CBCParameter ::= SEQUENCE {
    //   rc2ParameterVersion INTEGER,
    //   iv OCTET STRING  }  -- exactly 8 octets
    //
    // It then effectively says "see RFC2268" for the version.
    //
    // https://tools.ietf.org/html/rfc2268#section-6 provides the table (EkbEncoding),
    // and provides a different structure for "RC2-CBCParameter" (with a hyphen in this name).
    //
    // The RFC3370 structure is the second CHOICE option for RC2-CBCParameter (it has no name).
    // Since 3370 says to just use that alternative there's no fallback in this code for handling
    // just an IV which means that an effective key size of 32-bits has been chosen.  Since 40-bit is the
    // smallest supported by .NET that's not really a problem.
    [StructLayout(LayoutKind.Sequential)]
    internal struct Rc2CbcParameters
    {
        private static readonly byte[] s_rc2EkbEncoding =
        {
            0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a, 0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
            0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b, 0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
            0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda, 0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
            0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8, 0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
            0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17, 0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
            0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72, 0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
            0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd, 0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
            0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b, 0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
            0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77, 0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
            0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3, 0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
            0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e, 0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
            0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d, 0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
            0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46, 0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
            0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97, 0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
            0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef, 0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
            0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf, 0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,
        };

        internal int Rc2Version;

        [OctetString]
        internal ReadOnlyMemory<byte> Iv;

        internal Rc2CbcParameters(ReadOnlyMemory<byte> iv, int keySize)
        {
            if (keySize > byte.MaxValue)
            {
                Rc2Version = keySize;
            }
            else
            {
                Rc2Version = s_rc2EkbEncoding[keySize];
            }

            Iv = iv;
        }

        internal int GetEffectiveKeyBits()
        {
            if (Rc2Version > byte.MaxValue)
            {
                return Rc2Version;
            }

            return Array.IndexOf(s_rc2EkbEncoding, (byte)Rc2Version);
        }
    }
}
