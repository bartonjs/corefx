// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal static class ECDiffieHellmanDerivation
    {
        /// <summary>
        /// Derive the raw ECDH value into <paramref name="hasher"/>, if present, otherwise returning the value.
        /// </summary>
        internal delegate byte[] DeriveSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey, IncrementalHash hasher);

        internal static byte[] DeriveKeyFromHash(
            ECDiffieHellmanPublicKey otherPartyPublicKey,
            HashAlgorithmName hashAlgorithm,
            ReadOnlySpan<byte> secretPrepend,
            ReadOnlySpan<byte> secretAppend,
            DeriveSecretAgreement deriveSecretAgreement)
        {
            Debug.Assert(otherPartyPublicKey != null);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            using (IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm))
            {
                hash.AppendData(secretPrepend);

                byte[] secretAgreement = deriveSecretAgreement(otherPartyPublicKey, hash);
                // We want the side effect, and it should not have returned the answer.
                Debug.Assert(secretAgreement == null);

                hash.AppendData(secretAppend);

                return hash.GetHashAndReset();
            }
        }

        internal static byte[] DeriveKeyFromHmac(
            ECDiffieHellmanPublicKey otherPartyPublicKey,
            HashAlgorithmName hashAlgorithm,
            byte[] hmacKey,
            ReadOnlySpan<byte> secretPrepend,
            ReadOnlySpan<byte> secretAppend,
            DeriveSecretAgreement deriveSecretAgreement)
        {
            Debug.Assert(otherPartyPublicKey != null);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            // If an hmac key is provided then calculate
            // HMAC(hmacKey, prepend || derived || append)
            //
            // Otherwise, calculate
            // HMAC(derived, prepend || derived || append)

            bool useSecretAsKey = hmacKey == null;
            GCHandle pinHandle = default;

            if (useSecretAsKey)
            {
                hmacKey = deriveSecretAgreement(otherPartyPublicKey, null);
                Debug.Assert(hmacKey != null);
                pinHandle = GCHandle.Alloc(hmacKey, GCHandleType.Pinned);
            }

            using (IncrementalHash hash = IncrementalHash.CreateHMAC(hashAlgorithm, hmacKey))
            {
                hash.AppendData(secretPrepend);

                if (useSecretAsKey)
                {
                    hash.AppendData(hmacKey);
                    Array.Clear(hmacKey, 0, hmacKey.Length);
                    Debug.Assert(pinHandle.IsAllocated);
                    pinHandle.Free();
                }
                else
                {
                    byte[] secretAgreement = deriveSecretAgreement(otherPartyPublicKey, hash);
                    // We want the side effect, and it should not have returned the answer.
                    Debug.Assert(secretAgreement == null);
                }

                hash.AppendData(secretAppend);
                return hash.GetHashAndReset();
            }
        }

        internal static byte[] DeriveKeyTls(
            ECDiffieHellmanPublicKey otherPartyPublicKey,
            ReadOnlySpan<byte> prfLabel,
            ReadOnlySpan<byte> prfSeed,
            DeriveSecretAgreement deriveSecretAgreement)
        {
            Debug.Assert(otherPartyPublicKey != null);

            if (prfSeed.Length != 64)
            {
                throw new CryptographicException($"{nameof(prfSeed)} must be exactly 64 bytes");
            }

            byte[] ret = new byte[48];

            const int Sha1Size = 20;
            const int Md5Size = 16;

            byte[] secretAgreement = deriveSecretAgreement(otherPartyPublicKey, null);
            GCHandle handle = GCHandle.Alloc(secretAgreement, GCHandleType.Pinned);

            try
            {
                int half = secretAgreement.Length / 2;
                int odd = secretAgreement.Length & 1;

                PHash(
                    HashAlgorithmName.MD5,
                    new ReadOnlySpan<byte>(secretAgreement, 0, half + odd),
                    prfLabel,
                    prfSeed,
                    Md5Size,
                    ret);

                Span<byte> part2 = stackalloc byte[ret.Length];

                PHash(
                    HashAlgorithmName.SHA1,
                    new ReadOnlySpan<byte>(secretAgreement, half, half + odd),
                    prfLabel,
                    prfSeed,
                    Sha1Size,
                    part2);

                for (int i = 0; i < ret.Length; i++)
                {
                    ret[i] ^= part2[i];
                }

                return ret;
            }
            finally
            {
                Array.Clear(secretAgreement, 0, secretAgreement.Length);
                handle.Free();
            }
        }

        private static void PHash(
            HashAlgorithmName algorithmName,
            ReadOnlySpan<byte> secret,
            ReadOnlySpan<byte> prfLabel,
            ReadOnlySpan<byte> prfSeed,
            int hashOutputSize,
            Span<byte> ret)
        {
            byte[] secretTmp = new byte[secret.Length];
            GCHandle pinHandle = GCHandle.Alloc(secretTmp, GCHandleType.Pinned);
            secret.Slice(0, secretTmp.Length).CopyTo(secretTmp);

            try
            {
                Span<byte> retSpan = ret;

                using (IncrementalHash hasher = IncrementalHash.CreateHMAC(algorithmName, secretTmp))
                {
                    Span<byte> a = stackalloc byte[hashOutputSize];
                    Span<byte> p = stackalloc byte[hashOutputSize];

                    // A(1)
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);
                    int ai = 0;

                    if (!hasher.TryGetHashAndReset(a, out int bytesWritten) || bytesWritten != hashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    while (true)
                    {
                        // HMAC_hash(secret, A(i) || seed) => p
                        hasher.AppendData(a);
                        hasher.AppendData(prfLabel);
                        hasher.AppendData(prfSeed);

                        if (!hasher.TryGetHashAndReset(p, out bytesWritten) || bytesWritten != hashOutputSize)
                        {
                            throw new CryptographicException();
                        }

                        int len = Math.Min(p.Length, retSpan.Length);

                        p.Slice(0, len).CopyTo(retSpan);
                        retSpan = retSpan.Slice(len);

                        if (retSpan.Length == 0)
                        {
                            return;
                        }

                        // Build the next A(i)
                        hasher.AppendData(a);

                        if (!hasher.TryGetHashAndReset(a, out bytesWritten) || bytesWritten != hashOutputSize)
                        {
                            throw new CryptographicException();
                        }

                        ai++;
                    }
                }
            }
            finally
            {
                Array.Clear(secretTmp, 0, secretTmp.Length);
                pinHandle.Free();
            }
        }

        internal static byte[] DeriveKeyTls12(
            ECDiffieHellmanPublicKey otherPartyPublicKey,
            ReadOnlySpan<byte> prfLabel,
            ReadOnlySpan<byte> prfSeed,
            DeriveSecretAgreement deriveSecretAgreement)
        {
            Debug.Assert(otherPartyPublicKey != null);

            if (prfSeed.Length != 64)
            {
                throw new CryptographicException($"{nameof(prfSeed)} must be exactly 64 bytes");
            }

            byte[] secretAgreement = deriveSecretAgreement(otherPartyPublicKey, null);
            GCHandle handle = GCHandle.Alloc(secretAgreement, GCHandleType.Pinned);
            const int HashOutputSize = 256 / 8;

            try
            {
                // Windows always outputs 384 bits / 48 bytes of data.
                // Since ECDHCng didn't specify a hash algorithm in net35 it uses the
                // Windows default of (HMAC)SHA-2-256.
                //
                // Defaults can be found at
                // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375393(v=vs.85).aspx
                // in the section on BCRYPT_KDF_TLS_PRF

                // The algorithm is described at https://tools.ietf.org/html/rfc5246#section-5
                //
                // PRF(secret, label, seed) = P_<hash>(secret, label + seed)
                //
                // P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                //                        HMAC_hash(secret, A(2) + seed) + ...
                //
                // A(0) = seed
                // A(i) = HMAC_hash(secret, A(i-1))
                using (IncrementalHash hasher = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, secretAgreement))
                {
                    Span<byte> a = stackalloc byte[HashOutputSize];
                    Span<byte> p = stackalloc byte[HashOutputSize];
                    byte[] ret = new byte[100];
                    Span<byte> retSpan = ret;

                    // A(1)
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(a, out int bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    while (true)
                    {
                        // HMAC_hash(secret, A(i) || seed) => p
                        hasher.AppendData(a);
                        hasher.AppendData(prfLabel);
                        hasher.AppendData(prfSeed);

                        if (!hasher.TryGetHashAndReset(p, out bytesWritten) || bytesWritten != HashOutputSize)
                        {
                            throw new CryptographicException();
                        }

                        if (p.Length > retSpan.Length)
                        {
                            p.Slice(0, retSpan.Length).CopyTo(retSpan);
                            return ret;
                        }

                        p.CopyTo(retSpan);
                        retSpan = retSpan.Slice(p.Length);

                        // Build the next A(i)
                        hasher.AppendData(a);

                        if (!hasher.TryGetHashAndReset(a, out bytesWritten) || bytesWritten != HashOutputSize)
                        {
                            throw new CryptographicException();
                        }
                    }
                }
            }
            finally
            {
                Array.Clear(secretAgreement, 0, secretAgreement.Length);
                handle.Free();
            }
        }
    }
}
