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

            byte[] secretAgreement = deriveSecretAgreement(otherPartyPublicKey, null);
            GCHandle handle = GCHandle.Alloc(secretAgreement, GCHandleType.Pinned);
            ArrayPool<byte> pool = ArrayPool<byte>.Shared;
            const int HashOutputSize = 256 / 8;
            byte[] a0toA2 = pool.Rent(3 * HashOutputSize);
            byte[] pHash = pool.Rent(2 * HashOutputSize);

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

                // Since we're outputting 48 bytes and HMACSHA256 outputs 32 bytes, we need two runs.
                // So we need A0, A1, and A2.

                using (IncrementalHash hasher = IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, secretAgreement))
                {
                    Span<byte> a0 = new Span<byte>(a0toA2, 0, HashOutputSize);
                    Span<byte> a1 = new Span<byte>(a0toA2, HashOutputSize, HashOutputSize);
                    Span<byte> a2 = new Span<byte>(a0toA2, 2 * HashOutputSize, HashOutputSize);

                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(a0, out int bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    // Should this really have the label and seed?
                    hasher.AppendData(a0);
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(a1, out bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    hasher.AppendData(a1);
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(a2, out bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    Span<byte> pHash0 = new Span<byte>(pHash, 0, HashOutputSize);
                    Span<byte> pHash1 = new Span<byte>(pHash, HashOutputSize, HashOutputSize);

                    hasher.AppendData(a1);
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(pHash0, out bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    hasher.AppendData(a2);
                    hasher.AppendData(prfLabel);
                    hasher.AppendData(prfSeed);

                    if (!hasher.TryGetHashAndReset(pHash1, out bytesWritten) || bytesWritten != HashOutputSize)
                    {
                        throw new CryptographicException();
                    }

                    byte[] ret = new byte[48];
                    Buffer.BlockCopy(pHash, 0, ret, 0, ret.Length);
                    return ret;
                }
            }
            finally
            {
                Array.Clear(secretAgreement, 0, secretAgreement.Length);
                handle.Free();

                Array.Clear(a0toA2, 0, 3 * HashOutputSize);
                Array.Clear(pHash, 0, 2 * HashOutputSize);
                pool.Return(a0toA2);
                pool.Return(pHash);
            }
        }
    }
}
