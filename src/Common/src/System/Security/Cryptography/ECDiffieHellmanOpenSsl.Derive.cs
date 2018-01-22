// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Diagnostics;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.Contracts;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanOpenSsl : ECDiffieHellman
        {
            private static byte[] PrependAppendToSecretAgreement(byte[] secretAgreement, byte[] secretPrepend, byte[] secretAppend)
            {
                //TODO: I need to figure out if this is *actually* correct, as the docs are somewhat terse. Add some better tests or research more.
                if (secretAppend == null && secretPrepend == null)
                {
                    return secretAgreement;
                }
                
                int newLength = secretAgreement.Length + (secretPrepend == null ?  0: secretPrepend.Length) + (secretAppend == null ? 0 : secretAppend.Length);
                if (newLength != secretAgreement.Length)
                {
                    //byte[] newSecretAgreement = ArrayPool<byte>.Shared.Rent(newLength);
                    byte[] newSecretAgreement = new byte[newLength];
                    int index = 0;
                    if (secretPrepend != null)
                    {
                        Buffer.BlockCopy(secretPrepend, 0, newSecretAgreement, 0, secretPrepend.Length);
                        index += secretPrepend.Length;
                    }
                    Buffer.BlockCopy(secretAgreement, 0, newSecretAgreement, index, secretAgreement.Length);
                    index += secretAgreement.Length;
                    if (secretAppend != null)
                    {
                        Buffer.BlockCopy(secretAppend, 0, newSecretAgreement, index, secretAppend.Length);
                    }
                    return newSecretAgreement;
                }
                return secretAgreement;
            }
            
            /// <summary>
            /// Given a second party's public key, derive shared key material
            /// </summary>
            public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey) =>
                DeriveKeyFromHash(otherPartyPublicKey, HashAlgorithmName.SHA256, null, null);

            public override byte[] DeriveKeyFromHash(
                ECDiffieHellmanPublicKey otherPartyPublicKey,
                HashAlgorithmName hashAlgorithm,
                byte[] secretPrepend,
                byte[] secretAppend)
            {
                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException(nameof(otherPartyPublicKey));
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

                using (IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm))
                {
                    if (secretPrepend != null)
                    {
                        hash.AppendData(secretPrepend);
                    }

                    DeriveSecretAgreement(otherPartyPublicKey, hash);

                    if (secretAppend != null)
                    {
                        hash.AppendData(secretAppend);
                    }

                    return hash.GetHashAndReset();
                }
            }

            public override byte[] DeriveKeyFromHmac(
                ECDiffieHellmanPublicKey otherPartyPublicKey,
                HashAlgorithmName hashAlgorithm,
                byte[] hmacKey,
                byte[] secretPrepend,
                byte[] secretAppend)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException(nameof(otherPartyPublicKey));
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

                // If an hmac key is provided then calculate
                // HMAC(hmacKey, prepend || derived || append)
                //
                // Otherwise, calculate
                // HMAC(derived, prepend || derived || append)

                bool useSecretAsKey = hmacKey == null;

                if (useSecretAsKey)
                {
                    hmacKey = DeriveSecretAgreement(otherPartyPublicKey, null);
                }

                using (IncrementalHash hash = IncrementalHash.CreateHMAC(hashAlgorithm, hmacKey))
                {
                    if (secretPrepend != null)
                    {
                        hash.AppendData(secretPrepend);
                    }

                    if (useSecretAsKey)
                    {
                        hash.AppendData(hmacKey);
                        Array.Clear(hmacKey, 0, hmacKey.Length);
                    }
                    else
                    {
                        DeriveSecretAgreement(otherPartyPublicKey, hash);
                    }

                    if (secretAppend != null)
                    {
                        hash.AppendData(secretAppend);
                    }

                    return hash.GetHashAndReset();
                }
            }

            public override byte[] DeriveKeyTls(ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] prfLabel, byte[] prfSeed)
            {
                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException(nameof(otherPartyPublicKey));
                if (prfLabel == null)
                    throw new ArgumentNullException(nameof(prfLabel));
                if (prfSeed == null)
                    throw new ArgumentNullException(nameof(prfSeed));

                // TODO: do derivation
                throw new PlatformNotSupportedException("OpenSSL does not support DeriveKeyTls.");
            }

            /// <summary>
            /// Get the secret agreement generated between two parties
            /// </summary>
            private byte[] DeriveSecretAgreement(ECDiffieHellmanPublicKey otherPartyPublicKey, IncrementalHash hasher)
            {
                Debug.Assert(otherPartyPublicKey != null);

                // Ensure that this ECDH object contains a private key by attempting a parameter export
                // which will throw an OpenSslCryptoException if no private key is available
                ECParameters thisKeyExplicit = ExportExplicitParameters(true);
                bool thisIsNamed = Interop.Crypto.EcKeyHasCurveName(_key.Value);
                ECDiffieHellmanOpenSslPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanOpenSslPublicKey;
                bool disposeOtherKey = false;

                if (otherKey == null)
                {
                    disposeOtherKey = true;

                    ECParameters otherParameters =
                        thisIsNamed
                            ? otherPartyPublicKey.ExportParameters()
                            : otherPartyPublicKey.ExportExplicitParameters();

                    otherKey = new ECDiffieHellmanOpenSslPublicKey(otherParameters);
                }

                bool otherIsNamed = otherKey.HasCurveName;

                SafeEvpPKeyHandle ourKey = null;
                SafeEvpPKeyHandle theirKey = null;
                ArrayPool<byte> pool = ArrayPool<byte>.Shared;
                byte[] rented = null;
                int secretLength = 0;

                try
                {
                    if (otherKey.KeySize != KeySize)
                    {
                        throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, nameof(otherPartyPublicKey));
                    }

                    if (otherIsNamed == thisIsNamed)
                    {
                        ourKey = _key.UpRefKeyHandle();
                        theirKey = otherKey.DuplicateKeyHandle();
                    }
                    else if (otherIsNamed)
                    {
                        ourKey = _key.UpRefKeyHandle();

                        using (ECOpenSsl tmp = new ECOpenSsl(otherKey.ExportExplicitParameters()))
                        {
                            theirKey = tmp.UpRefKeyHandle();
                        }
                    }
                    else
                    {
                        using (ECOpenSsl tmp = new ECOpenSsl(thisKeyExplicit))
                        {
                            ourKey = tmp.UpRefKeyHandle();
                        }

                        theirKey = otherKey.DuplicateKeyHandle();
                    }

                    using (SafeEvpPKeyCtxHandle ctx = Interop.Crypto.EvpPKeyCtxCreate(ourKey, theirKey, out uint secretLengthU))
                    {
                        if (ctx == null || ctx.IsInvalid || secretLengthU == 0 || secretLengthU > int.MaxValue)
                        {
                            throw Interop.Crypto.CreateOpenSslCryptographicException();
                        }

                        secretLength = (int)secretLengthU;

                        // Indicate that secret can hold stackallocs from nested scopes
                        Span<byte> secret = stackalloc byte[0];

                        // Arbitrary limit. But it covers secp521r1, which is the biggest common case.
                        const int StackAllocMax = 65;

                        if (secretLength > StackAllocMax)
                        {
                            rented = pool.Rent(secretLength);
                            secret = new Span<byte>(rented, 0, secretLength);
                        }
                        else
                        {
                            secret = stackalloc byte[secretLength];
                        }

                        Interop.Crypto.EvpPKeyDeriveSecretAgreement(ctx, secret);

                        if (hasher == null)
                        {
                            return secret.ToArray();
                        }
                        else
                        {
                            hasher.AppendData(secret);
                            return null;
                        }
                    }
                }
                finally
                {
                    theirKey?.Dispose();
                    ourKey?.Dispose();

                    if (disposeOtherKey)
                    {
                        otherKey.Dispose();
                    }

                    if (rented != null)
                    {
                        Array.Clear(rented, 0, secretLength);
                        pool.Return(rented);
                    }
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
