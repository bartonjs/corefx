// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    internal static partial class ECDiffieHellmanImplementation
    {
#endif
        public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
        {
            public override byte[] DeriveKeyFromHash(
                ECDiffieHellmanPublicKey otherPartyPublicKey,
                HashAlgorithmName hashAlgorithm,
                byte[] secretPrepend,
                byte[] secretAppend)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException(nameof(otherPartyPublicKey));
                if (string.IsNullOrEmpty(hashAlgorithm.Name))
                    throw new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, nameof(hashAlgorithm));

                using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
                {
                    return Interop.NCrypt.DeriveKeyMaterialHash(
                        secretAgreement,
                        hashAlgorithm.Name,
                        secretPrepend,
                        secretAppend,
                        Interop.NCrypt.SecretAgreementFlags.None);
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

                using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
                {
                    Interop.NCrypt.SecretAgreementFlags flags = hmacKey == null ?
                        Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey :
                        Interop.NCrypt.SecretAgreementFlags.None;

                    return Interop.NCrypt.DeriveKeyMaterialHmac(
                        secretAgreement,
                        hashAlgorithm.Name,
                        hmacKey,
                        secretPrepend,
                        secretAppend,
                        flags);
                }
            }

            public override byte[] DeriveKeyTls(ECDiffieHellmanPublicKey otherPartyPublicKey, byte[] prfLabel, byte[] prfSeed)
            {
                Contract.Ensures(Contract.Result<byte[]>() != null);

                if (otherPartyPublicKey == null)
                    throw new ArgumentNullException(nameof(otherPartyPublicKey));
                if (prfLabel == null)
                    throw new ArgumentNullException(nameof(prfLabel));
                if (prfSeed == null)
                    throw new ArgumentNullException(nameof(prfSeed));

                using (SafeNCryptSecretHandle secretAgreement = DeriveSecretAgreementHandle(otherPartyPublicKey))
                {
                    return Interop.NCrypt.DeriveKeyMaterialTls(
                        secretAgreement,
                        prfLabel,
                        prfSeed,
                        Interop.NCrypt.SecretAgreementFlags.None);
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
