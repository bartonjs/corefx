// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Security.Permissions;
using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
    {
        private CngAlgorithm _hashAlgorithm = CngAlgorithm.Sha256;
        private CngKey _key;

    /// <summary>
        ///     Hash algorithm used with the Hash and HMAC KDFs
        /// </summary>
        public CngAlgorithm HashAlgorithm
        {
            get
            {
                Contract.Ensures(Contract.Result<CngAlgorithm>() != null);
                return _hashAlgorithm;
            }

            set
            {
                Contract.Ensures(_hashAlgorithm != null);

                if (_hashAlgorithm == null)
                {
                    throw new ArgumentNullException("value");
                }

                _hashAlgorithm = value;
            }
        }

        /// <summary>
        ///     Full key pair being used for key generation
        /// </summary>
        public CngKey Key
        {
            get
            {
                Contract.Ensures(Contract.Result<CngKey>() != null);
                Contract.Ensures(Contract.Result<CngKey>().AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman);
                Contract.Ensures(_key != null && _key.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman);

                // If the size of the key no longer matches our stored value, then we need to replace it with
                // a new key of the correct size.
                if (_key != null && _key.KeySize != KeySize)
                {
                    _key.Dispose();
                    _key = null;
                }

                if (_key == null)
                {
                    // Map the current key size to a CNG algorithm name
                    CngAlgorithm algorithm = null;
                    switch (KeySize)
                    {
                        case 256:
                            algorithm = CngAlgorithm.ECDiffieHellmanP256;
                            break;

                        case 384:
                            algorithm = CngAlgorithm.ECDiffieHellmanP384;
                            break;

                        case 521:
                            algorithm = CngAlgorithm.ECDiffieHellmanP521;
                            break;

                        default:
                            Debug.Assert(false, "Illegal key size set");
                            break;
                    }

                    _key = CngKey.Create(algorithm);
                }

                return _key;
            }

            private set
            {
                Contract.Requires(value != null);
                Contract.Ensures(_key != null && _key.AlgorithmGroup == CngAlgorithmGroup.ECDiffieHellman);

                if (value.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
                {
                    throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey);
                }

                if (_key != null)
                {
                    _key.Dispose();
                }

                //
                // We do not duplicate the handle because the only time the user has access to the key itself
                // to dispose underneath us is when they construct via the CngKey constructor, which does a
                // duplication. Otherwise all key lifetimes are controlled directly by the ECDiffieHellmanCng
                // class.
                //

                _key = value;

                // Our LegalKeySizes value stores the values that we encoded as being the correct
                // legal key size limitations for this algorithm, as documented on MSDN.
                //
                // But on a new OS version we might not question if our limit is accurate, or MSDN
                // could have been innacurate to start with.
                //
                // Since the key is already loaded, we know that Windows thought it to be valid;
                // therefore we should set KeySizeValue directly to bypass the LegalKeySizes conformance
                // check.
                //
                // For RSA there are known cases where this change matters. RSACryptoServiceProvider can
                // create a 384-bit RSA key, which we consider too small to be legal. It can also create
                // a 1032-bit RSA key, which we consider illegal because it doesn't match our 64-bit
                // alignment requirement. (In both cases Windows loads it just fine)
                KeySizeValue = _key.KeySize;
            }
        }

        /// <summary>
        ///     Public key used to generate key material with the second party
        /// </summary>
        public override ECDiffieHellmanPublicKey PublicKey
        {
            get
            {
                Contract.Ensures(Contract.Result<ECDiffieHellmanPublicKey>() != null);
                return ECDiffieHellmanCngPublicKey.FromKey(Key);
            }
        }

        private void DisposeKey()
        {
            if (_key != null)
                _key.Dispose();
        }   

        /// <summary>
        ///     Given a second party's public key, derive shared key material
        /// </summary>
        public override byte[] DeriveKeyMaterial(ECDiffieHellmanPublicKey otherPartyPublicKey)
        {
            Contract.Ensures(Contract.Result<byte[]>() != null);
            Contract.Assert(_kdf >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                            _kdf <= ECDiffieHellmanKeyDerivationFunction.Tls);

            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }

            // We can only work with ECDiffieHellmanCngPublicKeys
            ECDiffieHellmanCngPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanCngPublicKey;
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentException(SR.Cryptography_ArgExpectedECDiffieHellmanCngPublicKey);
            }

            using (CngKey import = otherKey.Import())
            {
                return DeriveKeyMaterial(import);
            }
        }

        /// <summary>
        ///     Given a second party's public key, derive shared key material
        /// </summary>
        public byte[] DeriveKeyMaterial(CngKey otherPartyPublicKey)
        {
            Contract.Ensures(Contract.Result<byte[]>() != null);
            Contract.Assert(_kdf >= ECDiffieHellmanKeyDerivationFunction.Hash &&
                            _kdf <= ECDiffieHellmanKeyDerivationFunction.Tls);

            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }
            if (otherPartyPublicKey.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
            }
            if (otherPartyPublicKey.KeySize != KeySize)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
            }

            Interop.NCrypt.SecretAgreementFlags flags =
                UseSecretAgreementAsHmacKey ? Interop.NCrypt.SecretAgreementFlags.UseSecretAsHmacKey : Interop.NCrypt.SecretAgreementFlags.None;

            // We require access to the handles for generating key material. This is safe since we will never
            // expose these handles to user code
            //TODO probably need to do something with these.
            // new SecurityPermission(SecurityPermissionFlag.UnmanagedCode).Assert();

            // This looks horribly wrong - but accessing the handle property actually returns a duplicate handle, which
            // we need to dispose of - otherwise, we're stuck keepign the resource alive until the GC runs.  This explicitly
            // is not disposing of the handle underlying the key dispite what the syntax looks like.
            using (SafeNCryptKeyHandle localKey = Key.Handle)
            using (SafeNCryptKeyHandle otherKey = otherPartyPublicKey.Handle)
            {
                //TODO: CAS 
                //CodeAccessPermission.RevertAssert();

                //
                // Generating key material is a two phase process.
                //   1. Generate the secret agreement
                //   2. Pass the secret agreement through a KDF to get key material
                //

                using (SafeNCryptSecretHandle secretAgreement = Interop.NCrypt.DeriveSecretAgreement(localKey, otherKey))
                {
                    if (KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Hash)
                    {
                        byte[] secretAppend = SecretAppend == null ? null : SecretAppend.Clone() as byte[];
                        byte[] secretPrepend = SecretPrepend == null ? null : SecretPrepend.Clone() as byte[];

                        return Interop.NCrypt.DeriveKeyMaterialHash(secretAgreement,
                                                                    HashAlgorithm.Algorithm,
                                                                    secretPrepend,
                                                                    secretAppend,
                                                                    flags);
                    }
                    else if (KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Hmac)
                    {
                        byte[] hmacKey = HmacKey == null ? null : HmacKey.Clone() as byte[];
                        byte[] secretAppend = SecretAppend == null ? null : SecretAppend.Clone() as byte[];
                        byte[] secretPrepend = SecretPrepend == null ? null : SecretPrepend.Clone() as byte[];

                        return Interop.NCrypt.DeriveKeyMaterialHmac(secretAgreement,
                                                                    HashAlgorithm.Algorithm,
                                                                    hmacKey,
                                                                    secretPrepend,
                                                                    secretAppend,
                                                                    flags);
                    }
                    else
                    {
                        Debug.Assert(KeyDerivationFunction == ECDiffieHellmanKeyDerivationFunction.Tls, "Unknown KDF");

                        byte[] label = Label == null ? null : Label.Clone() as byte[];
                        byte[] seed = Seed == null ? null : Seed.Clone() as byte[];

                        if (label == null || seed == null)
                        {
                            throw new InvalidOperationException(SR.Cryptography_TlsRequiresLabelAndSeed);
                        }

                        return Interop.NCrypt.DeriveKeyMaterialTls(secretAgreement, label, seed, flags);
                    }
                }
            }
        }

        /// <summary>
        ///     Get a handle to the secret agreement generated between two parties
        /// </summary>
        public SafeNCryptSecretHandle DeriveSecretAgreementHandle(ECDiffieHellmanPublicKey otherPartyPublicKey)
        {
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }

            // We can only work with ECDiffieHellmanCngPublicKeys
            ECDiffieHellmanCngPublicKey otherKey = otherPartyPublicKey as ECDiffieHellmanCngPublicKey;
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentException(SR.Cryptography_ArgExpectedECDiffieHellmanCngPublicKey);
            }

            using (CngKey importedKey = otherKey.Import())
            {
                return DeriveSecretAgreementHandle(importedKey);
            }
        }

        /// <summary>
        ///     Get a handle to the secret agreement between two parties
        /// </summary>
        [SecurityPermission(SecurityAction.Demand, UnmanagedCode = true)]
        public SafeNCryptSecretHandle DeriveSecretAgreementHandle(CngKey otherPartyPublicKey)
        {
            if (otherPartyPublicKey == null)
            {
                throw new ArgumentNullException("otherPartyPublicKey");
            }
            if (otherPartyPublicKey.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, "otherPartyPublicKey");
            }
            if (otherPartyPublicKey.KeySize != KeySize)
            {
                throw new ArgumentException(SR.Cryptography_ArgECDHKeySizeMismatch, "otherPartyPublicKey");
            }

            // This looks strange, but the Handle property returns a duplicate so we need to dispose of it when we're done
            using (SafeNCryptKeyHandle localHandle = Key.Handle)
            using (SafeNCryptKeyHandle otherPartyHandle = otherPartyPublicKey.Handle)
            {
                return Interop.NCrypt.DeriveSecretAgreement(localHandle, otherPartyHandle);
            }
        }

        public override void GenerateKey(ECCurve curve)
        {
            curve.Validate();

            if (_key != null)
            {
                _key.Dispose();
                _key = null;
            }

            CngKey newKey = CngKey.Create(curve, name => CngKey.EcdhCurveNameToAlgorithm(name));
            _key = newKey;
            KeySizeValue = newKey.KeySize;
        }
    }
}
