// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics.Contracts;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Wrapper for CNG's implementation of elliptic curve Diffie-Hellman key exchange
    /// </summary>
    public sealed partial class ECDiffieHellmanCng : ECDiffieHellman
    {
        private CngAlgorithmCore _core = new CngAlgorithmCore { DefaultKeyType = CngAlgorithm.ECDiffieHellman };
        private CngAlgorithm _hashAlgorithm = CngAlgorithm.Sha256;

        public ECDiffieHellmanCng(CngKey key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.AlgorithmGroup != CngAlgorithmGroup.ECDiffieHellman)
                throw new ArgumentException(SR.Cryptography_ArgECDHRequiresECDHKey, nameof(key));

            Key = CngAlgorithmCore.Duplicate(key);
        }

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

        protected override void Dispose(bool disposing)
        {
            _core.Dispose();
        }

        private void DisposeKey()
        {
            _core.DisposeKey();
        }

        internal string GetCurveName()
        {
            return Key.GetCurveName();
        }

        private void ImportFullKeyBlob(byte[] ecfullKeyBlob, bool includePrivateParameters)
        {
            Key = ECCng.ImportFullKeyBlob(ecfullKeyBlob, includePrivateParameters);
        }

        private void ImportKeyBlob(byte[] ecfullKeyBlob, string curveName, bool includePrivateParameters)
        {
            Key = ECCng.ImportKeyBlob(ecfullKeyBlob, curveName, includePrivateParameters);
        }

        private byte[] ExportKeyBlob(bool includePrivateParameters)
        {
            return ECCng.ExportKeyBlob(Key, includePrivateParameters);
        }

        private byte[] ExportFullKeyBlob(bool includePrivateParameters)
        {
            return ECCng.ExportFullKeyBlob(Key, includePrivateParameters);
        }
    }
}
