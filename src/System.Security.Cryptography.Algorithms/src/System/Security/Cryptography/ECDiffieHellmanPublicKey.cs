// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Wrapper for public key material passed between parties during Diffie-Hellman key material generation
    /// </summary>
    public abstract class ECDiffieHellmanPublicKey : IDisposable
    {
        private readonly byte[] _keyBlob;

        protected ECDiffieHellmanPublicKey(byte[] keyBlob)
        {
            if (keyBlob == null)
            {
                throw new ArgumentNullException(nameof(keyBlob));
            }

            _keyBlob = keyBlob.Clone() as byte[];
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing) { }

        public virtual byte[] ToByteArray()
        {
            return _keyBlob.Clone() as byte[];
        }

        // This method must be implemented by derived classes. In order to conform to the contract, it cannot be abstract.
        public virtual string ToXmlString()
        {
            throw new NotImplementedException(SR.NotSupported_SubclassOverride);
        }

        /// <summary>
        /// When overridden in a derived class, exports the named or explicit ECParameters for an ECCurve.
        /// If the curve has a name, the Curve property will contain named curve parameters, otherwise it
        /// will contain explicit parameters.
        /// </summary>
        /// <returns>The ECParameters representing the point on the curve for this key.</returns>
        public virtual ECParameters ExportParameters()
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }

        /// <summary>
        /// When overridden in a derived class, exports the explicit ECParameters for an ECCurve.
        /// </summary>
        /// <returns>The ECParameters representing the point on the curve for this key, using the explicit curve format.</returns>
        public virtual ECParameters ExportExplicitParameters()
        {
            throw new NotSupportedException(SR.NotSupported_SubclassOverride);
        }
    }
}
