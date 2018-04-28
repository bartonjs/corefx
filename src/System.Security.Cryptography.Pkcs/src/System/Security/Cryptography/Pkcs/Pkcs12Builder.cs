// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Cryptography.X509Certificates;

namespace System.Security.Cryptography.Pkcs
{
    public sealed partial class Pkcs12Builder
    {
        public bool IsSealed { get; }
        public SafeContentsBag AddSafeContentsEncrypted(Pkcs12SafeContents safeContents, ReadOnlySpan<char> password, Pkcs8.EncryptionAlgorithm encryptionAlgorithm, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public SafeContentsBag AddSafeContentsEnveloped(Pkcs12SafeContents safeContents, CmsRecipient recipient) => throw null;
        public SafeContentsBag AddSafeContentsUnencrypted(Pkcs12SafeContents safeContents) => throw null;
        public byte[] Encode() => throw null;
        public void SealAndMac(ReadOnlySpan<char> password, HashAlgorithmName hashAlgorithm, int iterationCount) => throw null;
        public void SealAndSign(CmsSigner signer) => throw null;
        public bool TryEncode(ReadOnlySpan<byte> destination, out int bytesWritten) => throw null;
    }
}
