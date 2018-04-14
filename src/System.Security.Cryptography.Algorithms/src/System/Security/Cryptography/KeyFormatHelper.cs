// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography
{
    internal static class KeyFormatHelper
    {
        internal delegate void KeyReader<TRet, TParsed>(in TParsed key, in AlgorithmIdentifierAsn algId, out TRet ret);

        internal static void ReadPkcs8<TRet, TParsed>(
            string algorithmOid,
            ReadOnlySpan<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            byte[] buf = ArrayPool<byte>.Shared.Rent(source.Length);
            source.CopyTo(buf);
            Memory<byte> tmp = buf.AsMemory(0, source.Length);

            try
            {
                ReadPkcs8(algorithmOid, tmp, keyReader, out bytesRead, out ret);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(tmp.Span);
                ArrayPool<byte>.Shared.Return(buf);
            }
        }

        internal static void ReadPkcs8<TRet, TParsed>(
            string algorithmOid,
            ReadOnlyMemory<byte> source,
            KeyReader<TRet, TParsed> keyReader,
            out int bytesRead,
            out TRet ret)
        {
            PrivateKeyInfo privateKeyInfo =
                AsnSerializer.Deserialize<PrivateKeyInfo>(source, AsnEncodingRules.BER, out int read);

            if (privateKeyInfo.PrivateKeyAlgorithm.Algorithm != algorithmOid)
            {
                // TODO: Better message?
                throw new CryptographicException(SR.Cryptography_NotValidPublicOrPrivateKey);
            }

            // Fails if there are unconsumed bytes.
            TParsed parsed = AsnSerializer.Deserialize<TParsed>(
                privateKeyInfo.PrivateKey,
                AsnEncodingRules.BER);

            keyReader(parsed, privateKeyInfo.PrivateKeyAlgorithm, out ret);
            bytesRead = read;
        }
    }
}
