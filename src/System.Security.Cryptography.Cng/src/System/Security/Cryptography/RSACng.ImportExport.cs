// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.InteropServices;
using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    public sealed partial class RSACng : RSA
    {
        // CngKeyBlob formats for RSA key blobs
        private static readonly CngKeyBlobFormat s_rsaFullPrivateBlob =
            new CngKeyBlobFormat(Interop.BCrypt.KeyBlobType.BCRYPT_RSAFULLPRIVATE_BLOB);

        private static readonly CngKeyBlobFormat s_rsaPrivateBlob =
            new CngKeyBlobFormat(Interop.BCrypt.KeyBlobType.BCRYPT_RSAPRIVATE_BLOB);

        private static readonly CngKeyBlobFormat s_rsaPublicBlob =
            new CngKeyBlobFormat(Interop.BCrypt.KeyBlobType.BCRYPT_RSAPUBLIC_KEY_BLOB);

        private static readonly CngKeyBlobFormat s_pkcs8Blob =
            new CngKeyBlobFormat(Interop.NCrypt.NCRYPT_PKCS8_PRIVATE_KEY_BLOB);

        private void ImportKeyBlob(byte[] rsaBlob, bool includePrivate)
        {
            CngKeyBlobFormat blobFormat = includePrivate ? s_rsaPrivateBlob : s_rsaPublicBlob;

            CngKey newKey = CngKey.Import(rsaBlob, blobFormat);
            newKey.ExportPolicy |= CngExportPolicies.AllowPlaintextExport;

            Key = newKey;
        }

        private void ImportPkcs8(ReadOnlyMemory<byte> pkcs8)
        {
            ImportKeyBlob(pkcs8, s_pkcs8Blob);
        }

        private void ImportPkcs8(ReadOnlyMemory<byte> pkcs8, ReadOnlySpan<char> password)
        {
            ImportKeyBlob(
                pkcs8,
                s_pkcs8Blob,
                true,
                password);
        }

        private void ImportKeyBlob(
            ReadOnlyMemory<byte> rsaBlob,
            CngKeyBlobFormat blobFormat,
            bool encrypted=false,
            ReadOnlySpan<char> password=default)
        {
            CngKey newKey;

            if (encrypted)
            {
                Debug.Assert(blobFormat.Format == Interop.NCrypt.NCRYPT_PKCS8_PRIVATE_KEY_BLOB);
                newKey = CngKey.ImportEncryptedPkcs8(rsaBlob, password);
            }
            else
            {
                newKey = CngKey.Import(rsaBlob, blobFormat);
            }

            newKey.ExportPolicy |= CngExportPolicies.AllowPlaintextExport;

            Key = newKey;
        }

        private byte[] ExportKeyBlob(bool includePrivateParameters)
        {
            return Key.Export(includePrivateParameters ? s_rsaFullPrivateBlob : s_rsaPublicBlob);
        }

        public override bool TryExportPkcs8PrivateKey(Span<byte> destination, out int bytesWritten)
        {
            return Key.TryExportKeyBlob(
                Interop.NCrypt.NCRYPT_PKCS8_PRIVATE_KEY_BLOB,
                destination,
                out bytesWritten);
        }

        private byte[] ExportEncryptedPkcs8(ReadOnlySpan<char> pkcs8Password, int kdfCount)
        {
            return Key.ExportPkcs8KeyBlob(pkcs8Password, kdfCount);
        }

        private bool TryExportEncryptedPkcs8(
            ReadOnlySpan<char> pkcs8Password,
            int kdfCount,
            Span<byte> destination,
            out int bytesWritten)
        {
            return Key.TryExportPkcs8KeyBlob(
                pkcs8Password,
                kdfCount,
                destination,
                out bytesWritten);
        }
    }
}
