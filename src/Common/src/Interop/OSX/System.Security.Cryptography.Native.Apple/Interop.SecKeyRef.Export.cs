// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Buffers;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using Microsoft.Win32.SafeHandles;

internal static partial class Interop
{
    internal static partial class AppleCrypto
    {
        private const string OidPbes2 = "1.2.840.113549.1.5.13";
        private const string OidPbkdf2 = "1.2.840.113549.1.5.12";
        private const string OidSha1 = "1.3.14.3.2.26";
        private const string OidTripleDesCbc = "1.2.840.113549.3.7";

        private static readonly SafeCreateHandle s_nullExportString = new SafeCreateHandle();

        private static readonly SafeCreateHandle s_emptyExportString =
            CoreFoundation.CFStringCreateWithCString("");

        [DllImport(Libraries.AppleCryptoNative)]
        private static extern int AppleCryptoNative_SecKeyExport(
            SafeSecKeyRefHandle key,
            int exportPrivate,
            SafeCreateHandle cfExportPassphrase,
            out SafeCFDataHandle cfDataOut,
            out int pOSStatus);

        internal static DerSequenceReader SecKeyExport(
            SafeSecKeyRefHandle key,
            bool exportPrivate)
        {
            // Apple requires all private keys to be exported encrypted, but since we're trying to export
            // as parsed structures we will need to decrypt it for the user.
            const string ExportPassword = "DotnetExportPassphrase";

            SafeCreateHandle exportPassword = exportPrivate
                ? CoreFoundation.CFStringCreateWithCString(ExportPassword)
                : s_nullExportString;

            int ret;
            SafeCFDataHandle cfData;
            int osStatus;

            try
            {
                ret = AppleCryptoNative_SecKeyExport(
                    key,
                    exportPrivate ? 1 : 0,
                    exportPassword,
                    out cfData,
                    out osStatus);
            }
            finally
            {
                if (exportPassword != s_nullExportString)
                {
                    exportPassword.Dispose();
                }
            }

            byte[] exportedData;

            using (cfData)
            {
                if (ret == 0)
                {
                    throw CreateExceptionForOSStatus(osStatus);
                }

                if (ret != 1)
                {
                    Debug.Fail($"AppleCryptoNative_SecKeyExport returned {ret}");
                    throw new CryptographicException();
                }

                exportedData = CoreFoundation.CFGetData(cfData);
            }

            DerSequenceReader reader = new DerSequenceReader(exportedData);

            if (!exportPrivate)
            {
                return reader;
            }

            byte tag = reader.PeekTag();

            // PKCS#8 defines two structures, PrivateKeyInfo, which starts with an integer,
            // and EncryptedPrivateKey, which starts with an encryption algorithm (DER sequence).
            if (tag == (byte)DerSequenceReader.DerTag.Integer)
            {
                return reader;
            }

            const byte ConstructedSequence =
                DerSequenceReader.ConstructedFlag | (byte)DerSequenceReader.DerTag.Sequence;

            if (tag == ConstructedSequence)
            {
                ArraySegment<byte> decrypted = KeyFormatHelper.DecryptPkcs8(
                    ExportPassword,
                    exportedData,
                    out int bytesRead);

                Debug.Assert(bytesRead == exportedData.Length);

                try
                {
                    byte[] copy = decrypted.ToArray();
                    return new DerSequenceReader(copy);
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(decrypted);
                    ArrayPool<byte>.Shared.Return(decrypted.Array);
                }
            }

            Debug.Fail($"Data was neither PrivateKey or EncryptedPrivateKey: {tag:X2}");
            throw new CryptographicException();
        }
    }
}
