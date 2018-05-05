// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Internal.Cryptography;
using Microsoft.Win32.SafeHandles;

using ErrorCode = Interop.NCrypt.ErrorCode;

namespace System.Security.Cryptography
{
    /// <summary>
    ///     Managed representation of an NCrypt key
    /// </summary>
    public sealed partial class CngKey : IDisposable
    {
        /// <summary>
        ///     Export the key out of the KSP
        /// </summary>
        public byte[] Export(CngKeyBlobFormat format)
        {
            if (format == null)
                throw new ArgumentNullException(nameof(format));

            int numBytesNeeded;
            ErrorCode errorCode = Interop.NCrypt.NCryptExportKey(_keyHandle, IntPtr.Zero, format.Format, IntPtr.Zero, null, 0, out numBytesNeeded, 0);
            if (errorCode != ErrorCode.ERROR_SUCCESS)
                throw errorCode.ToCryptographicException();

            byte[] buffer = new byte[numBytesNeeded];
            errorCode = Interop.NCrypt.NCryptExportKey(_keyHandle, IntPtr.Zero, format.Format, IntPtr.Zero, buffer, buffer.Length, out numBytesNeeded, 0);
            if (errorCode != ErrorCode.ERROR_SUCCESS)
                throw errorCode.ToCryptographicException();

            Array.Resize(ref buffer, numBytesNeeded);
            return buffer;
        }

        private static readonly byte[] s_oidBytes =
            System.Text.Encoding.ASCII.GetBytes("1.2.840.113549.1.12.1.3\0");

        internal unsafe byte[] ExportPkcs8(string password)
        {
            const string BlobType = "PKCS8_PRIVATEKEY";
            int numBytesNeeded;

            using (SafeUnicodeStringHandle stringHandle = new SafeUnicodeStringHandle(password))
            fixed (byte* oidPtr = s_oidBytes)
            {
                Interop.NCrypt.NCryptBuffer* buffers = stackalloc Interop.NCrypt.NCryptBuffer[3];

                Interop.NCrypt.PBE_PARAMS pbeParams = new Interop.NCrypt.PBE_PARAMS();
                Span<byte> salt = new Span<byte>(pbeParams.rgbSalt, Interop.NCrypt.PBE_PARAMS.RgbSaltSize);
                RandomNumberGenerator.Fill(salt);
                pbeParams.Params.cbSalt = salt.Length;
                pbeParams.Params.iIterations = 2048;

                buffers[0] = new Interop.NCrypt.NCryptBuffer
                {
                    BufferType = Interop.NCrypt.BufferType.PkcsSecret,
                    cbBuffer = checked(2 * (password.Length + 1)),
                    pvBuffer = stringHandle.DangerousGetHandle(),
                };

                buffers[1] = new Interop.NCrypt.NCryptBuffer
                {
                    BufferType = Interop.NCrypt.BufferType.PkcsAlgOid,
                    cbBuffer = s_oidBytes.Length,
                    pvBuffer = (IntPtr)oidPtr,
                };

                buffers[2] = new Interop.NCrypt.NCryptBuffer
                {
                    BufferType = Interop.NCrypt.BufferType.PkcsAlgParam,
                    cbBuffer = sizeof(Interop.NCrypt.PBE_PARAMS),
                    pvBuffer = (IntPtr)(&pbeParams),
                };

                Interop.NCrypt.NCryptBufferDesc desc = new Interop.NCrypt.NCryptBufferDesc
                {
                    cBuffers = 3,
                    pBuffers = (IntPtr)buffers,
                    ulVersion = 0,
                };

                ErrorCode errorCode = Interop.NCrypt.NCryptExportKey(
                    _keyHandle,
                    IntPtr.Zero,
                    BlobType,
                    ref desc,
                    null,
                    0,
                    out numBytesNeeded,
                    0);

                if (errorCode != ErrorCode.ERROR_SUCCESS)
                {
                    throw errorCode.ToCryptographicException();
                }

                byte[] dest = new byte[numBytesNeeded];

                errorCode = Interop.NCrypt.NCryptExportKey(
                    _keyHandle,
                    IntPtr.Zero,
                    BlobType,
                    ref desc,
                    dest,
                    dest.Length,
                    out numBytesNeeded,
                    0);

                if (errorCode != ErrorCode.ERROR_SUCCESS)
                {
                    throw errorCode.ToCryptographicException();
                }

                Array.Resize(ref dest, numBytesNeeded);
                return dest;
            }
        }
    }
}

