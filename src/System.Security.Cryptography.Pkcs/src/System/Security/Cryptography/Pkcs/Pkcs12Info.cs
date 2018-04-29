// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    public sealed class Pkcs12Info
    {
        private Pfx _decoded;
        private ReadOnlyMemory<byte> _authSafeContents;

        public ReadOnlyCollection<Pkcs12SafeContents> AuthenticatedSafe { get; private set; }
        public IntegrityMode DataIntegrityMode { get; private set; }

        private Pkcs12Info()
        {
        }

        public bool VerifyMac(ReadOnlySpan<char> password)
        {
            if (DataIntegrityMode != IntegrityMode.Password)
            {
                return false;
            }

            Debug.Assert(_decoded.MacData.HasValue);

            HashAlgorithmName hashAlgorithm;
            int expectedOutputSize;

            string algorithmValue = _decoded.MacData.Value.Mac.DigestAlgorithm.Algorithm.Value;

            switch (algorithmValue)
            {
                case Oids.Md5:
                    expectedOutputSize = 128 >> 3;
                    hashAlgorithm = HashAlgorithmName.MD5;
                    break;
                case Oids.Sha1:
                    expectedOutputSize = 160 >> 3;
                    hashAlgorithm = HashAlgorithmName.SHA1;
                    break;
                case Oids.Sha256:
                    expectedOutputSize = 256 >> 3;
                    hashAlgorithm = HashAlgorithmName.SHA256;
                    break;
                case Oids.Sha384:
                    expectedOutputSize = 384 >> 3;
                    hashAlgorithm = HashAlgorithmName.SHA384;
                    break;
                case Oids.Sha512:
                    expectedOutputSize = 512 >> 3;
                    hashAlgorithm = HashAlgorithmName.SHA512;
                    break;
                default:
                    throw new CryptographicException(
                        SR.Format(SR.Cryptography_UnknownHashAlgorithm, algorithmValue));
            }

            if (_decoded.MacData.Value.Mac.Digest.Length != expectedOutputSize)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            //Span<byte> derived = stackalloc byte[expectedOutputSize];
            byte[] derived = new byte[expectedOutputSize];

            Pkcs12Kdf.DeriveMacKey(
                password,
                hashAlgorithm,
                _decoded.MacData.Value.IterationCount,
                _decoded.MacData.Value.MacSalt.Span,
                derived);

            using (IncrementalHash hmac = IncrementalHash.CreateHMAC(hashAlgorithm, derived))
            {
                hmac.AppendData(_authSafeContents.Span);

                if (!hmac.TryGetHashAndReset(derived, out int bytesWritten) || bytesWritten != expectedOutputSize)
                {
                    Debug.Fail($"TryGetHashAndReset wrote {bytesWritten} bytes when {expectedOutputSize} was expected");
                    throw new CryptographicException();
                }

                return CryptographicOperations.FixedTimeEquals(
                    derived,
                    _decoded.MacData.Value.Mac.Digest.Span);
            }
        }

        public bool VerifySignature(X509Certificate2 signerCertificate) => throw null;

        public static Pkcs12Info Decode(
            ReadOnlyMemory<byte> encodedBytes,
            out int bytesConsumed)
        {
            AsnReader reader = new AsnReader(encodedBytes, AsnEncodingRules.BER);
            // Trim it to the first value
            encodedBytes = reader.PeekEncodedValue();

            // Copy the data
            byte[] copy = encodedBytes.ToArray();

            Pfx pfx = AsnSerializer.Deserialize<Pfx>(copy, AsnEncodingRules.BER);

            // https://tools.ietf.org/html/rfc7292#section-4 only defines version 3.
            if (pfx.Version != 3)
            {
                throw new CryptographicException("Only version 3 PFX data is supported");
            }

            ReadOnlyMemory<byte> authSafeBytes = ReadOnlyMemory<byte>.Empty;
            IntegrityMode mode = IntegrityMode.Unknown;

            if (pfx.AuthSafe.ContentType == Oids.Pkcs7Data)
            {
                authSafeBytes = Helpers.DecodeOctetString(pfx.AuthSafe.Content);
                
                if (pfx.MacData.HasValue)
                {
                    mode = IntegrityMode.Password;
                }
            }
            else if (pfx.AuthSafe.ContentType == Oids.Pkcs7Signed)
            {
                SignedDataAsn signedData =
                    AsnSerializer.Deserialize<SignedDataAsn>(pfx.AuthSafe.Content, AsnEncodingRules.BER);

                mode = IntegrityMode.PublicKey;

                if (signedData.EncapContentInfo.ContentType == Oids.Pkcs7Data)
                {
                    authSafeBytes = signedData.EncapContentInfo.Content.GetValueOrDefault();
                }

                if (pfx.MacData.HasValue)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            if (mode == IntegrityMode.Unknown)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ContentInfoAsn[] authSafeData =
                AsnSerializer.Deserialize<ContentInfoAsn[]>(authSafeBytes, AsnEncodingRules.BER);

            ReadOnlyCollection<Pkcs12SafeContents> authSafe;

            if (authSafeData.Length == 0)
            {
                authSafe = new ReadOnlyCollection<Pkcs12SafeContents>(Array.Empty<Pkcs12SafeContents>());
            }
            else
            {
                Pkcs12SafeContents[] contentsArray = new Pkcs12SafeContents[authSafeData.Length];

                for (int i = 0; i < contentsArray.Length; i++)
                {
                    contentsArray[i] = new Pkcs12SafeContents(authSafeData[i]);
                }

                authSafe = new ReadOnlyCollection<Pkcs12SafeContents>(contentsArray);
            }

            bytesConsumed = encodedBytes.Length;

            return new Pkcs12Info
            {
                AuthenticatedSafe = authSafe,
                DataIntegrityMode = mode,
                _decoded = pfx,
                _authSafeContents = authSafeBytes,
            };
        }

        public enum IntegrityMode
        {
            Unknown,
            Password,
            PublicKey,
        }
    }

    internal static class Pkcs12Kdf
    {
        private static readonly Dictionary<HashAlgorithmName, Tuple<int, int>> s_uvLookup =
            new Dictionary<HashAlgorithmName, Tuple<int, int>>
            {
                { HashAlgorithmName.MD5, Tuple.Create(128, 512) },
                { HashAlgorithmName.SHA1, Tuple.Create(160, 512) },
                { HashAlgorithmName.SHA256, Tuple.Create(256, 512) },
                { HashAlgorithmName.SHA384, Tuple.Create(384, 1024) },
                { HashAlgorithmName.SHA512, Tuple.Create(512, 1024) },
            };

        internal static void DeriveMacKey(
            ReadOnlySpan<char> password,
            HashAlgorithmName hashAlgorithm,
            uint iterationCount,
            ReadOnlySpan<byte> salt,
            Span<byte> destination)
        {
            Derive(
                password,
                hashAlgorithm,
                iterationCount,
                3,
                salt,
                destination);
        }

        private static void Derive(
            ReadOnlySpan<char> password,
            HashAlgorithmName hashAlgorithm,
            uint iterationCount,
            byte id,
            ReadOnlySpan<byte> salt,
            Span<byte> destination)
        {
            // https://tools.ietf.org/html/rfc7292#appendix-B.2

            if (!s_uvLookup.TryGetValue(hashAlgorithm, out Tuple<int, int> uv))
            {
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name);
            }

            (int u, int v) = uv;

            //  1. Construct a string, D (the "diversifier"), by concatenating v/8 copies of ID.
            int vBytes = v >> 3;
            Span<byte> D = stackalloc byte[vBytes];
            D.Fill(id);

            // 2.  Concatenate copies of the salt together to create a string S of
            // length v(ceiling(s/ v)) bits(the final copy of the salt may be
            // truncated to create S). Note that if the salt is the empty
            // string, then so is S.
            int SLen = ((salt.Length - 1 + vBytes) / vBytes) * vBytes;

            // The password is a null-terminated UTF-16BE version of the input.
            int passLen = (password.Length + 1) * 2;

            // 3.  Concatenate copies of the password together to create a string P
            // of length v(ceiling(p/v)) bits (the final copy of the password
            // may be truncated to create P).  Note that if the password is the
            // empty string, then so is P.
            int PLen = ((passLen - 1 + vBytes) / vBytes) * vBytes;

            // 4.  Set I=S||P to be the concatenation of S and P.
            int ILen = SLen + PLen;
            Span<byte> I = stackalloc byte[0];
            byte[] IRented = null;

            if (ILen <= 1024)
            {
                I = stackalloc byte[ILen];
            }
            else
            {
                IRented = ArrayPool<byte>.Shared.Rent(ILen);
                I = IRented.AsSpan(0, ILen);
            }

            IncrementalHash hash = IncrementalHash.CreateHash(hashAlgorithm);

            try
            {
                CircularCopy(salt, I.Slice(0, SLen));
                CircularCopyUtf16BE(password, I.Slice(SLen));

                // 5.  Set c=ceiling(n/u).
                int uBytes = u >> 3;
                int c = (destination.Length - 1 + uBytes) / uBytes;

                Span<byte> hashBuf = stackalloc byte[uBytes];
                Span<byte> bBuf = stackalloc byte[vBytes];

                // 6.  For i=1, 2, ..., c, do the following:
                while (true)
                {
                    // A.  Set A_i=H^r(D||I). (i.e., the r-th hash of D||I,
                    // H(H(H(... H(D || I))))
                    hash.AppendData(D);
                    hash.AppendData(I);

                    for (uint j = iterationCount; j > 0; j--)
                    {
                        if (!hash.TryGetHashAndReset(hashBuf, out int bytesWritten) || bytesWritten != hashBuf.Length)
                        {
                            Debug.Fail($"Hash output wrote {bytesWritten} bytes when {hashBuf.Length} was expected");
                            throw new CryptographicException();
                        }

                        if (j != 1)
                        {
                            hash.AppendData(hashBuf);
                        }
                    }

                    // 7.  Concatenate A_1, A_2, ..., A_c together to form a pseudorandom
                    // bit string, A.
                    //
                    // 8.  Use the first n bits of A as the output of this entire process.

                    if (hashBuf.Length >= destination.Length)
                    {
                        hashBuf.Slice(0, destination.Length).CopyTo(destination);
                        return;
                    }

                    hashBuf.CopyTo(destination);
                    destination = destination.Slice(hashBuf.Length);

                    // B.  Concatenate copies of A_i to create a string B of length v
                    // bits(the final copy of Ai may be truncated to create B).
                    CircularCopy(hashBuf, bBuf);

                    // C.  Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit
                    // blocks, where k = ceiling(s / v) + ceiling(p / v), modify I by
                    // setting I_j = (I_j + B + 1) mod 2 ^ v for each j.
                    for (int j = (I.Length / vBytes) - 1; j >= 0; j--)
                    {
                        Span<byte> I_j = I.Slice(j * vBytes, vBytes);
                        AddPlusOne(I_j, bBuf);
                    }
                }
            }
            finally
            {
                CryptographicOperations.ZeroMemory(I);

                if (IRented != null)
                {
                    ArrayPool<byte>.Shared.Return(IRented);
                }

                hash.Dispose();
            }
        }

        private static void AddPlusOne(Span<byte> into, Span<byte> addend)
        {
            Debug.Assert(into.Length == addend.Length);

            int carry = 1;

            for (int i = into.Length - 1; i >= 0; i--)
            {
                int tmp = carry + into[i] + addend[i];
                into[i] = (byte)tmp;
                carry = tmp >> 8;
            }
        }

        private static void CircularCopy(ReadOnlySpan<byte> bytes, Span<byte> destination)
        {
            while (destination.Length > 0)
            {
                if (destination.Length >= bytes.Length)
                {
                    bytes.CopyTo(destination);
                    destination = destination.Slice(bytes.Length);
                }
                else
                {
                    bytes.Slice(0, destination.Length).CopyTo(destination);
                    return;
                }
            }
        }

        private static void CircularCopyUtf16BE(ReadOnlySpan<char> password, Span<byte> destination)
        {
            int fullCopyLen = password.Length * 2;
            Encoding bigEndianUnicode = System.Text.Encoding.BigEndianUnicode;

            while (destination.Length > 0)
            {
                if (destination.Length >= fullCopyLen)
                {
                    int count = bigEndianUnicode.GetBytes(password, destination);

                    if (count != fullCopyLen)
                    {
                        Debug.Fail($"Unexpected written byte count ({count} vs {fullCopyLen})");
                        throw new CryptographicException();
                    }

                    destination = destination.Slice(count);
                    Span<byte> nullTerminator = destination.Slice(0, Math.Min(2, destination.Length));
                    nullTerminator.Clear();
                    destination = destination.Slice(nullTerminator.Length);
                }
                else
                {
                    ReadOnlySpan<char> trimmed = password.Slice(0, destination.Length / 2);

                    int count = bigEndianUnicode.GetBytes(trimmed, destination);
                    destination = destination.Slice(count);

                    // Allow one trailing byte if the formula produced an odd length destination
                    if (destination.Length > 1)
                    {
                        Debug.Fail($"Partial copy wrote {count} bytes and left {destination.Length} bytes unassigned");
                        throw new CryptographicException();
                    }

                    destination.Clear();
                    return;
                }
            }
        }
    }
}
