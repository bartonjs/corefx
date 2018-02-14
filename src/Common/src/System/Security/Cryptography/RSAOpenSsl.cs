// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using Microsoft.Win32.SafeHandles;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
    internal class RsaPaddingProcessor
    {
        private static readonly Dictionary<HashAlgorithmName, RsaPaddingProcessor> s_lookup =
            new Dictionary<HashAlgorithmName, RsaPaddingProcessor>();

        private static readonly byte[] s_eightZeros = new byte[8];

        private readonly HashAlgorithmName _hashAlgorithmName;
        private readonly int _hLen;

        private RsaPaddingProcessor(HashAlgorithmName hashAlgorithmName, int hLen)
        {
            _hashAlgorithmName = hashAlgorithmName;
            _hLen = hLen;
        }

        internal static RsaPaddingProcessor OpenProcessor(HashAlgorithmName hashAlgorithmName)
        {
            if (s_lookup.TryGetValue(hashAlgorithmName, out RsaPaddingProcessor processor))
            {
                return processor;
            }

            lock (s_lookup)
            {
                if (s_lookup.TryGetValue(hashAlgorithmName, out processor))
                {
                    return processor;
                }

                using (IncrementalHash hasher = IncrementalHash.CreateHash(hashAlgorithmName))
                {
                    // SHA-2-512 is the biggest we expect
                    Span<byte> stackDest = stackalloc byte[512 / 8];

                    if (hasher.TryGetHashAndReset(stackDest, out int bytesWritten))
                    {
                        processor = new RsaPaddingProcessor(hashAlgorithmName, bytesWritten);
                    }
                    else
                    {
                        byte[] big = hasher.GetHashAndReset();
                        processor = new RsaPaddingProcessor(hashAlgorithmName, big.Length);
                    }
                }

                s_lookup[hashAlgorithmName] = processor;
                return processor;
            }
        }

        internal void PadOaep(
            ReadOnlySpan<byte> source,
            Span<byte> destination)
        {
            // https://tools.ietf.org/html/rfc3447#section-7.1.2

            byte[] dbMask = null;
            Span<byte> dbMaskSpan = Span<byte>.Empty;

            try
            {
                // Since the biggest known _hLen is 512/8 (64) and destination.Length is 0 or more,
                // this shouldn't underflow without something having severely gone wrong.
                int maxInput = checked(destination.Length - _hLen - _hLen - 2);

                // 1(a) does not apply, we do not allow custom label values.

                // 1(b)
                if (source.Length > maxInput)
                {
                    throw new CryptographicException("Message too long.");
                }

                // The final message (step 2(i)) will be
                // 0x00 || maskedSeed (hLen long) || maskedDB (rest of the buffer)
                Span<byte> seed = destination.Slice(1, _hLen);
                Span<byte> db = destination.Slice(1 + _hLen);

                using (IncrementalHash hasher = IncrementalHash.CreateHash(_hashAlgorithmName))
                {
                    // DB = lHash || PS || 0x01 || M
                    Span<byte> lHash = db.Slice(0, _hLen);
                    Span<byte> mDest = db.Slice(db.Length - source.Length);
                    Span<byte> ps = db.Slice(_hLen, db.Length - _hLen - 1 - mDest.Length);
                    Span<byte> psEnd = db.Slice(_hLen + ps.Length, 1);

                    // 2(a) lHash = Hash(L), where L is the empty string.
                    if (!hasher.TryGetHashAndReset(lHash, out int hLen2) || hLen2 != _hLen)
                    {
                        Debug.Fail("TryGetHashAndReset failed with exact-size destination");
                        throw new CryptographicException();
                    }

                    // 2(b) generate a padding string of all zeros equal to the amount of unused space.
                    ps.Clear();

                    // 2(c)
                    psEnd[0] = 0x01;

                    // still 2(c)
                    source.CopyTo(mDest);

                    // 2(d)
                    RandomNumberGenerator.Fill(seed);

                    // 2(e)
                    dbMask = ArrayPool<byte>.Shared.Rent(db.Length);
                    dbMaskSpan = new Span<byte>(dbMask, 0, db.Length);
                    Mgf1(hasher, seed, dbMaskSpan);

                    // 2(f)
                    for (int i = 0; i < dbMaskSpan.Length; i++)
                    {
                        db[i] ^= dbMaskSpan[i];
                    }

                    // 2(g)
                    Span<byte> seedMask = stackalloc byte[_hLen];
                    Mgf1(hasher, db, seedMask);

                    // 2(h)
                    for (int i = 0; i < seedMask.Length; i++)
                    {
                        seed[i] ^= seedMask[i];
                    }

                    // 2(i)
                    destination[0] = 0;
                }
            }
            catch (Exception e) when (!(e is CryptographicException))
            {
                Debug.Fail("Bad exception produced from OAEP padding: " + e);
                throw new CryptographicException();
            }
            finally
            {
                if (dbMask != null)
                {
                    dbMaskSpan.Clear();
                    ArrayPool<byte>.Shared.Return(dbMask);
                }
            }
        }

        internal void DepadOaep(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            out int bytesWritten)
        {
            // https://tools.ietf.org/html/rfc3447#section-7.1.2
            using (IncrementalHash hasher = IncrementalHash.CreateHash(_hashAlgorithmName))
            {
                Span<byte> lHash = stackalloc byte[_hLen];

                if (!hasher.TryGetHashAndReset(lHash, out int hLen2) || hLen2 != _hLen)
                {
                    Debug.Fail("TryGetHashAndReset failed with exact-size destination");
                    throw new CryptographicException();
                }

                int y = source[0];
                ReadOnlySpan<byte> maskedSeed = source.Slice(1, _hLen);
                ReadOnlySpan<byte> maskedDB = source.Slice(1 + _hLen);

                Span<byte> seed = stackalloc byte[_hLen];
                // seedMask = MGF(maskedDB, hLen)
                Mgf1(hasher, maskedDB, seed);

                // seed = seedMask XOR maskedSeed
                for (int i = 0; i < seed.Length; i++)
                {
                    seed[i] ^= maskedSeed[i];
                }

                byte[] tmp = ArrayPool<byte>.Shared.Rent(source.Length);

                try
                {
                    Span<byte> dbMask = new Span<byte>(tmp, 0, maskedDB.Length);
                    // dbMask = MGF(seed, k - hLen - 1)
                    Mgf1(hasher, seed, dbMask);

                    // DB = dbMask XOR maskedDB
                    for (int i = 0; i < dbMask.Length; i++)
                    {
                        dbMask[i] ^= maskedDB[i];
                    }

                    ReadOnlySpan<byte> lHashPrime = dbMask.Slice(0, _hLen);

                    int separatorPos = int.MaxValue;

                    for (int i = dbMask.Length - 1; i >= _hLen; i--)
                    {
                        // if dbMask[i] is 1, val is 0. otherwise val is [01,FF]
                        byte dbMinus1 = (byte)(dbMask[i] - 1);
                        int val = dbMinus1;

                        // if val is 0: FFFFFFFF & FFFFFFFF => FFFFFFFF
                        // if val is any other byte value, val-1 will be in the range 00000000 to 000000FE,
                        // and so the high bit will not be set.
                        val = (~val & (val - 1)) >> 31;

                        // if val is 0: separator = (0 & i) | (~0 & separator) => separator
                        // else: separator = (~0 & i) | (0 & separator) => i
                        //
                        // Net result: non-branching "if (dbMask[i] == 1) separatorPos = i;"
                        separatorPos = (val & i) | (~val & separatorPos);
                    }

                    bool lHashMatches = CryptographicOperations.FixedTimeEquals(lHash, lHashPrime);
                    bool yIsZero = y == 0;
                    bool separatorMadeSense = separatorPos < dbMask.Length;

                    bool shouldContinue = lHashMatches & yIsZero & separatorMadeSense;

                    if (!shouldContinue)
                    {
                        throw new CryptographicException("Padding failed.");
                    }

                    Span<byte> message = dbMask.Slice(separatorPos + 1);
                    message.CopyTo(destination);
                    bytesWritten = message.Length;
                }
                finally
                {
                    Array.Clear(tmp, 0, source.Length);
                    ArrayPool<byte>.Shared.Return(tmp);
                }
            }
        }

        internal void EncodePss(ReadOnlySpan<byte> mHash, Span<byte> destination, int keySize)
        {
            // https://tools.ietf.org/html/rfc3447#section-9.1.1
            int emBits = keySize - 1;
            int emLen = (emBits + 7) / 8;
            
            // In this implementation, sLen is restricted to hLen.
            int sLen = _hLen;

            // 3.  if emLen < hLen + sLen + 2, encoding error.
            //
            // sLen = hLen in this implementation.

            if (emLen < 2 + _hLen + sLen)
            {
                throw new CryptographicException("Input is too big.");
            }

            if (mHash.Length != _hLen)
            {
                throw new CryptographicException("Hash is of the wrong size.");
            }

            // Set any leading bytes to zero, since that will be required for the pending
            // RSA operation.
            destination.Slice(0, destination.Length - emLen).Clear();

            // 12. Let EM = maskedDB || H || 0xbc (H has length hLen)
            Span<byte> em = destination.Slice(destination.Length - emLen, emLen);

            int dbLen = emLen - _hLen - 1;

            Span<byte> db = em.Slice(0, dbLen);
            Span<byte> hDest = em.Slice(dbLen, _hLen);
            em[emLen - 1] = 0xBC;

            byte[] dbMaskRented = ArrayPool<byte>.Shared.Rent(dbLen);
            Span<byte> dbMask = new Span<byte>(dbMaskRented, 0, dbLen);

            using (IncrementalHash hasher = IncrementalHash.CreateHash(_hashAlgorithmName))
            {
                // 4. Generate a random salt of length sLen
                Span<byte> salt = stackalloc byte[sLen];
                RandomNumberGenerator.Fill(salt);

                // 5. Let M' = an octet string of 8 zeros concat mHash concat salt
                // 6. Let H = Hash(M')

                hasher.AppendData(s_eightZeros);
                hasher.AppendData(mHash);
                hasher.AppendData(salt);

                if (!hasher.TryGetHashAndReset(hDest, out int hLen2) || hLen2 != _hLen)
                {
                    Debug.Fail("TryGetHashAndReset failed with exact-size destination");
                    throw new CryptographicException();
                }

                // 7. Generate PS as zero-valued bytes of length emLen - sLen - hLen - 2.
                // 8. Let DB = PS || 0x01 || salt
                int psLen = emLen - sLen - _hLen - 2;
                db.Slice(0, psLen).Clear();
                db[psLen] = 0x01;
                salt.CopyTo(db.Slice(psLen + 1));

                // 9. Let dbMask = MGF(H, emLen - hLen - 1)
                Mgf1(hasher, hDest, dbMask);

                // 10. Let maskedDB = DB XOR dbMask
                for (int i = 0; i < dbMask.Length; i++)
                {
                    db[i] ^= dbMask[i];
                }

                // 11. Set the "unused" bits in the leftmost byte of maskedDB to 0.
                int unusedBits = 8 * emLen - emBits;

                if (unusedBits != 0)
                {
                    byte mask = (byte)(0xFF >> unusedBits);
                    db[0] &= mask;
                }
            }

            dbMask.Clear();
            ArrayPool<byte>.Shared.Return(dbMaskRented);
        }

        internal bool VerifyPss(ReadOnlySpan<byte> mHash, ReadOnlySpan<byte> em, int keySize)
        {
            int emBits = keySize - 1;
            int emLen = (emBits + 7) / 8;

            Debug.Assert(em.Length >= emLen);

            // In this implementation, sLen is restricted to hLen.
            int sLen = _hLen;

            // 3. If emLen < hLen + sLen + 2, output "inconsistent" and stop.
            if (emLen < _hLen + sLen + 2)
            {
                return false;
            }

            // 4. If the last byte is not 0xBC, output "inconsistent" and stop.
            if (em[em.Length - 1] != 0xBC)
            {
                return false;
            }

            // 5. maskedDB is the leftmost emLen - hLen -1 bytes, H is the next hLen bytes.
            int dbLen = emLen - _hLen - 1;

            ReadOnlySpan<byte> maskedDb = em.Slice(0, dbLen);
            ReadOnlySpan<byte> h = em.Slice(dbLen, _hLen);

            // 6. If the unused bits aren't zero, output "inconsistent" and stop.
            int unusedBits = 8 * emLen - emBits;
            byte usedBitsMask = (byte)(0xFF >> unusedBits);

            if ((maskedDb[0] & usedBitsMask) != maskedDb[0])
            {
                return false;
            }

            // 7. dbMask = MGF(H, emLen - hLen - 1)
            byte[] dbMaskRented = ArrayPool<byte>.Shared.Rent(maskedDb.Length);
            Span<byte> dbMask = new Span<byte>(dbMaskRented, 0, maskedDb.Length);

            try
            {
                using (IncrementalHash hasher = IncrementalHash.CreateHash(_hashAlgorithmName))
                {
                    Mgf1(hasher, h, dbMask);

                    // 8. DB = maskedDB XOR dbMask
                    for (int i = 0; i < dbMask.Length; i++)
                    {
                        dbMask[i] ^= maskedDb[i];
                    }

                    // 9. Set the unused bits of DB to 0
                    dbMask[0] &= usedBitsMask;

                    // 10 ("a"): If the emLen - hLen - sLen - 2 leftmost bytes are not 0,
                    // output "inconsistent" and stop.
                    //
                    // Since signature verification is a public key operation there's no need to
                    // use fixed time equality checking here.
                    for (int i = emLen - _hLen - sLen - 2 - 1; i >= 0; --i)
                    {
                        if (dbMask[i] != 0)
                        {
                            return false;
                        }
                    }

                    // 10 ("b") If the octet at position emLen - hLen - sLen - 1 (under a 1-indexed scheme)
                    // is not 0x01, output "inconsistent" and stop.
                    if (dbMask[emLen - _hLen - sLen - 2] != 0x01)
                    {
                        return false;
                    }

                    // 11. Let salt be the last sLen octets of DB.
                    ReadOnlySpan<byte> salt = dbMask.Slice(dbMask.Length - sLen);

                    // 12/13. Let H' = Hash(eight zeros || mHash || salt)
                    hasher.AppendData(s_eightZeros);
                    hasher.AppendData(mHash);
                    hasher.AppendData(salt);

                    Span<byte> hPrime = stackalloc byte[_hLen];

                    if (!hasher.TryGetHashAndReset(hPrime, out int hLen2) || hLen2 != _hLen)
                    {
                        Debug.Fail("TryGetHashAndReset failed with exact-size destination");
                        throw new CryptographicException();
                    }

                    // 14. If H = H' output "consistent". Otherwise, output "inconsistent"
                    //
                    // Since this is a public key operation, no need to provide fixed time
                    // checking.
                    return h.SequenceEqual(hPrime);
                }
            }
            finally
            {
                dbMask.Clear();
                ArrayPool<byte>.Shared.Return(dbMaskRented);
            }
        }

        // https://tools.ietf.org/html/rfc3447#appendix-B.2.1
        private void Mgf1(IncrementalHash hasher, ReadOnlySpan<byte> mgfSeed, Span<byte> mask)
        {
            Span<byte> writePtr = mask;
            int count = 0;
            Span<byte> bigEndianCount = stackalloc byte[sizeof(int)];

            while (writePtr.Length > 0)
            {
                hasher.AppendData(mgfSeed);
                BinaryPrimitives.WriteInt32BigEndian(bigEndianCount, count);
                hasher.AppendData(bigEndianCount);

                if (writePtr.Length >= _hLen)
                {
                    if (!hasher.TryGetHashAndReset(writePtr, out int bytesWritten))
                    {
                        Debug.Fail($"TryGetHashAndReset failed with sufficient space");
                        throw new CryptographicException();
                    }

                    Debug.Assert(bytesWritten == _hLen);
                    writePtr = writePtr.Slice(bytesWritten);
                }
                else
                {
                    Span<byte> tmp = stackalloc byte[_hLen];

                    if (!hasher.TryGetHashAndReset(tmp, out int bytesWritten))
                    {
                        Debug.Fail($"TryGetHashAndReset failed with sufficient space");
                        throw new CryptographicException();
                    }

                    Debug.Assert(bytesWritten == _hLen);
                    tmp.Slice(0, writePtr.Length).CopyTo(writePtr);
                    break;
                }

                count++;
            }
        }
    }

#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    public partial class RSA : AsymmetricAlgorithm
    {
        public static new RSA Create() => new RSAImplementation.RSAOpenSsl();
    }

    internal static partial class RSAImplementation
    {
#endif
    public sealed partial class RSAOpenSsl : RSA
    {
        private const int BitsPerByte = 8;

        // 65537 (0x10001) in big-endian form
        private static readonly byte[] s_defaultExponent = { 0x01, 0x00, 0x01 };

        private Lazy<SafeRsaHandle> _key;

        public RSAOpenSsl()
            : this(2048)
        {
        }

        public RSAOpenSsl(int keySize)
        {
            KeySize = keySize;
            _key = new Lazy<SafeRsaHandle>(GenerateKey);
        }

        public override int KeySize
        {
            set
            {
                if (KeySize == value)
                {
                    return;
                }

                // Set the KeySize before FreeKey so that an invalid value doesn't throw away the key
                base.KeySize = value;

                FreeKey();
                _key = new Lazy<SafeRsaHandle>(GenerateKey);
            }
        }

        private void ForceSetKeySize(int newKeySize)
        {
            // In the event that a key was loaded via ImportParameters or an IntPtr/SafeHandle
            // it could be outside of the bounds that we currently represent as "legal key sizes".
            // Since that is our view into the underlying component it can be detached from the
            // component's understanding.  If it said it has opened a key, and this is the size, trust it.
            KeySizeValue = newKeySize;
        }

        public override KeySizes[] LegalKeySizes
        {
            get
            {
                // OpenSSL seems to accept answers of all sizes.
                // Choosing a non-multiple of 8 would make some calculations misalign
                // (like assertions of (output.Length * 8) == KeySize).
                // Choosing a number too small is insecure.
                // Choosing a number too large will cause GenerateKey to take much
                // longer than anyone would be willing to wait.
                //
                // So, copying the values from RSACryptoServiceProvider
                return new[] { new KeySizes(384, 16384, 8) };
            }
        }

        public override byte[] Decrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out RsaPaddingProcessor oaepProcessor);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            int rsaSize = Interop.Crypto.RsaSize(key);
            byte[] buf = null;

            try
            {
                buf = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> destination = new Span<byte>(buf, 0, rsaSize);

                if (!TryDecrypt(key, data, destination, rsaPadding, oaepProcessor, out int bytesWritten))
                {
                    Debug.Fail($"{nameof(TryDecrypt)} should not return false for RSA_size buffer");
                    throw new CryptographicException();
                }

                return destination.Slice(0, bytesWritten).ToArray();
            }
            finally
            {
                if (buf != null)
                {
                    Array.Clear(buf, 0, rsaSize);
                    ArrayPool<byte>.Shared.Return(buf);
                }
            }
        }

        public override bool TryDecrypt(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            RSAEncryptionPadding padding,
            out int bytesWritten)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out RsaPaddingProcessor oaepProcessor);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            return TryDecrypt(key, source, destination, rsaPadding, oaepProcessor, out bytesWritten);
        }

        private static bool TryDecrypt(
            SafeRsaHandle key,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            Interop.Crypto.RsaPadding rsaPadding,
            RsaPaddingProcessor rsaPaddingProcessor,
            out int bytesWritten)
        {
            // If rsaPadding is PKCS1 or OAEP-SHA1 then no depadding method should be present.
            // If rsaPadding is NoPadding then a depadding method should be present.
            Debug.Assert(
                (rsaPadding == Interop.Crypto.RsaPadding.NoPadding) ==
                (rsaPaddingProcessor != null));

            // Caller should have already checked this.
            Debug.Assert(!key.IsInvalid);

            int rsaSize = Interop.Crypto.RsaSize(key);

            if (destination.Length < rsaSize)
            {
                bytesWritten = 0;
                return false;
            }

            Span<byte> decryptBuf = destination;
            byte[] paddingBuf = null;

            if (rsaPaddingProcessor != null)
            {
                paddingBuf = ArrayPool<byte>.Shared.Rent(rsaSize);
                decryptBuf = paddingBuf;
            }

            try
            {
                int returnValue = Interop.Crypto.RsaPrivateDecrypt(source.Length, source, decryptBuf, key, rsaPadding);
                CheckReturn(returnValue);

                if (rsaPaddingProcessor != null)
                {
                    rsaPaddingProcessor.DepadOaep(paddingBuf, destination, out bytesWritten);
                }
                else
                {
                    // If the padding mode is RSA_NO_PADDING then the size of the decrypted block
                    // will be RSA_size. If any padding was used, then some amount (determined by the padding algorithm)
                    // will have been reduced, and only returnValue bytes were part of the decrypted
                    // body.  Either way, we can just use returnValue, but some additional bytes may have been overwritten
                    // in the destination span.
                    bytesWritten = returnValue;
                }

                return true;
            }
            finally
            {
                if (paddingBuf != null)
                {
                    Array.Clear(paddingBuf, 0, rsaSize);
                    ArrayPool<byte>.Shared.Return(paddingBuf);
                }
            }
        }

        public override byte[] Encrypt(byte[] data, RSAEncryptionPadding padding)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out RsaPaddingProcessor oaepProcessor);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            byte[] buf = new byte[Interop.Crypto.RsaSize(key)];

            bool encrypted = TryEncrypt(
                key,
                data,
                buf,
                rsaPadding,
                oaepProcessor,
                out int bytesWritten);

            if (!encrypted || bytesWritten != buf.Length)
            {
                Debug.Fail("TryEncrypt behaved unexpectedly");
                throw new CryptographicException();
            }

            return buf;
        }

        public override bool TryEncrypt(ReadOnlySpan<byte> source, Span<byte> destination, RSAEncryptionPadding padding, out int bytesWritten)
        {
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            Interop.Crypto.RsaPadding rsaPadding = GetInteropPadding(padding, out RsaPaddingProcessor oaepProcessor);
            SafeRsaHandle key = _key.Value;
            CheckInvalidKey(key);

            return TryEncrypt(key, source, destination, rsaPadding, oaepProcessor, out bytesWritten);
        }

        private static bool TryEncrypt(
            SafeRsaHandle key,
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            Interop.Crypto.RsaPadding rsaPadding,
            RsaPaddingProcessor rsaPaddingProcessor,
            out int bytesWritten)
        {
            int rsaSize = Interop.Crypto.RsaSize(key);

            if (destination.Length < rsaSize)
            {
                bytesWritten = 0;
                return false;
            }

            int returnValue;

            if (rsaPaddingProcessor != null)
            {
                Debug.Assert(rsaPadding == Interop.Crypto.RsaPadding.NoPadding);
                byte[] rented = ArrayPool<byte>.Shared.Rent(rsaSize);
                Span<byte> tmp = new Span<byte>(rented, 0, rsaSize);

                try
                {
                    rsaPaddingProcessor.PadOaep(source, tmp);
                    returnValue = Interop.Crypto.RsaPublicEncrypt(tmp.Length, tmp, destination, key, rsaPadding);
                }
                finally
                {
                    tmp.Clear();
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }
            else
            {
                Debug.Assert(rsaPadding != Interop.Crypto.RsaPadding.NoPadding);

                returnValue = Interop.Crypto.RsaPublicEncrypt(source.Length, source, destination, key, rsaPadding);
            }

            CheckReturn(returnValue);

            bytesWritten = returnValue;
            Debug.Assert(returnValue == rsaSize);
            return true;

        }

        private static Interop.Crypto.RsaPadding GetInteropPadding(
            RSAEncryptionPadding padding,
            out RsaPaddingProcessor rsaPaddingProcessor)
        {
            if (padding == RSAEncryptionPadding.Pkcs1)
            {
                rsaPaddingProcessor = null;
                return Interop.Crypto.RsaPadding.Pkcs1;
            }

            if (padding == RSAEncryptionPadding.OaepSHA1)
            {
                rsaPaddingProcessor = null;
                return Interop.Crypto.RsaPadding.OaepSHA1;
            }

            if (padding.Mode == RSAEncryptionPaddingMode.Oaep)
            {
                rsaPaddingProcessor = RsaPaddingProcessor.OpenProcessor(padding.OaepHashAlgorithm);
                return Interop.Crypto.RsaPadding.NoPadding;
            }

            throw PaddingModeNotSupported();
        }

        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            // It's entirely possible that this line will cause the key to be generated in the first place.
            SafeRsaHandle key = _key.Value;

            CheckInvalidKey(key);

            RSAParameters rsaParameters = Interop.Crypto.ExportRsaParameters(key, includePrivateParameters);
            bool hasPrivateKey = rsaParameters.D != null;

            if (hasPrivateKey != includePrivateParameters || !HasConsistentPrivateKey(ref rsaParameters))
            {
                throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
            }

            return rsaParameters;
        }
        
        public override void ImportParameters(RSAParameters parameters)
        {
            ValidateParameters(ref parameters);

            SafeRsaHandle key = Interop.Crypto.RsaCreate();
            bool imported = false;

            Interop.Crypto.CheckValidOpenSslHandle(key);

            try
            {
                Interop.Crypto.SetRsaParameters(
                    key,
                    parameters.Modulus,
                    parameters.Modulus != null ? parameters.Modulus.Length : 0,
                    parameters.Exponent,
                    parameters.Exponent != null ? parameters.Exponent.Length : 0,
                    parameters.D,
                    parameters.D != null ? parameters.D.Length : 0,
                    parameters.P,
                    parameters.P != null ? parameters.P.Length : 0,
                    parameters.DP, 
                    parameters.DP != null ? parameters.DP.Length : 0,
                    parameters.Q,
                    parameters.Q != null ? parameters.Q.Length : 0,
                    parameters.DQ, 
                    parameters.DQ != null ? parameters.DQ.Length : 0,
                    parameters.InverseQ,
                    parameters.InverseQ != null ? parameters.InverseQ.Length : 0);

                imported = true;
            }
            finally
            {
                if (!imported)
                {
                    key.Dispose();
                }
            }

            FreeKey();
            _key = new Lazy<SafeRsaHandle>(key);

            // Use ForceSet instead of the property setter to ensure that LegalKeySizes doesn't interfere
            // with the already loaded key.
            ForceSetKeySize(BitsPerByte * Interop.Crypto.RsaSize(key));
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                FreeKey();
            }

            base.Dispose(disposing);
        }

        private void FreeKey()
        {
            if (_key != null && _key.IsValueCreated)
            {
                SafeRsaHandle handle = _key.Value;
                handle?.Dispose();
            }
        }

        private static void ValidateParameters(ref RSAParameters parameters)
        {
            if (parameters.Modulus == null || parameters.Exponent == null)
                throw new CryptographicException(SR.Argument_InvalidValue);

            if (!HasConsistentPrivateKey(ref parameters))
                throw new CryptographicException(SR.Argument_InvalidValue);
        }

        private static bool HasConsistentPrivateKey(ref RSAParameters parameters)
        {
            if (parameters.D == null)
            {
                if (parameters.P != null ||
                    parameters.DP != null ||
                    parameters.Q != null ||
                    parameters.DQ != null ||
                    parameters.InverseQ != null)
                {
                    return false;
                }
            }
            else
            {
                if (parameters.P == null ||
                    parameters.DP == null ||
                    parameters.Q == null ||
                    parameters.DQ == null ||
                    parameters.InverseQ == null)
                {
                    return false;
                }
            }

            return true;
        }

        private static void CheckInvalidKey(SafeRsaHandle key)
        {
            if (key == null || key.IsInvalid)
            {
                throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
            }
        }

        private static void CheckReturn(int returnValue)
        {
            if (returnValue == -1)
            {
                throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }

        private static void CheckBoolReturn(int returnValue)
        {
            if (returnValue != 1)
            {
               throw Interop.Crypto.CreateOpenSslCryptographicException();
            }
        }

        private SafeRsaHandle GenerateKey()
        {
            SafeRsaHandle key = Interop.Crypto.RsaCreate();
            bool generated = false;

            Interop.Crypto.CheckValidOpenSslHandle(key);

            try
            {
                using (SafeBignumHandle exponent = Interop.Crypto.CreateBignum(s_defaultExponent))
                {
                    // The documentation for RSA_generate_key_ex does not say that it returns only
                    // 0 or 1, so the call marshals it back as a full Int32 and checks for a value
                    // of 1 explicitly.
                    int response = Interop.Crypto.RsaGenerateKeyEx(
                        key,
                        KeySize,
                        exponent);

                    CheckBoolReturn(response);
                    generated = true;
                }
            }
            finally
            {
                if (!generated)
                {
                    key.Dispose();
                }
            }

            return key;
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
            AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

        protected override bool TryHashData(ReadOnlySpan<byte> source, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
            AsymmetricAlgorithmHelpers.TryHashData(source, destination, hashAlgorithm, out bytesWritten);

        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (hash == null)
                throw new ArgumentNullException(nameof(hash));
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
                throw HashAlgorithmNameNullOrEmpty();
            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            if (!TrySignHash(
                hash,
                Span<byte>.Empty,
                hashAlgorithm, padding,
                true,
                out int bytesWritten,
                out byte[] signature))
            {
                Debug.Fail("TrySignHash should not return false in allocation mode");
                throw new CryptographicException();
            }

            Debug.Assert(signature != null);
            return signature;
        }

        public override bool TrySignHash(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding,
            out int bytesWritten)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            bool ret = TrySignHash(
                source,
                destination,
                hashAlgorithm,
                padding,
                false,
                out bytesWritten,
                out byte[] alloced);

            Debug.Assert(alloced == null);
            return ret;
        }

        private bool TrySignHash(
            ReadOnlySpan<byte> hash,
            Span<byte> destination,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding,
            bool allocateSignature,
            out int bytesWritten,
            out byte[] signature)
        {
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));
            Debug.Assert(padding != null);

            signature = null;

            // Do not factor out getting _key.Value, since the key creation should not happen on
            // invalid padding modes.

            if (padding.Mode == RSASignaturePaddingMode.Pkcs1)
            {
                int algorithmNid = GetAlgorithmNid(hashAlgorithm);
                SafeRsaHandle rsa = _key.Value;

                int bytesRequired = Interop.Crypto.RsaSize(rsa);

                if (allocateSignature)
                {
                    Debug.Assert(destination.Length == 0);
                    signature = new byte[bytesRequired];
                    destination = signature;
                }

                if (destination.Length < bytesRequired)
                {
                    bytesWritten = 0;
                    return false;
                }

                if (!Interop.Crypto.RsaSign(algorithmNid, hash, hash.Length, destination, out int signatureSize, rsa))
                {
                    throw Interop.Crypto.CreateOpenSslCryptographicException();
                }

                Debug.Assert(
                    signatureSize == bytesRequired,
                    $"RSA_sign reported signatureSize was {signatureSize}, when {bytesRequired} was expected");

                bytesWritten = signatureSize;
                return true;
            }
            else if (padding.Mode == RSASignaturePaddingMode.Pss)
            {
                RsaPaddingProcessor processor = RsaPaddingProcessor.OpenProcessor(hashAlgorithm);
                SafeRsaHandle rsa = _key.Value;

                int bytesRequired = Interop.Crypto.RsaSize(rsa);

                if (allocateSignature)
                {
                    Debug.Assert(destination.Length == 0);
                    signature = new byte[bytesRequired];
                    destination = signature;
                }

                if (destination.Length < bytesRequired)
                {
                    bytesWritten = 0;
                    return false;
                }

                byte[] pssRented = ArrayPool<byte>.Shared.Rent(bytesRequired);
                Span<byte> pssBytes = new Span<byte>(pssRented, 0, bytesRequired);

                processor.EncodePss(hash, pssBytes, KeySize);

                int ret = Interop.Crypto.RsaSignPrimitive(pssBytes, destination, rsa);

                pssBytes.Clear();
                ArrayPool<byte>.Shared.Return(pssRented);

                CheckReturn(ret);

                Debug.Assert(
                    ret == signature.Length,
                    $"RSA_private_encrypt returned {ret} when {signature.Length} was expected");

                bytesWritten = ret;
                return true;
            }

            throw PaddingModeNotSupported();
        }

        public override bool VerifyHash(
            byte[] hash,
            byte[] signature,
            HashAlgorithmName hashAlgorithm,
            RSASignaturePadding padding)
        {
            if (hash == null)
            {
                throw new ArgumentNullException(nameof(hash));
            }
            if (signature == null)
            {
                throw new ArgumentNullException(nameof(signature));
            }

            return VerifyHash(new ReadOnlySpan<byte>(hash), new ReadOnlySpan<byte>(signature), hashAlgorithm, padding);
        }

        public override bool VerifyHash(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            if (string.IsNullOrEmpty(hashAlgorithm.Name))
            {
                throw HashAlgorithmNameNullOrEmpty();
            }
            if (padding == null)
            {
                throw new ArgumentNullException(nameof(padding));
            }

            if (padding == RSASignaturePadding.Pkcs1)
            {
                int algorithmNid = GetAlgorithmNid(hashAlgorithm);
                SafeRsaHandle rsa = _key.Value;
                return Interop.Crypto.RsaVerify(algorithmNid, hash, hash.Length, signature, signature.Length, rsa);
            }
            else if (padding == RSASignaturePadding.Pss)
            {
                RsaPaddingProcessor processor = RsaPaddingProcessor.OpenProcessor(hashAlgorithm);
                SafeRsaHandle rsa = _key.Value;

                int requiredBytes = Interop.Crypto.RsaSize(rsa);

                if (signature.Length != requiredBytes)
                {
                    return false;
                }

                byte[] rented = ArrayPool<byte>.Shared.Rent(requiredBytes);
                Span<byte> unwrapped = new Span<byte>(rented, 0, requiredBytes);

                try
                {
                    int ret = Interop.Crypto.RsaVerificationPrimitive(signature, unwrapped, rsa);

                    CheckReturn(ret);

                    Debug.Assert(
                        ret == requiredBytes,
                        $"RSA_private_encrypt returned {ret} when {requiredBytes} was expected");

                    return processor.VerifyPss(hash, unwrapped, KeySize);
                }
                finally
                {
                    unwrapped.Clear();
                    ArrayPool<byte>.Shared.Return(rented);
                }
            }

            throw PaddingModeNotSupported();
        }

        private static int GetAlgorithmNid(HashAlgorithmName hashAlgorithmName)
        {
            // All of the current HashAlgorithmName values correspond to the SN values in OpenSSL 0.9.8.
            // If there's ever a new one that doesn't, translate it here.
            string sn = hashAlgorithmName.Name;

            int nid = Interop.Crypto.ObjSn2Nid(sn);

            if (nid == Interop.Crypto.NID_undef)
            {
                throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithmName.Name);
            }

            return nid;
        }

        private static Exception PaddingModeNotSupported() =>
            new CryptographicException(SR.Cryptography_InvalidPaddingMode);

        private static Exception HashAlgorithmNameNullOrEmpty() =>
            new ArgumentException(SR.Cryptography_HashAlgorithmNameNullOrEmpty, "hashAlgorithm");
    }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#endif
}
