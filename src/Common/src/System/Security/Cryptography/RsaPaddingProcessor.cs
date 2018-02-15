// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;

namespace System.Security.Cryptography
{
    internal sealed class RsaPaddingProcessor
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
                    throw new CryptographicException(
                        SR.Format(SR.Cryptography_Encryption_MessageTooLong, maxInput));
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
                        throw new CryptographicException(SR.Cryptography_OAEP_Decryption_Failed);
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

            // In this implementation, sLen is restricted to the hLen of the declared hash.
            int sLen = _hLen;

            // 3.  if emLen < hLen + sLen + 2, encoding error.
            //
            // sLen = hLen in this implementation.

            if (emLen < 2 + _hLen + sLen)
            {
                throw new CryptographicException(SR.Cryptography_PSS_KeyTooSmall);
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
}
