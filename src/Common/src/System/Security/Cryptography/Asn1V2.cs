// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.InteropServices;

namespace System.Security.Cryptography.Asn1
{
    // Uses a masked overlay of the tag class encoding.
    // T-REC-X.690-201508 sec 8.1.2.2
    internal enum TagClass : byte
    {
        Universal = 0,
        Application = 0b0100_0000,
        ContextSpecific = 0b1000_0000,
        Private = 0b1100_0000,
    }

    internal enum UniversalTagNumber
    {
        EndOfContents = 0,
        Boolean = 1,
        Integer = 2,
        BitString = 3,
        OctetString = 4,
        Null = 5,
        ObjectIdentifier = 6,
        ObjectDescriptor = 7,
        External = 8,
        InstanceOf = External,
        Real = 9,
        Enumerated = 10,
        Embedded = 11,
        UTF8String = 12,
        RelativeObjectIdentifier = 13,
        Time = 14,
        // 15 is reserved
        Sequence = 16,
        SequenceOf = Sequence,
        Set = 17,
        SetOf = Set,
        NumericString = 18,
        PrintableString = 19,
        TeletexString = 20,
        T61String = TeletexString,
        VideotexString = 21,
        IA5String = 22,
        UtcTime = 23,
        GenrealizedTime = 24,
        GraphicString = 25,
        VisibleString = 26,
        ISO646String = VisibleString,
        GeneralString = 27,
        UniversalString = 28,
        UnrestrictedCharacterString = 29,
        BMPString = 30,
        Date = 31,
        TimeOfDay = 32,
        DateTime = 33,
        Duration = 34,
    }

    internal struct Asn1Tag
    {
        private const byte ClassMask = 0b1100_0000;
        private const byte ConstructedMask = 0b0010_0000;
        private const byte ControlMask = ClassMask | ConstructedMask;
        private const byte TagNumberMask = 0b0001_1111;

        internal static readonly Asn1Tag EndOfContents = new Asn1Tag(0);

        private readonly byte _controlFlags;
        private readonly int _tagValue;

        public TagClass TagClass => (TagClass)(_controlFlags & ClassMask);
        public bool IsConstructed => (_controlFlags & ConstructedMask) == ConstructedMask;
        public int TagValue => _tagValue;

        private Asn1Tag(byte controlFlags, int tagValue)
        {
            _controlFlags = (byte)(controlFlags & ControlMask);
            _tagValue = tagValue;
        }

        public Asn1Tag(byte singleByteEncoding)
        {
            unsafe
            {
                byte* data = &singleByteEncoding;

                if (TryParse(new ReadOnlySpan<byte>(data, 1), out Asn1Tag parsed, out int bytesRead))
                {
                    Debug.Assert(bytesRead == 1);
                    _controlFlags = parsed._controlFlags;
                    _tagValue = parsed._tagValue;
                }
                else
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }
        }

        public static bool TryParse(ReadOnlySpan<byte> source, out Asn1Tag tag, out int bytesRead)
        {
            tag = default(Asn1Tag);
            bytesRead = 0;

            if (source.IsEmpty)
                return false;

            bytesRead++;
            byte first = source[0];
            uint tagValue = (uint)(first & TagNumberMask);

            if (tagValue == TagNumberMask)
            {
                // Multi-byte encoding
                // T-REC-X.690-201508 sec 8.1.2.4
                const byte ContinuationFlag = 0x80;
                const byte ValueMask = ContinuationFlag - 1;

                tagValue = 0;
                byte current;

                do
                {
                    if (source.Length <= bytesRead)
                    {
                        bytesRead = 0;
                        return false;
                    }

                    current = source[bytesRead];
                    byte currentValue = (byte)(current & ValueMask);
                    bytesRead++;

                    // The first byte cannot have the value 0 (T-REC-X.690-201508 sec 8.1.2.4.2.c)
                    if (currentValue == 0 && tagValue == 0)
                    {
                        bytesRead = 0;
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    // If TooBigToShift is shifted left 7, the content bit shifts out.
                    // So any value greater than or equal to this cannot be shifted without loss.
                    const int TooBigToShift = 0b00000010_00000000_00000000_00000000;

                    if (tagValue >= TooBigToShift)
                    {
                        bytesRead = 0;
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    tagValue <<= 7;
                    tagValue |= currentValue;
                }
                while ((current & ContinuationFlag) == ContinuationFlag);

                // This encoding is only valid for tag values greater than 30.
                // (T-REC-X.690-201508 sec 8.1.2.3, 8.1.2.4)

                if (tagValue <= 30)
                {
                    bytesRead = 0;
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // There's not really any ambiguity, but prevent negative numbers from showing up.
                if (tagValue > int.MaxValue)
                {
                    bytesRead = 0;
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            tag = new Asn1Tag(first, (int)tagValue);
            return true;
        }

        public bool Equals(Asn1Tag other)
        {
            return _controlFlags == other._controlFlags && _tagValue == other._tagValue;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            return obj is Asn1Tag && Equals((Asn1Tag)obj);
        }

        public override int GetHashCode()
        {
            // Most TagValue values will be in the 0-30 range,
            // the GetHashCode value only has collisions when TagValue is
            // between 2^29 and uint.MaxValue
            return (_controlFlags << 24) ^ _tagValue;
        }

        public static bool operator ==(Asn1Tag left, Asn1Tag right)
        {
            return left.Equals(right);
        }

        public static bool operator !=(Asn1Tag left, Asn1Tag right)
        {
            return !left.Equals(right);
        }
    }

    internal enum AsnEncodingRules
    {
        BasicEncodingRules,
        BER = BasicEncodingRules,
        CanonicalEncodingRules,
        CER = CanonicalEncodingRules,
        DistinguishedEncodingRules,
        DER = DistinguishedEncodingRules,
    }

    internal struct AsnReader
    {
        // ITU-T-REC-X.690-201508 sec 9.2
        private const int MaxCERSegmentSize = 1000;

        private ReadOnlySpan<byte> _data;

        public bool HasData => !_data.IsEmpty;

        public AsnReader(ReadOnlySpan<byte> data)
        {
            _data = data;
        }

        public static bool TryPeekTag(ReadOnlySpan<byte> source, out Asn1Tag tag, out int bytesRead)
        {
            return Asn1Tag.TryParse(source, out tag, out bytesRead);
        }

        public Asn1Tag PeekTag()
        {
            if (TryPeekTag(_data, out Asn1Tag tag, out int bytesRead))
            {
                return tag;
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static bool TryReadLength(
            ReadOnlySpan<byte> source,
            AsnEncodingRules ruleSet,
            out int? length,
            out int bytesRead)
        {
            length = null;
            bytesRead = 0;

            CheckEncodingRules(ruleSet);

            if (source.IsEmpty)
                return false;

            // T-REC-X.690-201508 sec 8.1.3

            bytesRead++;
            byte lengthOrLengthLength = source[0];
            const byte MultiByteMarker = 0x80;

            // 0x00-0x7F are direct length values.
            // 0x80 is BER/CER indefinite length.
            // 0x81-0xFE says that the length takes the next 1-126 bytes.
            // 0xFF is forbidden.
            if (lengthOrLengthLength == MultiByteMarker)
            {
                // T-REC-X.690-201508 sec 10.1 (DER: Length forms)
                if (ruleSet == AsnEncodingRules.DER)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                // Null length == indefinite.
                return true;
            }

            if (lengthOrLengthLength < MultiByteMarker)
            {
                length = lengthOrLengthLength;
                return true;
            }

            if (lengthOrLengthLength == 0xFF)
            {
                bytesRead = 0;
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            byte lengthLength = (byte)(lengthOrLengthLength & ~MultiByteMarker);

            // +1 for lengthOrLengthLength
            if (lengthLength + 1 > source.Length)
            {
                bytesRead = 0;
                return false;
            }

            // T-REC-X.690-201508 sec 9.1 (CER: Length forms)
            // T-REC-X.690-201508 sec 10.1 (DER: Length forms)
            bool minimalRepresentation =
                ruleSet == AsnEncodingRules.DER || ruleSet == AsnEncodingRules.CER;

            // The ITU-T specifications tecnically allow lengths up to ((2^128) - 1), but
            // since Span's length is a signed Int32 we're limited to identifying memory
            // that is within ((2^31) - 1) bytes of the tag start.
            if (minimalRepresentation && lengthLength > sizeof(int))
            {
                bytesRead = 0;
                return false;
            }

            uint parsedLength = 0;

            for (int i = 0; i < lengthLength; i++)
            {
                byte current = source[bytesRead];
                bytesRead++;

                if (parsedLength == 0)
                {
                    if (minimalRepresentation && current == 0)
                    {
                        bytesRead = 0;
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    if (!minimalRepresentation && current != 0)
                    {
                        // Under BER rules we could have had padding zeros, so
                        // once the first data bits come in check that we fit within
                        // sizeof(int) due to Span bounds.

                        if (lengthLength - i > sizeof(int))
                        {
                            bytesRead = 0;
                            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                        }
                    }
                }

                parsedLength <<= 8;
                parsedLength |= current;
            }

            // This value cannot be represented as a Span length.
            if (parsedLength > int.MaxValue)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (minimalRepresentation && parsedLength < MultiByteMarker)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            length = (int)parsedLength;
            return true;
        }

        internal (Asn1Tag, int?) ReadTagAndLength(AsnEncodingRules ruleSet, out int bytesRead)
        {
            if (TryPeekTag(_data, out Asn1Tag tag, out int tagBytesRead) &&
                TryReadLength(_data.Slice(tagBytesRead), ruleSet, out int? length, out int lengthBytesRead))
            {
                int allBytesRead = tagBytesRead + lengthBytesRead;

                if (tag.IsConstructed)
                {
                    // T-REC-X.690-201508 sec 9.1 (CER: Length forms) says constructed is always indefinite.
                    if (ruleSet == AsnEncodingRules.CER && length != null)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }
                else if (length == null)
                {
                    // T-REC-X.690-201508 sec 8.1.3.2 says primitive encodings must use a definite form.
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                bytesRead = allBytesRead;
                return (tag, length);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static void ValidateEndOfContents(Asn1Tag tag, int? length, int headerLength)
        {
            // T-REC-X.690-201508 sec 8.1.5 excludes the BER 8100 length form for 0.
            if (tag.IsConstructed || length != 0 || headerLength != 2)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
        }

        private static ReadOnlySpan<byte> SeekEndOfContents(
            ReadOnlySpan<byte> source,
            AsnEncodingRules ruleSet)
        {
            ReadOnlySpan<byte> cur = source;
            int totalLen = 0;

            while (!cur.IsEmpty)
            {
                AsnReader reader = new AsnReader(cur);
                (Asn1Tag tag, int? length) = reader.ReadTagAndLength(ruleSet, out int bytesRead);
                ReadOnlySpan<byte> nestedContents = reader.GetContentSpan(ruleSet);
                int localLen = bytesRead + nestedContents.Length;

                totalLen += localLen;
                cur = cur.Slice(localLen);

                if (tag == Asn1Tag.EndOfContents)
                {
                    ValidateEndOfContents(tag, length, bytesRead);

                    return source.Slice(0, totalLen);
                }
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        public ReadOnlySpan<byte> GetContentSpan(AsnEncodingRules ruleSet)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out int bytesRead);

            if (length == null)
            {
                return SeekEndOfContents(_data.Slice(bytesRead), ruleSet);
            }

            return Slice(_data, bytesRead, length.Value);
        }

        public void SkipValue(AsnEncodingRules ruleSet)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out int bytesRead);

            if (length == null)
            {
                ReadOnlySpan<byte> nestedContents = GetContentSpan(ruleSet);
                _data = _data.Slice(bytesRead + nestedContents.Length);
            }
            else
            {
                _data = _data.Slice(bytesRead + length.Value);
            }
        }

        public static bool ReadBooleanValue(
            ReadOnlySpan<byte> source,
            AsnEncodingRules ruleSet)
        {
            // T-REC-X.690-201508 sec 8.2.1
            if (source.Length != 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            byte val = source[0];

            // T-REC-X.690-201508 sec 8.2.2
            if (val == 0)
            {
                return false;
            }

            // T-REC-X.690-201508 sec 11.1
            if (val != 0xFF && (ruleSet == AsnEncodingRules.DER || ruleSet == AsnEncodingRules.CER))
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return true;
        }
        
        public bool ReadBoolean(AsnEncodingRules ruleSet)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out int headerLength);
            // TODO/Review: Should non-Universal tags work, or require an expected tag parameter?
            CheckTagIfUniversal(tag, UniversalTagNumber.Boolean);

            // T-REC-X.690-201508 sec 8.2.1
            if (tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            bool value = ReadBooleanValue(
                Slice(_data, headerLength, length.Value),
                ruleSet);

            _data = _data.Slice(headerLength + length.Value);
            return value;
        }

        private ReadOnlySpan<byte> GetIntegerContents(
            AsnEncodingRules ruleSet,
            UniversalTagNumber tagNumber,
            out int headerLength)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out headerLength);
            CheckTagIfUniversal(tag, tagNumber);

            // T-REC-X.690-201508 sec 8.3.1
            if (tag.IsConstructed || length < 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // Slice first so that an out of bounds value triggers a CryptographicException.
            ReadOnlySpan<byte> contents = Slice(_data, headerLength, length.Value);

            // T-REC-X.690-201508 sec 8.3.2
            if (contents.Length > 1)
            {
                ushort bigEndianValue = (ushort)(contents[0] << 8 | contents[1]);
                const ushort RedundancyMask = 0b1111_1111_1000_0000;
                ushort masked = (ushort)(bigEndianValue & RedundancyMask);

                // If the first 9 bits are all 0 or are all 1, the value is invalid.
                if (masked == 0 || masked == RedundancyMask)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            return contents;
        }

        public ReadOnlySpan<byte> GetIntegerBytes(AsnEncodingRules ruleSet)
        {
            ReadOnlySpan<byte> contents =
                GetIntegerContents(ruleSet, UniversalTagNumber.Integer, out int headerLength);

            _data = _data.Slice(headerLength + contents.Length);
            return contents;
        }

        private bool TryReadSignedInteger(
            AsnEncodingRules ruleSet,
            int sizeLimit,
            UniversalTagNumber tagNumber,
            out long value)
        {
            Debug.Assert(sizeLimit <= sizeof(long));

            ReadOnlySpan<byte> contents = GetIntegerContents(ruleSet, tagNumber, out int headerLength);

            if (contents.Length > sizeLimit)
            {
                value = 0;
                return false;
            }

            bool isNegative = contents[0] >= 0x80;
            long accum = isNegative ? -1 : 0;

            for (int i = 0; i < contents.Length; i++)
            {
                accum <<= 8;
                accum |= contents[i];
            }

            _data = _data.Slice(headerLength + contents.Length);
            value = accum;
            return true;
        }

        private bool TryReadUnsignedInteger(
            AsnEncodingRules ruleSet,
            int sizeLimit,
            UniversalTagNumber tagNumber,
            out ulong value)
        {
            Debug.Assert(sizeLimit <= sizeof(ulong));

            ReadOnlySpan<byte> contents = GetIntegerContents(ruleSet, tagNumber, out int headerLength);
            int contentLength = contents.Length;

            bool isNegative = contents[0] >= 0x80;

            if (isNegative)
            {
                // TODO/Review: Should this be "false", an Exception, or not a scenario?
                value = 0;
                return false;
            }

            // Remove any padding zeros.
            if (contents.Length > 1 && contents[0] == 0)
            {
                contents = contents.Slice(1);
            }

            if (contents.Length > sizeLimit)
            {
                value = 0;
                return false;
            }

            ulong accum = 0;

            for (int i = 0; i < contents.Length; i++)
            {
                accum <<= 8;
                accum |= contents[i];
            }

            _data = _data.Slice(headerLength + contentLength);
            value = accum;
            return true;
        }

        public bool TryReadInt32(AsnEncodingRules ruleSet, out int value)
        {
            if (TryReadSignedInteger(ruleSet, sizeof(int), UniversalTagNumber.Integer, out long longValue))
            {
                value = (int)longValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadUInt32(AsnEncodingRules ruleSet, out uint value)
        {
            if (TryReadUnsignedInteger(ruleSet, sizeof(uint), UniversalTagNumber.Integer, out ulong ulongValue))
            {
                value = (uint)ulongValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadInt64(AsnEncodingRules ruleSet, out long value)
        {
            return TryReadSignedInteger(ruleSet, sizeof(long), UniversalTagNumber.Integer, out value);
        }

        public bool TryReadUInt64(AsnEncodingRules ruleSet, out ulong value)
        {
            return TryReadUnsignedInteger(ruleSet, sizeof(ulong), UniversalTagNumber.Integer, out value);
        }

        private static bool TryCopyPrimitiveBitStringValue(
            ReadOnlySpan<byte> source,
            Span<byte> destination,
            bool write,
            bool requireBerMaskMatch,
            AsnEncodingRules ruleSet,
            out int unusedBitCount,
            out int bytesWritten)
        {
            // T-REC-X.690-201508 sec 9.2
            if (ruleSet == AsnEncodingRules.CER && source.Length > MaxCERSegmentSize)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (write && destination.Length < source.Length - 1)
            {
                unusedBitCount = bytesWritten = 0;
                return false;
            }

            // T-REC-X.690-201508 sec 8.6.2.3
            if (source.Length < 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            unusedBitCount = source[0];

            // T-REC-X.690-201508 sec 8.6.2.2
            if (unusedBitCount > 7)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (source.Length == 1)
            {
                // T-REC-X.690-201508 sec 8.6.2.4
                if (unusedBitCount > 0)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                unusedBitCount = 0;
                bytesWritten = 0;
                return true;
            }

            // If 3 bits are "unused" then build a mask for the top 5 bits.
            // 0b1111_1111 >> (8 - 3)
            // 0b1111_1111 >> 5
            // 0b0000_0111
            // (then invert that)
            // 0b1111_1000
            byte mask = (byte)~(0xFF >> (8 - unusedBitCount));
            byte lastByte = source[source.Length - 1];
            byte maskedByte = (byte)(lastByte & mask);

            if (maskedByte == lastByte)
            {
                if (write)
                {
                    source.Slice(1).CopyTo(destination);
                }

                bytesWritten = source.Length - 1;
                return true;
            }

            // T-REC-X.690-201508 sec 11.2.1
            if (ruleSet == AsnEncodingRules.DER || ruleSet == AsnEncodingRules.CER)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (requireBerMaskMatch)
            {
                bytesWritten = 0;
                unusedBitCount = 0;
                return false;
            }

            if (write)
            {
                source.Slice(1, source.Length - 2).CopyTo(destination);
                destination[source.Length - 2] = maskedByte;
            }

            bytesWritten = source.Length - 1;
            return true;
        }

        private static int CopyConstructedBitString(
            ReadOnlySpan<byte> source,
            ref Span<byte> destination,
            bool write,
            AsnEncodingRules ruleSet,
            bool isIndefinite,
            ref int lastUnusedBitCount,
            ref int lastSegmentLength,
            out int bytesRead)
        {
            if (source.IsEmpty)
            {
                if (isIndefinite)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                bytesRead = 0;
                return 0;
            }

            int totalRead = 0;
            int totalContent = 0;
            ReadOnlySpan<byte> cur = source;

            while (!cur.IsEmpty)
            {
                AsnReader reader = new AsnReader(cur);
                (Asn1Tag tag, int? length) = reader.ReadTagAndLength(ruleSet, out int headerLength);

                if (tag.TagClass != TagClass.Universal)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                totalRead += headerLength;

                if (isIndefinite && tag.TagValue == (int)UniversalTagNumber.EndOfContents)
                {
                    ValidateEndOfContents(tag, length, headerLength);

                    bytesRead = totalRead;
                    return totalContent;
                }

                if (tag.TagValue != (int)UniversalTagNumber.BitString)
                {
                    // T-REC-X.690-201508 sec 8.6.4.1 (in particular, Note 2)
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                if (ruleSet == AsnEncodingRules.CER)
                {
                    if (tag.IsConstructed || lastSegmentLength != MaxCERSegmentSize)
                    {
                        // T-REC-X.690-201508 sec 9.2
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }

                cur = cur.Slice(headerLength);

                if (length == null)
                {
                    totalContent += CopyConstructedBitString(
                        cur,
                        ref destination,
                        write,
                        ruleSet,
                        true,
                        ref lastUnusedBitCount,
                        ref lastSegmentLength,
                        out int nestedBytesRead);

                    totalRead += nestedBytesRead;
                    cur = cur.Slice(nestedBytesRead);
                }
                else if (tag.IsConstructed)
                {
                    totalContent += CopyConstructedBitString(
                        Slice(cur, 0, length.Value),
                        ref destination,
                        write,
                        ruleSet,
                        false,
                        ref lastUnusedBitCount,
                        ref lastSegmentLength,
                        out int nestedContentRead);

                    totalRead += nestedContentRead;
                    cur = cur.Slice(nestedContentRead);
                }
                else
                {
                    if (lastUnusedBitCount != 0)
                    {
                        // T-REC-X.690-201508 sec 8.6.4 (only the last segment can have unused bits)
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    int lengthValue = length.Value;

                    TryCopyPrimitiveBitStringValue(
                        Slice(cur, 0, lengthValue),
                        destination,
                        write,
                        false,
                        ruleSet,
                        out lastUnusedBitCount,
                        out int pretendWritten);

                    totalRead += lengthValue;
                    totalContent += pretendWritten;
                    lastSegmentLength = lengthValue;
                    cur = cur.Slice(lengthValue);

                    if (write)
                    {
                        destination = destination.Slice(pretendWritten);
                    }
                }
            }

            if (isIndefinite)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            bytesRead = totalRead;
            return totalContent;
        }

        private static bool TryCopyConstructedBitStringValue(
            ReadOnlySpan<byte> source,
            Span<byte> dest,
            AsnEncodingRules ruleSet,
            bool isIndefinite,
            out int unusedBitCount,
            out int bytesRead,
            out int bytesWritten)
        {
            int lastUnusedBitCount = 0;
            int lastSegmentSize = MaxCERSegmentSize;

            Span<byte> tmpDest = dest;

            int contentLength = CopyConstructedBitString(
                source,
                ref tmpDest,
                false,
                ruleSet,
                isIndefinite,
                ref lastUnusedBitCount,
                ref lastSegmentSize,
                out int encodedLength);

            // Since the unused bits byte from the segments don't count, only one segment
            // returns 999 (or less), the second segment bumps the count to 1000, and is legal.
            //
            // T-REC-X.690-201508 sec 9.2
            if (ruleSet == AsnEncodingRules.CER && contentLength < MaxCERSegmentSize)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (dest.Length < contentLength)
            {
                unusedBitCount = 0;
                bytesRead = 0;
                bytesWritten = 0;
                return false;
            }

            tmpDest = dest;
            unusedBitCount = lastUnusedBitCount;
            lastSegmentSize = MaxCERSegmentSize;
            lastUnusedBitCount = 0;

            bytesWritten = CopyConstructedBitString(
                source,
                ref tmpDest,
                true,
                ruleSet,
                isIndefinite,
                ref lastUnusedBitCount,
                ref lastSegmentSize,
                out bytesRead);

            Debug.Assert(unusedBitCount == lastUnusedBitCount);
            Debug.Assert(bytesWritten == contentLength);
            Debug.Assert(bytesRead == encodedLength);
            return true;
        }

        private bool TryGetBitStringBytes(
            AsnEncodingRules ruleSet,
            out int unusedBitCount,
            out ReadOnlySpan<byte> contents,
            out int headerLength)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.BitString);

            if (tag.IsConstructed)
            {
                if (ruleSet == AsnEncodingRules.DER)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                contents = default(ReadOnlySpan<byte>);
                unusedBitCount = 0;
                return false;
            }

            Debug.Assert(length.HasValue);
            ReadOnlySpan<byte> encodedValue = Slice(_data, headerLength, length.Value);

            if (TryCopyPrimitiveBitStringValue(
                encodedValue,
                Span<byte>.Empty,
                false,
                true,
                ruleSet,
                out unusedBitCount,
                out int bytesWritten))
            {
                contents = encodedValue.Slice(1);
                return true;
            }

            contents = default(ReadOnlySpan<byte>);
            return false;
        }

        /// <summary>
        /// Gets the source data for a BitString under a primitive encoding.
        /// </summary>
        /// <param name="ruleSet">The encoding rules for the reader.</param>
        /// <param name="unusedBitCount">The encoded value for the number of unused bits.</param>
        /// <param name="contents">The content bytes for the BitString payload.</param>
        /// <returns>
        ///   <c>true</c> if the bit string uses a primitive encoding and the "unused" bits have value 0,
        ///   <c>false</c> otherwise.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///  <ul>
        ///   <li>No data remains</li>
        ///   <li>The tag is invalid for a BitString value</li>
        ///   <li>The length is invalid under the chosen encoding rules</li>
        ///   <li>The unusedBitCount value is out of bounds</li>
        ///   <li>A CER or DER encoding was chosen and an "unused" bit was set to 1</li>
        ///   <li>A CER encoding was chosen and the primitive content length exceeds the maximum allowed</li>
        /// </ul>
        /// </exception>
        public bool TryGetBitStringBytes(
            AsnEncodingRules ruleSet,
            out int unusedBitCount,
            out ReadOnlySpan<byte> contents)
        {
            bool didGet = TryGetBitStringBytes(ruleSet, out unusedBitCount, out contents, out int headerLength);

            if (didGet)
            {
                // Skip the tag+length (header) and the unused bit count byte (1) and the contents.
                _data = _data.Slice(headerLength + contents.Length + 1);
            }

            return didGet;
        }

        public bool TryCopyBitStringBytes(
            AsnEncodingRules ruleSet,
            Span<byte> destination,
            out int unusedBitCount,
            out int bytesWritten)
        {
            if (TryGetBitStringBytes(
                ruleSet,
                out unusedBitCount,
                out ReadOnlySpan<byte> contents,
                out int headerLength))
            {
                if (contents.Length > destination.Length)
                {
                    bytesWritten = 0;
                    unusedBitCount = 0;
                    return false;
                }

                contents.CopyTo(destination);
                bytesWritten = contents.Length;
                // contents doesn't include the unusedBitCount value, so add one byte for that.
                _data.Slice(headerLength + contents.Length + 1);
                return true;
            }

            // Either constructed, or a BER payload with "unused" bits not set to 0.
            (Asn1Tag tag, int? length) = ReadTagAndLength(ruleSet, out headerLength);

            if (!tag.IsConstructed)
            {
                Debug.Assert(ruleSet == AsnEncodingRules.BER);

                return TryCopyPrimitiveBitStringValue(
                    Slice(_data, headerLength, length),
                    destination,
                    true,
                    false,
                    ruleSet,
                    out unusedBitCount,
                    out bytesWritten);
            }

            bool read = TryCopyConstructedBitStringValue(
                Slice(_data, headerLength, length),
                destination,
                ruleSet,
                length == null,
                out unusedBitCount,
                out int bytesRead,
                out bytesWritten);

            if (read)
            {
                _data = _data.Slice(headerLength + bytesRead);
            }

            return read;
        }

        public ReadOnlySpan<byte> GetEnumeratedBytes(AsnEncodingRules ruleSet)
        {
            // T-REC-X.690-201508 sec 8.4 says the contents are the same as for integers.
            ReadOnlySpan<byte> contents =
                GetIntegerContents(ruleSet, UniversalTagNumber.Enumerated, out int headerLength);

            _data = _data.Slice(headerLength + contents.Length);
            return contents;
        }

        public TEnum GetEnumeratedValue<TEnum>(AsnEncodingRules ruleSet) where TEnum : struct
        {
            Type tEnum = typeof(TEnum);
            const UniversalTagNumber tagNumber = UniversalTagNumber.Enumerated;
            
            // This will throw an ArgumentException if TEnum isn't an enum type,
            // so we don't need to validate it.
            Type backingType = tEnum.GetEnumUnderlyingType();

            // TODO/review: Is this worth checking?
            if (tEnum.IsDefined(typeof(FlagsAttribute), false))
            {
                // TODO/review: What kind of exception? (This message is no good)
                throw new ArgumentException();
            }

            // T-REC-X.690-201508 sec 8.4 says the contents are the same as for integers.
            int sizeLimit = Marshal.SizeOf(backingType);

            if (backingType == typeof(int) ||
                backingType == typeof(long) ||
                backingType == typeof(short) ||
                backingType == typeof(sbyte))
            {
                if (!TryReadSignedInteger(ruleSet, sizeLimit, tagNumber, out long value))
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return (TEnum)Enum.ToObject(tEnum, value);
            }

            if (backingType == typeof(uint) ||
                backingType == typeof(ulong) ||
                backingType == typeof(ushort) ||
                backingType == typeof(byte))
            {
                if (!TryReadUnsignedInteger(ruleSet, sizeLimit, tagNumber, out ulong value))
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return (TEnum)Enum.ToObject(tEnum, value);
            }

            Debug.Fail($"No handler for type {backingType.Name}");
            throw new CryptographicException();
        }

        private static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> source, int offset, int length)
        {
            Debug.Assert(offset >= 0);
            Debug.Assert(length >= 0);

            if (source.Length - offset < length)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return source.Slice(offset, length);
        }

        private static ReadOnlySpan<byte> Slice(ReadOnlySpan<byte> source, int offset, int? length)
        {
            Debug.Assert(offset >= 0);

            if (length == null)
            {
                return source.Slice(offset);
            }

            return Slice(source, offset, length.Value);
        }

        private static void CheckEncodingRules(AsnEncodingRules ruleSet)
        {
            if (ruleSet != AsnEncodingRules.BER &&
                ruleSet != AsnEncodingRules.CER &&
                ruleSet != AsnEncodingRules.DER)
            {
                throw new ArgumentOutOfRangeException(nameof(ruleSet));
            }
        }

        private static void CheckTagIfUniversal(Asn1Tag tag, UniversalTagNumber tagNumber)
        {
            if (tag.TagClass == TagClass.Universal && tag.TagValue != (int)tagNumber)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
        }
    }
}
