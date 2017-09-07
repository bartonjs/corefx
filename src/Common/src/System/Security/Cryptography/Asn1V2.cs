// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Data.Common;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;

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
        internal static readonly Asn1Tag Null = new Asn1Tag(5);

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

        public Asn1Tag(UniversalTagNumber universalTagNumber, bool isConstructed = false)
            : this(isConstructed ? ConstructedMask : (byte)0, (int)universalTagNumber)
        {
            if (!Enum.IsDefined(typeof(UniversalTagNumber), universalTagNumber))
            {
                throw new ArgumentOutOfRangeException(nameof(universalTagNumber), universalTagNumber, null);
            }
        }

        public Asn1Tag(TagClass tagClass, int tagValue, bool isConstructed = false)
            : this((byte)((byte)tagClass | (isConstructed ? ConstructedMask : 0)), tagValue)
        {
            if (!Enum.IsDefined(typeof(TagClass), tagClass))
            {
                throw new ArgumentOutOfRangeException(nameof(tagClass), tagClass, null);
            }

            if (tagClass == TagClass.Universal)
            {
                UniversalTagNumber universalTagNumber = (UniversalTagNumber)tagValue;

                if (!Enum.IsDefined(typeof(UniversalTagNumber), universalTagNumber))
                {
                    // TODO: Message this one.
                    throw new ArgumentOutOfRangeException(nameof(tagValue), tagValue, null);
                }
            }
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

        // T-REC-X.690-201508 sec 8.1.5 says only 0000 is legal.
        private const int EndOfContentsEncodedLength = 2;

        private static readonly Text.Encoding s_utf8Encoding = new UTF8Encoding(false, true);
        private static readonly Text.Encoding s_bmpEncoding = new BMPEncoding();
        private static readonly Text.Encoding s_ia5Encoding = new IA5Encoding();

        private ReadOnlySpan<byte> _data;
        private readonly AsnEncodingRules _ruleSet;

        public bool HasData => !_data.IsEmpty;

        public AsnReader(ReadOnlySpan<byte> data, AsnEncodingRules ruleSet)
        {
            CheckEncodingRules(ruleSet);

            _data = data;
            _ruleSet = ruleSet;
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

        internal (Asn1Tag, int?) ReadTagAndLength(out int bytesRead)
        {
            if (TryPeekTag(_data, out Asn1Tag tag, out int tagBytesRead) &&
                TryReadLength(_data.Slice(tagBytesRead), _ruleSet, out int? length, out int lengthBytesRead))
            {
                int allBytesRead = tagBytesRead + lengthBytesRead;

                if (tag.IsConstructed)
                {
                    // T-REC-X.690-201508 sec 9.1 (CER: Length forms) says constructed is always indefinite.
                    if (_ruleSet == AsnEncodingRules.CER && length != null)
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
            if (tag.IsConstructed || length != 0 || headerLength != EndOfContentsEncodedLength)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
        }

        private static ReadOnlySpan<byte> SeekEndOfContents(
            ReadOnlySpan<byte> source,
            AsnEncodingRules ruleSet,
            int initialSliceOffset = 0)
        {
            ReadOnlySpan<byte> cur = source.Slice(initialSliceOffset);
            int totalLen = 0;

            while (!cur.IsEmpty)
            {
                AsnReader reader = new AsnReader(cur, ruleSet);
                (Asn1Tag tag, int? length) = reader.ReadTagAndLength(out int bytesRead);
                ReadOnlySpan<byte> nestedContents = reader.PeekContentSpan();

                int localLen = bytesRead + nestedContents.Length;

                if (tag == Asn1Tag.EndOfContents)
                {
                    ValidateEndOfContents(tag, length, bytesRead);

                    return source.Slice(0, totalLen);
                }

                // If the current value was an indefinite-length-encoded value
                // then we need to skip over the EOC as well.  But we didn't want to
                // include it as part of the content span.
                //
                // T-REC-X.690-201508 sec 8.1.1.1 / 8.1.1.3 indicate that the
                // End -of-Contents octets are "after" the contents octets, not
                // "at the end" of them.
                if (length == null)
                {
                    localLen += EndOfContentsEncodedLength;
                }

                totalLen += localLen;
                cur = cur.Slice(localLen);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        public ReadOnlySpan<byte> PeekEncodedValue()
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int bytesRead);

            if (length == null)
            {
                return SeekEndOfContents(_data, _ruleSet, bytesRead);
            }

            return Slice(_data, 0, bytesRead + length.Value);
        }

        public ReadOnlySpan<byte> PeekContentSpan()
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int bytesRead);

            if (length == null)
            {
                return SeekEndOfContents(_data.Slice(bytesRead), _ruleSet);
            }

            return Slice(_data, bytesRead, length.Value);
        }

        public void SkipValue()
        {
            GetEncodedValue();
        }

        public ReadOnlySpan<byte> GetEncodedValue()
        {
            ReadOnlySpan<byte> encodedValue = PeekEncodedValue();
            _data = _data.Slice(encodedValue.Length);
            return encodedValue;
        }

        private static bool ReadBooleanValue(
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
        
        public bool ReadBoolean()
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int headerLength);
            // TODO/Review: Should non-Universal tags work, or require an expected tag parameter?
            CheckTagIfUniversal(tag, UniversalTagNumber.Boolean);

            // T-REC-X.690-201508 sec 8.2.1
            if (tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            bool value = ReadBooleanValue(
                Slice(_data, headerLength, length.Value),
                _ruleSet);

            _data = _data.Slice(headerLength + length.Value);
            return value;
        }

        private ReadOnlySpan<byte> GetIntegerContents(
            UniversalTagNumber tagNumber,
            out int headerLength)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);
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

        public ReadOnlySpan<byte> GetIntegerBytes()
        {
            ReadOnlySpan<byte> contents =
                GetIntegerContents(UniversalTagNumber.Integer, out int headerLength);

            _data = _data.Slice(headerLength + contents.Length);
            return contents;
        }

        private bool TryReadSignedInteger(
            int sizeLimit,
            UniversalTagNumber tagNumber,
            out long value)
        {
            Debug.Assert(sizeLimit <= sizeof(long));

            ReadOnlySpan<byte> contents = GetIntegerContents(tagNumber, out int headerLength);

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
            int sizeLimit,
            UniversalTagNumber tagNumber,
            out ulong value)
        {
            Debug.Assert(sizeLimit <= sizeof(ulong));

            ReadOnlySpan<byte> contents = GetIntegerContents(tagNumber, out int headerLength);
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

        public bool TryReadInt32(out int value)
        {
            if (TryReadSignedInteger(sizeof(int), UniversalTagNumber.Integer, out long longValue))
            {
                value = (int)longValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadUInt32(out uint value)
        {
            if (TryReadUnsignedInteger(sizeof(uint), UniversalTagNumber.Integer, out ulong ulongValue))
            {
                value = (uint)ulongValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadInt64(out long value)
        {
            return TryReadSignedInteger(sizeof(long), UniversalTagNumber.Integer, out value);
        }

        public bool TryReadUInt64(out ulong value)
        {
            return TryReadUnsignedInteger(sizeof(ulong), UniversalTagNumber.Integer, out value);
        }

        public bool TryReadInt16(out short value)
        {
            if (TryReadSignedInteger(sizeof(short), UniversalTagNumber.Integer, out long longValue))
            {
                value = (short)longValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadUInt16(out ushort value)
        {
            if (TryReadUnsignedInteger(sizeof(ushort), UniversalTagNumber.Integer, out ulong ulongValue))
            {
                value = (ushort)ulongValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadInt8(out sbyte value)
        {
            if (TryReadSignedInteger(sizeof(sbyte), UniversalTagNumber.Integer, out long longValue))
            {
                value = (sbyte)longValue;
                return true;
            }

            value = 0;
            return false;
        }

        public bool TryReadUInt8(out byte value)
        {
            if (TryReadUnsignedInteger(sizeof(byte), UniversalTagNumber.Integer, out ulong ulongValue))
            {
                value = (byte)ulongValue;
                return true;
            }

            value = 0;
            return false;
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
                AsnReader reader = new AsnReader(cur, ruleSet);
                (Asn1Tag tag, int? length) = reader.ReadTagAndLength(out int headerLength);

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
            out int unusedBitCount,
            out ReadOnlySpan<byte> contents,
            out int headerLength)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.BitString);

            if (tag.IsConstructed)
            {
                if (_ruleSet == AsnEncodingRules.DER)
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
                _ruleSet,
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
            out int unusedBitCount,
            out ReadOnlySpan<byte> contents)
        {
            bool didGet = TryGetBitStringBytes(out unusedBitCount, out contents, out int headerLength);

            if (didGet)
            {
                // Skip the tag+length (header) and the unused bit count byte (1) and the contents.
                _data = _data.Slice(headerLength + contents.Length + 1);
            }

            return didGet;
        }

        public bool TryCopyBitStringBytes(
            Span<byte> destination,
            out int unusedBitCount,
            out int bytesWritten)
        {
            if (TryGetBitStringBytes(
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
            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);

            if (!tag.IsConstructed)
            {
                Debug.Assert(_ruleSet == AsnEncodingRules.BER);

                return TryCopyPrimitiveBitStringValue(
                    Slice(_data, headerLength, length),
                    destination,
                    true,
                    false,
                    _ruleSet,
                    out unusedBitCount,
                    out bytesWritten);
            }

            bool read = TryCopyConstructedBitStringValue(
                Slice(_data, headerLength, length),
                destination,
                _ruleSet,
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

        public ReadOnlySpan<byte> GetEnumeratedBytes()
        {
            // T-REC-X.690-201508 sec 8.4 says the contents are the same as for integers.
            ReadOnlySpan<byte> contents =
                GetIntegerContents(UniversalTagNumber.Enumerated, out int headerLength);

            _data = _data.Slice(headerLength + contents.Length);
            return contents;
        }

        public TEnum GetEnumeratedValue<TEnum>() where TEnum : struct
        {
            Type tEnum = typeof(TEnum);

            return (TEnum)Enum.ToObject(tEnum, GetEnumeratedValue(tEnum));
        }

        public Enum GetEnumeratedValue(Type tEnum)
        {
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
                if (!TryReadSignedInteger(sizeLimit, tagNumber, out long value))
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return (Enum)Enum.ToObject(tEnum, value);
            }

            if (backingType == typeof(uint) ||
                backingType == typeof(ulong) ||
                backingType == typeof(ushort) ||
                backingType == typeof(byte))
            {
                if (!TryReadUnsignedInteger(sizeLimit, tagNumber, out ulong value))
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                return (Enum)Enum.ToObject(tEnum, value);
            }

            Debug.Fail($"No handler for type {backingType.Name}");
            throw new CryptographicException();
        }

        private bool TryGetOctetStringBytes(
            out ReadOnlySpan<byte> contents,
            out int headerLength,
            UniversalTagNumber universalTagNumber = UniversalTagNumber.OctetString)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);
            CheckTagIfUniversal(tag, universalTagNumber);

            if (tag.IsConstructed)
            {
                if (_ruleSet == AsnEncodingRules.DER)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                contents = default(ReadOnlySpan<byte>);
                return false;
            }

            Debug.Assert(length.HasValue);
            ReadOnlySpan<byte> encodedValue = Slice(_data, headerLength, length.Value);

            if (_ruleSet == AsnEncodingRules.CER && encodedValue.Length > MaxCERSegmentSize)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            contents = encodedValue;
            return true;
        }

        private bool TryGetOctetStringBytes(
            UniversalTagNumber universalTagNumber,
            out ReadOnlySpan<byte> contents)
        {
            if (TryGetOctetStringBytes(out contents, out int headerLength, universalTagNumber))
            {
                _data = _data.Slice(headerLength + contents.Length);
                return true;
            }

            return false;
        }

        /// <summary>
        /// Gets the source data for an OctetString under a primitive encoding.
        /// </summary>
        /// <param name="contents">The content bytes for the OctetString payload.</param>
        /// <returns>
        ///   <c>true</c> if the octet string uses a primitive encoding, <c>false</c> otherwise.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///  <ul>
        ///   <li>No data remains</li>
        ///   <li>The tag is invalid for an OctetString value</li>
        ///   <li>The length is invalid under the chosen encoding rules</li>
        ///   <li>A CER encoding was chosen and the primitive content length exceeds the maximum allowed</li>
        /// </ul>
        /// </exception>
        public bool TryGetOctetStringBytes(out ReadOnlySpan<byte> contents)
        {
            return TryGetOctetStringBytes(UniversalTagNumber.OctetString, out contents);
        }

        private static int CopyConstructedOctetString(
            ReadOnlySpan<byte> source,
            ref Span<byte> destination,
            bool write,
            AsnEncodingRules ruleSet,
            bool isIndefinite,
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
                AsnReader reader = new AsnReader(cur, ruleSet);
                (Asn1Tag tag, int? length) = reader.ReadTagAndLength(out int headerLength);
                
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

                if (tag.TagValue != (int)UniversalTagNumber.OctetString)
                {
                    // T-REC-X.690-201508 sec 8.7.3.2 (in particular, Note 2)
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
                    totalContent += CopyConstructedOctetString(
                        cur,
                        ref destination,
                        write,
                        ruleSet,
                        true,
                        ref lastSegmentLength,
                        out int nestedBytesRead);

                    totalRead += nestedBytesRead;
                    cur = cur.Slice(nestedBytesRead);
                }
                else if (tag.IsConstructed)
                {
                    totalContent += CopyConstructedOctetString(
                        Slice(cur, 0, length.Value),
                        ref destination,
                        write,
                        ruleSet,
                        false,
                        ref lastSegmentLength,
                        out int nestedContentRead);

                    totalRead += nestedContentRead;
                    cur = cur.Slice(nestedContentRead);
                }
                else
                {
                    int lengthValue = length.Value;

                    // T-REC-X.690-201508 sec 9.2
                    if (ruleSet == AsnEncodingRules.CER && lengthValue > MaxCERSegmentSize)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    totalRead += lengthValue;
                    totalContent += lengthValue;
                    lastSegmentLength = lengthValue;

                    ReadOnlySpan<byte> segment = Slice(cur, 0, lengthValue);
                    cur = cur.Slice(lengthValue);

                    if (write)
                    {
                        segment.CopyTo(destination);
                        destination = destination.Slice(lengthValue);
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

        private static bool TryCopyConstructedOctetStringValue(
            ReadOnlySpan<byte> source,
            Span<byte> dest,
            bool write,
            AsnEncodingRules ruleSet,
            bool isIndefinite,
            out int bytesRead,
            out int bytesWritten)
        {
            int lastSegmentSize = MaxCERSegmentSize;

            Span<byte> tmpDest = dest;

            int contentLength = CopyConstructedOctetString(
                source,
                ref tmpDest,
                false,
                ruleSet,
                isIndefinite,
                ref lastSegmentSize,
                out int encodedLength);

            // ITU-T-REC-X.690-201508 sec 9.2
            if (ruleSet == AsnEncodingRules.CER && contentLength <= MaxCERSegmentSize)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (!write)
            {
                bytesRead = encodedLength;
                bytesWritten = contentLength;
                return true;
            }

            if (dest.Length < contentLength)
            {
                bytesRead = 0;
                bytesWritten = 0;
                return false;
            }

            tmpDest = dest;
            lastSegmentSize = MaxCERSegmentSize;

            bytesWritten = CopyConstructedOctetString(
                source,
                ref tmpDest,
                true,
                ruleSet,
                isIndefinite,
                ref lastSegmentSize,
                out bytesRead);

            Debug.Assert(bytesWritten == contentLength);
            Debug.Assert(bytesRead == encodedLength);
            return true;
        }

        public bool TryCopyOctetStringBytes(
            Span<byte> destination,
            out int bytesWritten)
        {
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> contents,
                out int headerLength))
            {
                if (contents.Length > destination.Length)
                {
                    bytesWritten = 0;
                    return false;
                }

                contents.CopyTo(destination);
                bytesWritten = contents.Length;
                _data.Slice(headerLength + contents.Length);
                return true;
            }

            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);

            bool copied = TryCopyConstructedOctetStringValue(
                Slice(_data, headerLength, length),
                destination,
                true,
                _ruleSet,
                length == null,
                out int bytesRead,
                out bytesWritten);

            if (copied)
            {
                _data = _data.Slice(headerLength + bytesRead);
            }

            return copied;
        }

        public void ReadNull()
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.Null);

            // T-REC-X.690-201508 sec 8.8.1
            // T-REC-X.690-201508 sec 8.8.2
            if (tag.IsConstructed || length != 0)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            _data = _data.Slice(headerLength);
        }
        
        private static BigInteger ReadSubIdentifier(
            ReadOnlySpan<byte> source,
            out int bytesRead)
        {
            Debug.Assert(source.Length > 0);

            // T-REC-X.690-201508 sec 8.19.2 (last sentence)
            if (source[0] == 0x80)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            BigInteger accum = BigInteger.Zero;

            for (int idx = 0; idx < source.Length; idx++)
            {
                byte cur = source[idx];

                accum <<= 7;
                accum |= (cur & 0x7F);

                // If the high bit isn't set this marks the end of the sub-identifier.
                if (cur < 0x80)
                {
                    bytesRead = idx + 1;
                    return accum;
                }
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private string ReadObjectIdentifierAsString(out int totalBytesRead)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.ObjectIdentifier);

            // T-REC-X.690-201508 sec 8.19.1
            // T-REC-X.690-201508 sec 8.19.2 says the minimum length is 1
            if (tag.IsConstructed || length < 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ReadOnlySpan<byte> contents = Slice(_data, headerLength, length.Value);
            BigInteger firstIdentifier = ReadSubIdentifier(contents, out int bytesRead);
            byte firstArc;

            // T-REC-X.690-201508 sec 8.19.4
            // The first two subidentifiers (X.Y) are encoded as (X * 40) + Y, because Y is
            // bounded [0, 39] for X in {0, 1}, and only X in {0, 1, 2} are legal.
            // So:
            // * identifier < 40 => X = 0, Y = identifier.
            // * identifier < 80 => X = 1, Y = identifier - 40.
            // * else: X = 2, Y = identifier - 80.

            if (firstIdentifier < 40)
            {
                firstArc = 0;
            }
            else if (firstIdentifier < 80)
            {
                firstArc = 1;
                firstIdentifier -= 40;
            }
            else
            {
                firstArc = 2;
                firstIdentifier -= 80;
            }

            StringBuilder builder = new StringBuilder(contents.Length * 4);
            builder.Append(firstArc);
            builder.Append('.');
            builder.Append(firstIdentifier.ToString());

            contents = contents.Slice(bytesRead);

            while (!contents.IsEmpty)
            {
                BigInteger subIdentifier = ReadSubIdentifier(contents, out bytesRead);
                builder.Append('.');
                builder.Append(subIdentifier.ToString());

                contents = contents.Slice(bytesRead);
            }

            totalBytesRead = headerLength + length.Value;
            return builder.ToString();
        }

        public string ReadObjectIdentifierAsString()
        {
            string oidValue = ReadObjectIdentifierAsString(out int bytesRead);

            _data = _data.Slice(bytesRead);

            return oidValue;
        }

        public Oid ReadObjectIdentifier(bool skipFriendlyName=false)
        {
            string oidValue = ReadObjectIdentifierAsString(out int bytesRead);
            Oid oid = skipFriendlyName ? new Oid(oidValue, oidValue) : new Oid(oidValue);

            _data = _data.Slice(bytesRead);

            return oid;
        }

        private bool TryCopyCharacterStringBytes(
            UniversalTagNumber universalTagNumber,
            Span<byte> destination,
            bool write,
            out int bytesRead,
            out int bytesWritten)
        {
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> contents,
                out int headerLength,
                universalTagNumber))
            {
                bytesWritten = contents.Length;

                if (write)
                {
                    if (destination.Length < bytesWritten)
                    {
                        bytesWritten = 0;
                        bytesRead = 0;
                        return false;
                    }

                    contents.CopyTo(destination);
                }

                bytesRead = headerLength + bytesWritten;
                return true;
            }

            (Asn1Tag tag, int? length) = ReadTagAndLength(out headerLength);

            bool copied = TryCopyConstructedOctetStringValue(
                Slice(_data, headerLength, length),
                destination,
                write,
                _ruleSet,
                length == null,
                out int contentBytesRead,
                out bytesWritten);

            bytesRead = headerLength + contentBytesRead;
            return copied;
        }

        private static unsafe string GetCharacterString(
            ReadOnlySpan<byte> source,
            Text.Encoding encoding)
        {
            fixed (byte* bytePtr = &source.DangerousGetPinnableReference())
            {
                try
                {
                    return encoding.GetString(bytePtr, source.Length);
                }
                catch (DecoderFallbackException e)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
                }
            }
        }

        private static unsafe bool TryCopyCharacterString(
            ReadOnlySpan<byte> source,
            Text.Encoding encoding,
            Span<char> destination,
            out int charsWritten)
        {
            fixed (byte* bytePtr = &source.DangerousGetPinnableReference())
            fixed (char* charPtr = &destination.DangerousGetPinnableReference())
            {
                try
                {
                    int charCount = encoding.GetCharCount(bytePtr, source.Length);

                    if (charCount > destination.Length)
                    {
                        charsWritten = 0;
                        return false;
                    }

                    charsWritten = encoding.GetChars(bytePtr, source.Length, charPtr, destination.Length);
                    Debug.Assert(charCount == charsWritten);
                }
                catch (DecoderFallbackException e)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
                }

                return true;
            }
        }

        private string GetCharacterString(
            UniversalTagNumber universalTagNumber,
            Text.Encoding encoding)
        {
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> contents,
                out int headerLength,
                universalTagNumber))
            {
                string s = GetCharacterString(contents, encoding);

                _data = _data.Slice(headerLength + contents.Length);

                return s;
            }

            bool parsed = TryCopyCharacterStringBytes(
                universalTagNumber,
                Span<byte>.Empty,
                false,
                out int bytesRead,
                out int bytesWritten);

            Debug.Assert(parsed, "TryCopyCharacterStringBytes returned false in counting mode");

            byte[] rented = ArrayPool<byte>.Shared.Rent(bytesWritten);

            try
            {
                if (!TryCopyCharacterStringBytes(universalTagNumber, rented, true, out bytesRead, out bytesWritten))
                {
                    Debug.Fail("TryCopyCharacterStringBytes failed with a precomputed size");
                    throw new CryptographicException();
                }

                string s = GetCharacterString(
                    rented.AsReadOnlySpan().Slice(0, bytesWritten),
                    encoding);

                _data = _data.Slice(bytesRead);

                return s;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }

        private bool TryCopyCharacterString(
            UniversalTagNumber universalTagNumber,
            Text.Encoding encoding,
            Span<char> destination,
            out int charsWritten)
        {
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> contents,
                out int headerLength,
                universalTagNumber))
            {
                bool copied = TryCopyCharacterString(contents, encoding, destination, out charsWritten);

                if (copied)
                {
                    _data = _data.Slice(headerLength + contents.Length);
                }

                return copied;
            }

            bool parsed = TryCopyCharacterStringBytes(
                universalTagNumber,
                Span<byte>.Empty,
                false,
                out int bytesRead,
                out int bytesWritten);

            Debug.Assert(parsed, "TryCopyCharacterStringBytes returned false in counting mode");

            byte[] rented = ArrayPool<byte>.Shared.Rent(bytesWritten);

            try
            {
                if (!TryCopyCharacterStringBytes(universalTagNumber, rented, true, out bytesRead, out bytesWritten))
                {
                    Debug.Fail("TryCopyCharacterStringBytes failed with a precomputed size");
                    throw new CryptographicException();
                }

                bool copied = TryCopyCharacterString(
                    rented.AsReadOnlySpan().Slice(0, bytesWritten),
                    encoding,
                    destination,
                    out charsWritten);

                if (copied)
                {
                    _data = _data.Slice(bytesRead);
                }

                return copied;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rented, clearArray: true);
            }
        }

        /// <summary>
        /// Gets the source data for a UTF8String under a primitive encoding.
        /// </summary>
        /// <param name="contents">The content bytes for the UTF8String payload.</param>
        /// <returns>
        ///   <c>true</c> if the octet string uses a primitive encoding, <c>false</c> otherwise.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///  <ul>
        ///   <li>No data remains</li>
        ///   <li>The tag is invalid for a UTF8String value</li>
        ///   <li>The length is invalid under the chosen encoding rules</li>
        ///   <li>A CER encoding was chosen and the primitive content length exceeds the maximum allowed</li>
        /// </ul>
        /// </exception>
        public bool TryGetUTF8StringBytes(out ReadOnlySpan<byte> contents)
        {
            return TryGetOctetStringBytes(UniversalTagNumber.UTF8String, out contents);
        }

        public bool TryCopyUTF8StringBytes(Span<byte> destination, out int bytesWritten)
        {
            bool copied = TryCopyCharacterStringBytes(
                UniversalTagNumber.UTF8String,
                destination,
                true,
                out int bytesRead,
                out bytesWritten);

            if (copied)
            {
                _data = _data.Slice(bytesRead);
            }

            return copied;
        }

        public string GetCharacterString(UniversalTagNumber encodingType)
        {
            Text.Encoding encoding;

            switch (encodingType)
            {
                case UniversalTagNumber.UTF8String:
                    encoding = s_utf8Encoding;
                    break;
                case UniversalTagNumber.IA5String:
                    encoding = s_ia5Encoding;
                    break;
                case UniversalTagNumber.BMPString:
                    encoding = s_bmpEncoding;
                    break;
                default:
                    throw new ArgumentOutOfRangeException(nameof(encodingType), encodingType, null);
            }

            return GetCharacterString(encodingType, encoding);
        }

        public bool TryCopyUTF8String(Span<char> destination, out int charsWritten)
        {
            return TryCopyCharacterString(
                UniversalTagNumber.UTF8String,
                s_utf8Encoding,
                destination,
                out charsWritten);
        }

        public AsnReader ReadSequence()
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.Sequence);

            // T-REC-X.690-201508 sec 8.9.1
            // T-REC-X.690-201508 sec 8.10.1
            if (!tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ReadOnlySpan<byte> contents;
            int suffix = 0;

            if (length != null)
            {
                contents = Slice(_data, headerLength, length.Value);
            }
            else
            {
                contents = SeekEndOfContents(_data.Slice(headerLength), _ruleSet, 0);
                suffix = EndOfContentsEncodedLength;
            }

            _data = _data.Slice(headerLength + contents.Length + suffix);
            return new AsnReader(contents, _ruleSet);
        }

        /// <summary>
        /// Builds a new AsnReader over the bytes bounded by the current position which
        /// corresponds to an ASN.1 SET OF value, validating the CER or DER sort ordering
        /// unless suppressed.
        /// </summary>
        /// <param name="skipSortOrderValidation">
        ///   <c>false</c> to validate the sort ordering of the contents, <c>true</c> to
        ///   allow reading the data without verifying it was properly sorted by the writer.
        /// </param>
        /// <returns>An AsnReader over the current position, bounded by the contained length value.</returns>
        public AsnReader ReadSetOf(bool skipSortOrderValidation = false)
        {
            (Asn1Tag tag, int? length) = ReadTagAndLength(out int headerLength);
            CheckTagIfUniversal(tag, UniversalTagNumber.SetOf);

            // T-REC-X.690-201508 sec 8.12.1
            if (!tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            ReadOnlySpan<byte> contents;
            int suffix = 0;

            if (length != null)
            {
                contents = Slice(_data, headerLength, length.Value);
            }
            else
            {
                contents = SeekEndOfContents(_data.Slice(headerLength), _ruleSet);
                suffix = EndOfContentsEncodedLength;
            }

            if (!skipSortOrderValidation)
            {
                // T-REC-X.690-201508 sec 11.6
                // BER data is not required to be sorted.
                if (_ruleSet == AsnEncodingRules.DER ||
                    _ruleSet == AsnEncodingRules.CER)
                {
                    AsnReader reader = new AsnReader(contents, _ruleSet);

                    ReadOnlySpan<byte> current = ReadOnlySpan<byte>.Empty;

                    while (reader.HasData)
                    {
                        ReadOnlySpan<byte> previous = current;
                        current = reader.GetEncodedValue();

                        int end = Math.Min(previous.Length, current.Length);
                        int i;

                        for (i = 0; i < end; i++)
                        {
                            byte currentVal = current[i];
                            byte previousVal = previous[i];

                            if (currentVal > previousVal)
                            {
                                break;
                            }

                            if (currentVal < previousVal)
                            {
                                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                            }
                        }

                        if (i == end)
                        {
                            // If everything was a tie then we treat the shorter thing as if it were
                            // followed by an infinite number of 0x00s.  So "previous" better not have
                            // more data, or if it does, none of it can be non-zero.
                            //
                            // Note: It doesn't seem possible for the tiebreaker to matter.
                            // In DER everything is length prepended, so the content is only compared
                            // if the tag and length were the same.
                            //
                            // In CER you could have an indefinite octet string, but it will contain
                            // primitive octet strings and EoC. So at some point an EoC is compared
                            // against a tag, and the sort order is determined.
                            //
                            // But since the spec calls it out, maybe there's something degenerate, so
                            // we'll guard against it anyways.

                            for (; i < previous.Length; i++)
                            {
                                if (previous[i] != 0)
                                {
                                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                                }
                            }
                        }
                    }
                }
            }

            _data = _data.Slice(headerLength + contents.Length + suffix);
            return new AsnReader(contents, _ruleSet);
        }

        /// <summary>
        /// Gets the source data for an IA5String under a primitive encoding.
        /// </summary>
        /// <param name="contents">The content bytes for the IA5String payload.</param>
        /// <returns>
        ///   <c>true</c> if the octet string uses a primitive encoding, <c>false</c> otherwise.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///  <ul>
        ///   <li>No data remains</li>
        ///   <li>The tag is invalid for an IA5String value</li>
        ///   <li>The length is invalid under the chosen encoding rules</li>
        ///   <li>A CER encoding was chosen and the primitive content length exceeds the maximum allowed</li>
        /// </ul>
        /// </exception>
        public bool TryGetIA5StringBytes(out ReadOnlySpan<byte> contents)
        {
            return TryGetOctetStringBytes(UniversalTagNumber.IA5String, out contents);
        }

        public bool TryCopyIA5StringBytes(Span<byte> destination, out int bytesWritten)
        {
            bool copied = TryCopyCharacterStringBytes(
                UniversalTagNumber.IA5String,
                destination,
                true,
                out int bytesRead,
                out bytesWritten);

            if (copied)
            {
                _data = _data.Slice(bytesRead);
            }

            return copied;
        }

        public bool TryCopyIA5String(Span<char> destination, out int charsWritten)
        {
            return TryCopyCharacterString(
                UniversalTagNumber.IA5String,
                s_ia5Encoding,
                destination,
                out charsWritten);
        }

        /// <summary>
        /// Gets the source data for a BMPString under a primitive encoding.
        /// </summary>
        /// <param name="contents">The content bytes for the BMPString payload.</param>
        /// <returns>
        ///   <c>true</c> if the octet string uses a primitive encoding, <c>false</c> otherwise.
        /// </returns>
        /// <exception cref="CryptographicException">
        ///  <ul>
        ///   <li>No data remains</li>
        ///   <li>The tag is invalid for a BMPString value</li>
        ///   <li>The length is invalid under the chosen encoding rules</li>
        ///   <li>A CER encoding was chosen and the primitive content length exceeds the maximum allowed</li>
        /// </ul>
        /// </exception>
        public bool TryGetBMPStringBytes(out ReadOnlySpan<byte> contents)
        {
            return TryGetOctetStringBytes(UniversalTagNumber.BMPString, out contents);
        }

        public bool TryCopyBMPStringBytes(Span<byte> destination, out int bytesWritten)
        {
            bool copied = TryCopyCharacterStringBytes(
                UniversalTagNumber.BMPString,
                destination,
                true,
                out int bytesRead,
                out bytesWritten);

            if (copied)
            {
                _data = _data.Slice(bytesRead);
            }

            return copied;
        }

        public bool TryCopyBMPString(Span<char> destination, out int charsWritten)
        {
            return TryCopyCharacterString(
                UniversalTagNumber.BMPString,
                s_bmpEncoding,
                destination,
                out charsWritten);
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

    internal static class AsnSerializer
    {
        private const BindingFlags FieldFlags =
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.Instance;

        private delegate object Deserializer(ref AsnReader reader);

        private static ChoiceAttribute GetChoiceAttribute(Type typeT)
        {
            ChoiceAttribute attr = typeT.GetCustomAttribute<ChoiceAttribute>(inherit: false);

            if (attr == null)
            {
                return null;
            }

            if (attr.AllowNull)
            {
                if (!CanBeNull(typeT))
                {
                    throw new CryptographicException($"{nameof(ChoiceAttribute)}.{nameof(ChoiceAttribute.AllowNull)} is not valid because type {typeT.FullName} cannot be assigned to null");
                }
            }

            return attr;
        }

        private static bool CanBeNull(Type t)
        {
            return !t.IsValueType ||
                (t.IsGenericType && t.GetGenericTypeDefinition() == typeof(Nullable<>));
        }

        private static void PopulateChoiceLookup(
            Dictionary<(TagClass, int), LinkedList<FieldInfo>> lookup,
            Type typeT,
            LinkedList<FieldInfo> currentSet)
        {
            FieldInfo[] fieldInfos = typeT.GetFields(FieldFlags);

            foreach (FieldInfo fieldInfo in fieldInfos)
            {
                Type fieldType = fieldInfo.FieldType;

                if (!CanBeNull(fieldType))
                {
                    throw new CryptographicException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' can not be assigned a null value.");
                }

                fieldType = UnpackNullable(fieldType);

                if (currentSet.Contains(fieldInfo))
                {
                    throw new CryptographicException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' has introduced a type chain cycle.");
                }

                LinkedListNode<FieldInfo> newNode = new LinkedListNode<FieldInfo>(fieldInfo);
                currentSet.AddLast(newNode);
                
                if (GetChoiceAttribute(fieldType) != null)
                {
                    PopulateChoiceLookup(lookup, fieldType, currentSet);
                }
                else
                {
                    GetFieldInfo(
                        fieldType,
                        fieldInfo,
                        out _,
                        out _,
                        out _,
                        out _,
                        out _,
                        out byte[] defaultContents,
                        out Asn1Tag expectedTag);

                    if (defaultContents != null)
                    {
                        // TODO/Review: This might be legal?
                        throw new CryptographicException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' has a default value.");
                    }

                    var key = (expectedTag.TagClass, expectedTag.TagValue);

                    if (lookup.TryGetValue(key, out LinkedList<FieldInfo> existingSet))
                    {
                        FieldInfo existing = existingSet.Last.Value;

                        // TODO/Review: Exception type and message?
                        throw new CryptographicException(
                            $"{expectedTag.TagClass} {expectedTag.TagValue} for field {fieldInfo.Name} on type {fieldInfo.DeclaringType.FullName} already is associated in context with field {existing.Name} on type {existing.DeclaringType.FullName}");
                    }

                    lookup.Add(key, new LinkedList<FieldInfo>(currentSet));
                }

                currentSet.RemoveLast();
            }
        }

        private static object DeserializeChoice(ref AsnReader reader, Type typeT)
        {
            var lookup = new Dictionary<(TagClass, int), LinkedList<FieldInfo>>();
            LinkedList<FieldInfo> fields = new LinkedList<FieldInfo>();
            PopulateChoiceLookup(lookup, typeT, fields);

            Asn1Tag next = reader.PeekTag();

            if (next == Asn1Tag.Null)
            {
                ChoiceAttribute choiceAttr = GetChoiceAttribute(typeT);

                if (choiceAttr.AllowNull)
                {
                    reader.ReadNull();
                    return null;
                }

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            var key = (next.TagClass, next.TagValue);

            if (lookup.TryGetValue(key, out LinkedList<FieldInfo> fieldInfos))
            {
                LinkedListNode<FieldInfo> currentNode = fieldInfos.Last;
                FieldInfo currentField = currentNode.Value;
                object currentObject = Activator.CreateInstance(currentField.DeclaringType);
                Deserializer deserializer = GetDeserializer(currentField.FieldType, currentField);
                object deserialized = deserializer(ref reader);
                currentField.SetValue(currentObject, deserialized);

                while (currentNode.Previous != null)
                {
                    currentNode = currentNode.Previous;
                    currentField = currentNode.Value;

                    object nextObject = Activator.CreateInstance(currentField.DeclaringType);
                    currentField.SetValue(nextObject, currentObject);

                    currentObject = nextObject;
                }

                return currentObject;
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static object DeserializeCustomType(ref AsnReader reader, Type typeT)
        {
            object target = Activator.CreateInstance(typeT);

            AsnReader sequence = reader.ReadSequence();

            foreach (FieldInfo fieldInfo in typeT.GetFields(FieldFlags))
            {
                Deserializer deserializer = GetDeserializer(fieldInfo.FieldType, fieldInfo);
                fieldInfo.SetValue(target, deserializer(ref sequence));
            }

            if (sequence.HasData)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return target;
        }

        private static Deserializer GetDeserializer(Type typeT, FieldInfo fieldInfo)
        {
            if (typeT.IsAbstract || typeT.ContainsGenericParameters)
            {
                // TODO/Review: Exception type and message?
                throw new CryptographicException(typeT.FullName);
            }

            GetFieldInfo(
                typeT,
                fieldInfo,
                out bool wasCustomized,
                out UniversalTagNumber tagType,
                out ObjectIdentifierAttribute oidAttr,
                out bool isAny,
                out bool isCollection,
                out byte[] defaultContents,
                out Asn1Tag expectedTag);
            
            if (typeT.IsPrimitive)
            {
                if (wasCustomized)
                {
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException();
                }

                return DefaultValueDeserializer(
                    expectedTag,
                    tagType,
                    defaultContents,
                    GetPrimitiveDeserializer(typeT));
            }

            if (typeT.IsEnum)
            {
                if (typeT.GetCustomAttributes(typeof(FlagsAttribute), false).Length > 0)
                {
                    // TODO: Flags enums from BitString.
                    throw new NotImplementedException();
                }

                return (ref AsnReader reader) => reader.GetEnumeratedValue(typeT);
            }

            if (typeT == typeof(string))
            {

                if (tagType == 0)
                {
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException(
                        $"Field {fieldInfo.Name} of type {fieldInfo.DeclaringType.FullName} has ambiguous type 'string', an attribute derived from {nameof(AsnTypeAttribute)} is required.");
                }

                if (tagType == UniversalTagNumber.ObjectIdentifier)
                {
                    if ((oidAttr?.PopulateFriendlyName).GetValueOrDefault())
                    {
                        // TODO/Review: Exception type and message?
                        // Friendly name requested on a string output.
                        throw new CryptographicException();
                    }

                    return (ref AsnReader reader) => reader.ReadObjectIdentifierAsString();
                }

                return (ref AsnReader reader) => reader.GetCharacterString(tagType);
            }

            if (typeT == typeof(byte[]) && !isCollection)
            {
                if (isAny)
                {
                    return (ref AsnReader reader) => reader.GetEncodedValue().ToArray();
                }

                if (tagType == 0)
                {
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException(
                        $"Field {fieldInfo.Name} of type {fieldInfo.DeclaringType.FullName} has ambiguous type 'byte[]', an attribute derived from {nameof(AsnTypeAttribute)} is required.");
                }

                if (tagType == UniversalTagNumber.BitString)
                {
                    return (ref AsnReader reader) =>
                    {
                        if (reader.TryGetBitStringBytes(out int unusedBitCount, out ReadOnlySpan<byte> contents))
                        {
                            return contents.ToArray();
                        }

                        // Guaranteed too big, because it has the tag and length.
                        byte[] rented = ArrayPool<byte>.Shared.Rent(reader.PeekEncodedValue().Length);

                        try
                        {
                            if (reader.TryCopyBitStringBytes(rented, out unusedBitCount, out int bytesWritten))
                            {
                                return rented.AsReadOnlySpan().Slice(0, bytesWritten).ToArray();
                            }

                            Debug.Fail("TryCopyBitStringBytes produced more data than the encoded size");
                            throw new CryptographicException();
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
                        }
                    };
                }

                if (tagType == UniversalTagNumber.OctetString)
                {
                    return (ref AsnReader reader) =>
                    {
                        if (reader.TryGetOctetStringBytes(out ReadOnlySpan<byte> contents))
                        {
                            return contents.ToArray();
                        }

                        // Guaranteed too big, because it has the tag and length.
                        byte[] rented = ArrayPool<byte>.Shared.Rent(reader.PeekEncodedValue().Length);

                        try
                        {
                            if (reader.TryCopyOctetStringBytes(rented, out int bytesWritten))
                            {
                                return rented.AsReadOnlySpan().Slice(0, bytesWritten).ToArray();
                            }

                            Debug.Fail("TryCopyOctetStringBytes produced more data than the encoded size");
                            throw new CryptographicException();
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
                        }
                    };
                }

                if (tagType == UniversalTagNumber.Integer)
                {
                    return (ref AsnReader reader) => reader.GetIntegerBytes().ToArray();
                }

                Debug.Fail($"No byte[] handler for {tagType}");
                throw new CryptographicException();
            }

            if (typeT == typeof(Oid))
            {
                bool skipFriendlyName = !(oidAttr?.PopulateFriendlyName).GetValueOrDefault();
                return (ref AsnReader reader) => reader.ReadObjectIdentifier(skipFriendlyName);
            }

            if (typeT.IsArray)
            {
                Type baseType = typeT.GetElementType();

                if (typeT.GetArrayRank() != 1 || baseType.IsArray)
                {
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException();
                }

                return (ref AsnReader reader) =>
                {
                    LinkedList<object> linkedList = new LinkedList<object>();

                    AsnReader collectionReader;

                    if (tagType == UniversalTagNumber.SetOf)
                    {
                        collectionReader = reader.ReadSetOf();
                    }
                    else
                    {
                        Debug.Assert(tagType == 0 || tagType == UniversalTagNumber.SequenceOf);
                        collectionReader = reader.ReadSequence();
                    }

                    Deserializer deserializer = GetDeserializer(baseType, null);

                    while (collectionReader.HasData)
                    {
                        object elem = deserializer(ref collectionReader);
                        LinkedListNode<object> node = new LinkedListNode<object>(elem);
                        linkedList.AddLast(node);
                    }

                    object[] objArr = linkedList.ToArray();
                    Array arr = Array.CreateInstance(baseType, objArr.Length);
                    Array.Copy(objArr, arr, objArr.Length);
                    return arr;
                };
            }

            if (typeT.IsLayoutSequential)
            {
                if (GetChoiceAttribute(typeT) != null)
                {
                    return (ref AsnReader reader) => DeserializeChoice(ref reader, typeT);
                }

                return (ref AsnReader reader) => DeserializeCustomType(ref reader, typeT);
            }

            // TODO/Review: Exception type and message?
            throw new CryptographicException();
        }

        private static Deserializer DefaultValueDeserializer(
            Asn1Tag expectedTag,
            UniversalTagNumber tagType,
            byte[] defaultContents,
            Deserializer literalValueDeserializer)
        {
            if (expectedTag.TagClass == TagClass.Universal && defaultContents == null)
            {
                return literalValueDeserializer;
            }

            if (defaultContents != null)
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.HasData)
                    {
                        Asn1Tag actualTag = reader.PeekTag();

                        if (actualTag.TagClass == expectedTag.TagClass &&
                            actualTag.TagValue == expectedTag.TagValue)
                        {
                            return literalValueDeserializer(ref reader);
                        }
                    }

                    return DefaultValue(tagType, defaultContents);
                };
            }

            return (ref AsnReader reader) =>
            {
                Asn1Tag actualTag = reader.PeekTag();

                if (actualTag.TagClass == expectedTag.TagClass &&
                    actualTag.TagValue == expectedTag.TagValue)
                {
                    return literalValueDeserializer(ref reader);
                }

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            };
        }

        private static object DefaultValue(UniversalTagNumber tagType, byte[] defaultContents)
        {
            Debug.Assert(defaultContents != null);

            // TODO: WRITE THIS FOR REAL!
            if (tagType == UniversalTagNumber.Boolean)
            {
                return defaultContents[0] != 0;
            }
            if (tagType == UniversalTagNumber.Integer)
            {
                return (int)defaultContents[0];
            }

            throw new NotImplementedException(tagType.ToString());
        }

        private static void GetFieldInfo(
            Type typeT,
            FieldInfo fieldInfo,
            out bool wasCustomized,
            out UniversalTagNumber tagType,
            out ObjectIdentifierAttribute oidAttr,
            out bool isAny,
            out bool isCollection,
            out byte[] defaultContents,
            out Asn1Tag expectedTag)
        {
            object[] typeAttrs = fieldInfo?.GetCustomAttributes(typeof(AsnTypeAttribute), false) ??
                                 Array.Empty<object>();

            if (typeAttrs.Length > 1)
            {
                // TODO/Review: Exception type and message?
                throw new CryptographicException();
            }

            typeT = UnpackNullable(typeT);

            tagType = 0;
            oidAttr = null;
            isAny = false;
            isCollection = false;
            wasCustomized = false;

            if (typeAttrs.Length == 1)
            {
                Type[] expectedTypes;
                object attr = typeAttrs[0];
                wasCustomized = true;

                if (attr is AnyValueAttribute)
                {
                    isAny = true;
                    expectedTypes = new[] { typeof(byte[]) };
                }
                else if (attr is IntegerAttribute)
                {
                    expectedTypes = new[] { typeof(byte[]) };
                    tagType = UniversalTagNumber.Integer;
                }
                else if (attr is BitStringAttribute)
                {
                    expectedTypes = new[] { typeof(byte[]) };
                    tagType = UniversalTagNumber.BitString;
                }
                else if (attr is OctetStringAttribute)
                {
                    expectedTypes = new[] { typeof(byte[]) };
                    tagType = UniversalTagNumber.OctetString;
                }
                else if (attr is ObjectIdentifierAttribute oid)
                {
                    oidAttr = oid;
                    expectedTypes = new[] { typeof(Oid), typeof(string) };
                    tagType = UniversalTagNumber.ObjectIdentifier;
                }
                else if (attr is BMPStringAttribute)
                {
                    expectedTypes = new[] { typeof(string) };
                    tagType = UniversalTagNumber.BMPString;
                }
                else if (attr is IA5StringAttribute)
                {
                    expectedTypes = new[] { typeof(string) };
                    tagType = UniversalTagNumber.IA5String;
                }
                else if (attr is UTF8StringAttribute)
                {
                    expectedTypes = new[] { typeof(string) };
                    tagType = UniversalTagNumber.UTF8String;
                }
                else if (attr is SequenceOfAttribute)
                {
                    isCollection = true;
                    expectedTypes = null;
                    tagType = UniversalTagNumber.SequenceOf;
                }
                else if (attr is SetOfAttribute)
                {
                    isCollection = true;
                    expectedTypes = null;
                    tagType = UniversalTagNumber.SetOf;
                }
                else
                {
                    Debug.Fail($"Unregistered {nameof(AsnTypeAttribute)} kind: {attr.GetType().FullName}");
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException();
                }

                if (!isCollection && Array.IndexOf(expectedTypes, typeT) < 0)
                {
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException();
                }
            }

            var defaultValueAttr = fieldInfo?.GetCustomAttribute<DefaultValueAttribute>(false);
            defaultContents = defaultValueAttr?.EncodedBytes;

            if (typeT == typeof(bool))
            {
                tagType = UniversalTagNumber.Boolean;
            }
            else if (typeT == typeof(sbyte) ||
                typeT == typeof(byte) ||
                typeT == typeof(short) ||
                typeT == typeof(ushort) ||
                typeT == typeof(int) ||
                typeT == typeof(uint) ||
                typeT == typeof(long) ||
                typeT == typeof(ulong))
            {
                tagType = UniversalTagNumber.Integer;
            }

            var tagOverride = fieldInfo?.GetCustomAttribute<TagOverrideAttribute>(false);

            if (tagOverride != null)
            {
                // This will throw for unmapped TagClass values and specifying Universal.
                expectedTag = new Asn1Tag(tagOverride.TagClass, tagOverride.Value);
                return;
            }

            expectedTag = new Asn1Tag(tagType);
        }

        private static Type UnpackNullable(Type typeT)
        {
            if (typeT.IsGenericType && typeT.GetGenericTypeDefinition() == typeof(Nullable<>))
            {
                typeT = typeT.GetGenericArguments()[0];
            }
            return typeT;
        }

        private static Deserializer GetPrimitiveDeserializer(Type typeT)
        {
            if (typeT == typeof(bool))
            {
                return (ref AsnReader reader) => reader.ReadBoolean();
            }

            if (typeT == typeof(int))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadInt32(out int value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(uint))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadUInt32(out uint value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(short))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadInt16(out short value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(ushort))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadUInt16(out ushort value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(byte))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadUInt8(out byte value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(sbyte))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadInt8(out sbyte value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(long))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadInt64(out long value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            if (typeT == typeof(ulong))
            {
                return (ref AsnReader reader) =>
                {
                    if (reader.TryReadUInt64(out ulong value))
                    {
                        return value;
                    }

                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                };
            }

            // TODO/Review: Exception type and message?
            throw new CryptographicException();
        }

        public static T Deserialize<T>(ReadOnlySpan<byte> source, AsnEncodingRules ruleSet, out int bytesRead)
        {
            Deserializer deserializer = GetDeserializer(typeof(T), null);

            AsnReader reader = new AsnReader(source, ruleSet);

            bytesRead = 0;
            return (T)deserializer(ref reader);
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class ExpectedTagAttribute : Attribute
    {
        public TagClass TagClass { get; }
        public int TagValue { get; }

        public ExpectedTagAttribute(int tagValue)
            : this(TagClass.ContextSpecific, tagValue)
        {
        }

        public ExpectedTagAttribute(TagClass tagClass, int tagValue)
        {
            TagClass = tagClass;
            TagValue = tagValue;
        }
    }

    internal abstract class AsnTypeAttribute : Attribute
    {
        internal AsnTypeAttribute()
        {
        }
    }

    internal abstract class AsnEncodingRuleAttribute : Attribute
    {
        internal AsnEncodingRuleAttribute()
        {
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class OctetStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class BitStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class AnyValueAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class ObjectIdentifierAttribute : AsnTypeAttribute
    {
        public ObjectIdentifierAttribute()
        {
        }

        public bool PopulateFriendlyName { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class BMPStringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class IA5StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class UTF8StringAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class SequenceOfAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class SetOfAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class IntegerAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class OptionalValueAttribute : AsnEncodingRuleAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class DefaultValueAttribute : AsnEncodingRuleAttribute
    {
        internal byte[] EncodedBytes { get; }

        public DefaultValueAttribute(params byte[] encodedValue)
        {
            EncodedBytes = encodedValue;
        }

        public ReadOnlySpan<byte> EncodedValue => EncodedBytes;
    }

    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
    internal sealed class ChoiceAttribute : Attribute
    {
        public bool AllowNull { get; set; }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class TagOverrideAttribute : Attribute
    {
        public TagClass TagClass { get; }
        public int Value { get; }

        public TagOverrideAttribute(int value)
            : this(TagClass.ContextSpecific, value)
        {
        }

        public TagOverrideAttribute(TagClass tagClass, int value)
        {
            TagClass = tagClass;
            Value = value;
        }
    }

    internal abstract class SpanBasedEncoding : Text.Encoding
    {
        protected SpanBasedEncoding()
            : base(0, EncoderFallback.ExceptionFallback, DecoderFallback.ExceptionFallback)
        {
        }

        protected abstract int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write);
        protected abstract int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write);

        public override int GetByteCount(char[] chars, int index, int count)
        {
            return GetByteCount(new ReadOnlySpan<char>(chars, index, count));
        }

        public override unsafe int GetByteCount(char* chars, int count)
        {
            return GetByteCount(new ReadOnlySpan<char>(chars, count));
        }

        public override int GetByteCount(string s)
        {
            return GetByteCount(s.AsReadOnlySpan());
        }

        private int GetByteCount(ReadOnlySpan<char> chars)
        {
            return GetBytes(chars, Span<byte>.Empty, write: false);
        }
        
        public override int GetBytes(char[] chars, int charIndex, int charCount, byte[] bytes, int byteIndex)
        {
            return GetBytes(
                new ReadOnlySpan<char>(chars, charIndex, charCount),
                new Span<byte>(bytes, byteIndex, bytes.Length - byteIndex),
                write: true);
        }

        public override unsafe int GetBytes(char* chars, int charCount, byte* bytes, int byteCount)
        {
            return GetBytes(
                new ReadOnlySpan<char>(chars, charCount),
                new Span<byte>(bytes, byteCount),
                write: true);
        }

        public override int GetCharCount(byte[] bytes, int index, int count)
        {
            return GetCharCount(new ReadOnlySpan<byte>(bytes, index, count));
        }

        public override unsafe int GetCharCount(byte* bytes, int count)
        {
            return GetCharCount(new ReadOnlySpan<byte>(bytes, count));
        }

        private int GetCharCount(ReadOnlySpan<byte> bytes)
        {
            return GetChars(bytes, Span<char>.Empty, write: false);
        }

        public override int GetChars(byte[] bytes, int byteIndex, int byteCount, char[] chars, int charIndex)
        {
            return GetChars(
                new ReadOnlySpan<byte>(bytes, byteIndex, byteCount),
                new Span<char>(chars, charIndex, chars.Length - charIndex),
                write: true);
        }

        public override unsafe int GetChars(byte* bytes, int byteCount, char* chars, int charCount)
        {
            return GetChars(
                new ReadOnlySpan<byte>(bytes, byteCount),
                new Span<char>(chars, charCount),
                write: true);
        }
    }

    internal class IA5Encoding : SpanBasedEncoding
    {
        public override int GetMaxByteCount(int charCount)
        {
            return charCount;
        }

        public override int GetMaxCharCount(int byteCount)
        {
            return byteCount;
        }

        protected override int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write)
        {
            if (chars.IsEmpty)
                return 0;

            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];

                if (c > 0x7F)
                {
                    EncoderFallback.CreateFallbackBuffer().Fallback(c, i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                if (write)
                {
                    bytes[i] = (byte)c;
                }
            }

            return chars.Length;
        }

        protected override int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write)
        {
            if (bytes.IsEmpty)
                return 0;

            for (int i = 0; i < bytes.Length; i++)
            {
                byte b = bytes[i];

                if (b >= 0x7F)
                {
                    DecoderFallback.CreateFallbackBuffer().Fallback(
                        new[] { b }, 
                        i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                if (write)
                {
                    chars[i] = (char)b;
                }
            }

            return bytes.Length;
        }
    }

    /// <summary>
    /// Big-Endian UCS-2 encoding (the same as UTF-16BE, but disallowing surrogate pairs to leave plane 0)
    /// </summary>
    internal class BMPEncoding : SpanBasedEncoding
    {
        protected override int GetBytes(ReadOnlySpan<char> chars, Span<byte> bytes, bool write)
        {
            if (chars.IsEmpty)
                return 0;

            int writeIdx = 0;

            for (int i = 0; i < chars.Length; i++)
            {
                char c = chars[i];

                if (char.IsSurrogate(c))
                {
                    EncoderFallback.CreateFallbackBuffer().Fallback(c, i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                ushort val16 = c;

                if (write)
                {
                    bytes[writeIdx + 1] = (byte)val16;
                    bytes[writeIdx] = (byte)(val16 >> 8);
                }

                writeIdx += 2;
            }

            return writeIdx;
        }

        protected override int GetChars(ReadOnlySpan<byte> bytes, Span<char> chars, bool write)
        {
            if (bytes.IsEmpty)
            {
                return 0;
            }

            if (bytes.Length % 2 != 0)
            {
                DecoderFallback.CreateFallbackBuffer().Fallback(
                    bytes.Slice(bytes.Length - 1).ToArray(),
                    bytes.Length - 1);

                Debug.Fail("Fallback should have thrown");
                throw new CryptographicException();
            }

            int writeIdx = 0;

            for (int i = 0; i < bytes.Length; i += 2)
            {
                int val = bytes[i] << 8 | bytes[i + 1];
                char c = (char)val;

                if (char.IsSurrogate(c))
                {
                    DecoderFallback.CreateFallbackBuffer().Fallback(
                        bytes.Slice(i, 2).ToArray(),
                        i);

                    Debug.Fail("Fallback should have thrown");
                    throw new CryptographicException();
                }

                if (write)
                {
                    chars[writeIdx] = c;
                }

                writeIdx++;
            }

            return writeIdx;
        }

        public override int GetMaxByteCount(int charCount)
        {
            checked
            {
                return charCount * 2;
            }
        }

        public override int GetMaxCharCount(int byteCount)
        {
            return byteCount / 2;
        }
    }
}
