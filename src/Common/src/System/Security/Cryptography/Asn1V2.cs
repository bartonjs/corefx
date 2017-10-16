// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
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
        GeneralizedTime = 24,
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

        private static readonly ConcurrentDictionary<Asn1Tag, string> s_toString = new ConcurrentDictionary<Asn1Tag, string>();

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

        public int CalculateEncodedSize()
        {
            const int SevenBits = 0b0111_1111;
            const int FourteenBits = 0b0011_1111_1111_1111;
            const int TwentyOneBits = 0b0001_1111_1111_1111_1111_1111;
            const int TwentyEightBits = 0b0000_1111_1111_1111_1111_1111_1111_1111;

            if (TagValue < TagNumberMask)
                return 1;
            if (TagValue <= SevenBits)
                return 2;
            if (TagValue <= FourteenBits)
                return 3;
            if (TagValue <= TwentyOneBits)
                return 4;
            if (TagValue <= TwentyEightBits)
                return 5;

            return 6;
        }

        public bool TryWrite(Span<byte> destination, out int bytesWritten)
        {
            int spaceRequired = CalculateEncodedSize();

            if (destination.Length < spaceRequired)
            {
                bytesWritten = 0;
                return false;
            }

            if (spaceRequired == 1)
            {
                byte value = (byte)(_controlFlags | TagValue);
                destination[0] = value;
                bytesWritten = 1;
                return true;
            }

            byte firstByte = (byte)(_controlFlags | TagNumberMask);
            destination[0] = firstByte;

            int remaining = TagValue;
            int idx = spaceRequired - 1;

            while (remaining > 0)
            {
                int segment = remaining & 0x7F;

                // The last byte doesn't get the marker, which we write first.
                if (remaining != TagValue)
                {
                    segment |= 0x80;
                }

                Debug.Assert(segment <= byte.MaxValue);
                destination[idx] = (byte)segment;
                remaining >>= 7;
                idx--;
            }

            Debug.Assert(idx == 0);
            bytesWritten = spaceRequired;
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

        public override string ToString()
        {
            return s_toString.GetOrAdd(
                this,
                tag =>
                {
                    const string ConstructedPrefix = "Constructed ";
                    string classAndValue;

                    if (tag.TagClass == TagClass.Universal)
                    {
                        classAndValue = ((UniversalTagNumber)tag.TagValue).ToString();
                    }
                    else
                    {
                        classAndValue = tag.TagClass + "-" + tag.TagValue;
                    }

                    if (tag.IsConstructed)
                    {
                        return ConstructedPrefix + classAndValue;
                    }

                    return classAndValue;
                });
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
        internal const int MaxCERSegmentSize = 1000;

        // T-REC-X.690-201508 sec 8.1.5 says only 0000 is legal.
        private const int EndOfContentsEncodedLength = 2;

        private static readonly Text.Encoding s_utf8Encoding = new UTF8Encoding(false, true);
        private static readonly Text.Encoding s_bmpEncoding = new BMPEncoding();
        private static readonly Text.Encoding s_ia5Encoding = new IA5Encoding();
        private static readonly Text.Encoding s_visibleStringEncoding = new VisibleStringEncoding();

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

                    return source.Slice(0, totalLen + initialSliceOffset);
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
                var tagLengthAndContents = SeekEndOfContents(_data, _ruleSet, bytesRead);
                return Slice(_data, 0, tagLengthAndContents.Length + EndOfContentsEncodedLength);
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

            // TODO/review: Is this worth checking? (Flags would be BitString, not Enumerated)
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

        private static byte GetDigit(byte b)
        {
            if (b >= '0' && b <= '9')
                return (byte)(b - '0');

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static DateTimeOffset ParseUtcTime(ReadOnlySpan<byte> contentOctets, int twoDigitYearMax)
        {
            // The full allowed formats (T-REC-X.680-201510 sec 47.3)
            // YYMMDDhhmmZ  (a, b1, c1)
            // YYMMDDhhmm+hhmm (a, b1, c2+)
            // YYMMDDhhmm-hhmm (a, b1, c2-)
            // YYMMDDhhmmssZ (a, b2, c1)
            // YYMMDDhhmmss+hhmm (a, b2, c2+)
            // YYMMDDhhmmss-hhmm (a, b2, c2-)

            const int AB1C1Length = 11;
            const int AB1C2Length = AB1C1Length + 4;
            const int AB2C1Length = AB1C1Length + 2;
            const int AB2C2Length = AB2C1Length + 4;

            // 11, 13, 15, 17 are legal.
            // Range check + odd.
            if (contentOctets.Length < AB1C1Length ||
                contentOctets.Length > AB2C2Length ||
                (contentOctets.Length & 1) != 1)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int year = 10 * GetDigit(contentOctets[0]) + GetDigit(contentOctets[1]);
            int month = 10 * GetDigit(contentOctets[2]) + GetDigit(contentOctets[3]);
            int day = 10 * GetDigit(contentOctets[4]) + GetDigit(contentOctets[5]);
            int hour = 10 * GetDigit(contentOctets[6]) + GetDigit(contentOctets[7]);
            int minute = 10 * GetDigit(contentOctets[8]) + GetDigit(contentOctets[9]);
            int second = 0;
            int offsetHour = 0;
            int offsetMinute = 0;
            bool minus = false;

            if (contentOctets.Length == AB1C1Length)
            {
                if (contentOctets[10] != 'Z')
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }
            else if (contentOctets.Length == AB1C2Length)
            {
                if (contentOctets[10] == '-')
                {
                    minus = true;
                }
                else if (contentOctets[10] != '+')
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                offsetHour = 10 * GetDigit(contentOctets[11]) + GetDigit(contentOctets[12]);
                offsetMinute = 10 * GetDigit(contentOctets[13]) + GetDigit(contentOctets[14]);
            }
            else
            {
                second = 10 * GetDigit(contentOctets[10]) + GetDigit(contentOctets[11]);

                if (contentOctets.Length == AB2C1Length)
                {
                    if (contentOctets[12] != 'Z')
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }
                else
                {
                    Debug.Assert(contentOctets.Length == AB2C2Length);

                    if (contentOctets[12] == '-')
                    {
                        minus = true;
                    }
                    else if (contentOctets[12] != '+')
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    offsetHour = 10 * GetDigit(contentOctets[13]) + GetDigit(contentOctets[14]);
                    offsetMinute = 10 * GetDigit(contentOctets[15]) + GetDigit(contentOctets[16]);
                }
            }

            TimeSpan offset = new TimeSpan(offsetHour, offsetMinute, 0);

            if (minus)
            {
                offset = TimeSpan.Zero - offset;
            }

            int y = year % 100;
            int scaledYear = ((twoDigitYearMax / 100 - (y > twoDigitYearMax % 100 ? 1 : 0)) * 100 + y);

            try
            {
                return new DateTimeOffset(scaledYear, month, day, hour, minute, second, offset);
            }
            catch (Exception e)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding, e);
            }
        }

        /// <summary>
        /// Gets the DateTimeOffset represented by a UTCTime value.
        /// </summary>
        /// <param name="twoDigitYearMax">
        /// The largest year to represent with this value.
        /// The default value, 2049, represents the 1950-2049 range for X.509 certificates.
        /// </param>
        /// <returns>
        /// A DateTimeOffset representing the value encoded in the UTCTime.
        /// </returns>
        /// <seealso cref="System.Globalization.Calendar.TwoDigitYearMax"/>
        public DateTimeOffset GetUtcTime(int twoDigitYearMax = 2049)
        {
            // T-REC-X.680-201510 sec 47.3 says it is IMPLICIT VisibleString, which means
            // that BER is allowed to do complex constructed forms.

            // The full allowed formats (T-REC-X.680-201510 sec 47.3)
            // YYMMDDhhmmZ  (a, b1, c1)
            // YYMMDDhhmm+hhmm (a, b1, c2+)
            // YYMMDDhhmm-hhmm (a, b1, c2-)
            // YYMMDDhhmmssZ (a, b2, c1)
            // YYMMDDhhmmss+hhmm (a, b2, c2+)
            // YYMMDDhhmmss-hhmm (a, b2, c2-)

            // CER and DER are restricted to YYMMDDhhmmssZ
            // T-REC-X.690-201510 sec 11.8
            
            // Optimize for the CER/DER primitive encoding:
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> primitiveOctets,
                out int headerLength,
                UniversalTagNumber.UtcTime))
            {
                if (primitiveOctets.Length == 13)
                {
                    DateTimeOffset value = ParseUtcTime(primitiveOctets, twoDigitYearMax);
                    _data = _data.Slice(headerLength + primitiveOctets.Length);
                    return value;
                }
            }

            // T-REC-X.690-201510 sec 11.8
            if (_ruleSet == AsnEncodingRules.DER || _ruleSet == AsnEncodingRules.CER)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // The longest legal format is (a, b2, c2), which comes out to 17 characters/bytes.
            byte[] rented = ArrayPool<byte>.Shared.Rent(17);
            ReadOnlySpan<byte> contentOctets = ReadOnlySpan<byte>.Empty;

            try
            {
                if (TryCopyCharacterStringBytes(
                    UniversalTagNumber.UtcTime,
                    rented,
                    true,
                    out int bytesRead,
                    out int contentLength))
                {
                    contentOctets = Slice(rented, 0, contentLength);

                    DateTimeOffset value = ParseUtcTime(contentOctets, twoDigitYearMax);
                    // Includes the header
                    _data = _data.Slice(bytesRead);
                    return value;
                }
            }
            finally
            {
                Array.Clear(rented, 0, contentOctets.Length);
                ArrayPool<byte>.Shared.Return(rented);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static DateTimeOffset ParseGeneralizedTime(
            AsnEncodingRules ruleSet,
            ReadOnlySpan<byte> contentOctets,
            bool disallowFractions)
        {
            // T-REC-X.680-201510 sec 46 defines a lot of formats for GeneralizedTime.
            //
            // All formats start with yyyyMMdd.
            //
            // "Local time" formats are
            //   [date]HH.fractionOfAnHourToAnArbitraryPrecision
            //   [date]HHmm.fractionOfAMinuteToAnArbitraryPrecision
            //   [date]HHmmss.fractionOfASecondToAnArbitraryPrecision
            //
            // "UTC time" formats are the local formats suffixed with 'Z'
            //
            // "UTC offset time" formats are the local formats suffixed with
            //  +HH
            //  +HHmm
            //  -HH
            //  -HHmm
            // Additionally, it us unclear if the following formats are supposed to be supported,
            // because the ISO 8601:2004 spec is behind a paywall.
            //  +HH:mm
            //  -HH:mm
            //
            // Also, every instance of '.' is actually "period or comma".

            // Since DateTimeOffset doesn't have a notion of
            // "I'm a local time, but with an unknown offset", the computer's current offset will
            // be used.

            // T-REC-X.690-201510 sec 11.7 binds CER and DER to a much smaller set of inputs:
            //  * Only the UTC/Z format can be used.
            //  * HHmmss must always be used
            //  * If fractions are present they will be separated by period, never comma.
            //  * If fractions are present the last digit mustn't be 0.

            bool strict = ruleSet == AsnEncodingRules.DER || ruleSet == AsnEncodingRules.CER;
            if (strict && contentOctets.Length < 15)
            {
                // yyyyMMddHHmmssZ
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            else if (contentOctets.Length < 10)
            {
                // yyyyMMddHH
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int offset = 0;
            int year =
                1000 * GetDigit(contentOctets[offset++]) +
                100 * GetDigit(contentOctets[offset++]) +
                10 * GetDigit(contentOctets[offset++]) +
                GetDigit(contentOctets[offset++]);

            int month = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
            int day = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
            int hour = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
            int? minute = null;
            int? second = null;
            ulong fraction = 0;
            ulong fractionScale = 1;
            TimeSpan? timeOffset = null;
            bool isZulu = false;

            const byte HmsState = 0;
            const byte FracState = 1;
            const byte SuffixState = 2;
            byte state = HmsState;
            
            if (contentOctets.Length > offset)
            {
                byte octet = contentOctets[offset];

                if (octet == 'Z' || octet == '-' || octet == '+')
                {
                    state = SuffixState;
                }
                else if (octet == '.' || octet == ',')
                {
                    state = FracState;
                }
                else if (contentOctets.Length - 1 <= offset)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
                else
                {
                    minute = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
                }
            }

            if (state == HmsState && contentOctets.Length > offset)
            {
                byte octet = contentOctets[offset];

                if (octet == 'Z' || octet == '-' || octet == '+')
                {
                    state = SuffixState;
                }
                else if (octet == '.' || octet == ',')
                {
                    state = FracState;
                }
                else if (contentOctets.Length - 1 <= offset)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
                else
                {
                    second = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
                }
            }

            if (state == HmsState && contentOctets.Length > offset)
            {
                byte octet = contentOctets[offset];

                if (octet == 'Z' || octet == '-' || octet == '+')
                {
                    state = SuffixState;
                }
                else if (octet == '.' || octet == ',')
                {
                    state = FracState;
                }
                else
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            if (state == FracState)
            {
                if (disallowFractions)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                Debug.Assert(contentOctets.Length > offset);
                byte octet = contentOctets[offset++];

                if (octet == '.')
                {
                    // Always valid
                }
                else if (octet == ',')
                {
                    // Valid for BER, but not CER or DER.
                    if (strict)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }
                }
                else
                {
                    Debug.Fail($"Unhandled value '{octet:X2}' in {nameof(FracState)}");
                    throw new CryptographicException();
                }

                // There are 36,000,000,000 ticks per hour, and hour is our largest scale.
                // In case the double -> Ticks conversion allows for rounding up we can allow
                // for a 12th digit.
                const ulong MaxScale = 1_000_000_000_000;

                if (contentOctets.Length <= offset)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                for (; offset < contentOctets.Length; offset++)
                {
                    octet = contentOctets[offset];

                    if (octet == 'Z' || octet == '-' || octet == '+')
                    {
                        state = SuffixState;
                        break;
                    }

                    if (fractionScale < MaxScale)
                    {
                        fraction *= 10;
                        fraction += GetDigit(contentOctets[offset]);
                        fractionScale *= 10;
                    }
                    else
                    {
                        GetDigit(contentOctets[offset]);
                    }
                }
            }

            if (state == SuffixState)
            {
                Debug.Assert(contentOctets.Length > offset);
                byte octet = contentOctets[offset++];

                if (octet == 'Z')
                {
                    timeOffset = TimeSpan.Zero;
                    isZulu = true;
                }
                else
                {
                    bool isMinus;

                    if (octet == '+')
                    {
                        isMinus = false;
                    }
                    else if (octet == '-')
                    {
                        isMinus = true;
                    }
                    else
                    {
                        Debug.Fail($"Unhandled value '{octet:X2}' in {nameof(SuffixState)}");
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    if (contentOctets.Length - 1 <= offset)
                    {
                        throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                    }

                    int offsetHour = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
                    int offsetMinute = 0;

                    if (contentOctets.Length > offset)
                    {
                        if (contentOctets[offset] == ':')
                        {
                            offset++;
                        }
                    }

                    if (contentOctets.Length - 1 > offset)
                    {
                        offsetMinute = 10 * GetDigit(contentOctets[offset++]) + GetDigit(contentOctets[offset++]);
                    }

                    TimeSpan tmp = new TimeSpan(offsetHour, offsetMinute, 0);

                    if (isMinus)
                    {
                        tmp = TimeSpan.Zero - tmp;
                    }

                    timeOffset = tmp;
                }
            }

            // Was there data after a suffix?
            if (offset != contentOctets.Length)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // T-REC-X.690-201510 sec 11.7
            if (strict)
            {
                if (!isZulu || !second.HasValue)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }

                if (fraction != 0 && fraction % 10 == 0)
                {
                    throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
                }
            }

            double frac = (double)fraction / fractionScale;
            TimeSpan fractionSpan = TimeSpan.Zero;

            if (!minute.HasValue)
            {
                minute = 0;
                second = 0;

                if (fraction != 0)
                {
                    // No minutes means this is fractions of an hour
                    fractionSpan = TimeSpan.FromHours(frac);
                }
            }
            else if (!second.HasValue)
            {
                second = 0;

                if (fraction != 0)
                {
                    // No seconds means this is fractions of a minute
                    fractionSpan = TimeSpan.FromMinutes(frac);
                }
            }
            else if (fraction != 0)
            {
                // Both minutes and seconds means fractions of a second.
                fractionSpan = TimeSpan.FromSeconds(frac);
            }
            
            DateTimeOffset value;

            if (timeOffset == null)
            {
                value = new DateTimeOffset(new DateTime(year, month, day, hour, minute.Value, second.Value));
            }
            else
            {
                value = new DateTimeOffset(year, month, day, hour, minute.Value, second.Value, timeOffset.Value);
            }

            value += fractionSpan;
            return value;
        }

        public DateTimeOffset GetGeneralizedTime(bool disallowFractions=false)
        {
            if (TryGetOctetStringBytes(
                out ReadOnlySpan<byte> primitiveOctets,
                out int headerLength,
                UniversalTagNumber.GeneralizedTime))
            {
                DateTimeOffset value = ParseGeneralizedTime(_ruleSet, primitiveOctets, disallowFractions);
                _data = _data.Slice(headerLength + primitiveOctets.Length);
                return value;
            }

            // T-REC-X.690-201510 sec 9.2
            // T-REC-X.690-201510 sec 10.2
            if (_ruleSet == AsnEncodingRules.DER || _ruleSet == AsnEncodingRules.CER)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            int upperBound = PeekContentSpan().Length;

            byte[] rented = ArrayPool<byte>.Shared.Rent(upperBound);
            ReadOnlySpan<byte> contentOctets = ReadOnlySpan<byte>.Empty;

            try
            {
                if (TryCopyCharacterStringBytes(
                    UniversalTagNumber.GeneralizedTime,
                    rented,
                    true,
                    out int bytesRead,
                    out int contentLength))
                {
                    contentOctets = Slice(rented, 0, contentLength);

                    DateTimeOffset value = ParseGeneralizedTime(_ruleSet, contentOctets, disallowFractions);
                    // Includes the header
                    _data = _data.Slice(bytesRead);
                    return value;
                }
            }
            finally
            {
                Array.Clear(rented, 0, contentOctets.Length);
                ArrayPool<byte>.Shared.Return(rented);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
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

    internal abstract class RangedAsciiEncoding : SpanBasedEncoding
    {
        private readonly byte _minValue;
        private readonly byte _maxValue;

        protected RangedAsciiEncoding(byte minCharAllowed, byte maxCharAllowed)
        {
            Debug.Assert(maxCharAllowed >= minCharAllowed);
            _minValue = minCharAllowed;
            _maxValue = maxCharAllowed;
        }

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

                if (c > _maxValue || c < _minValue)
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

                if (b > _maxValue || b < _minValue)
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

    internal class IA5Encoding : RangedAsciiEncoding
    {
        // All of 7-bit ASCII
        internal IA5Encoding()
            : base(0x00, 0x7F)
        {
        }
    }

    internal class VisibleStringEncoding : RangedAsciiEncoding
    {
        // Space (0x20) through tilde (0x7E)
        // Removes the 0x00-0x1F and the 0x7F control codes.
        internal VisibleStringEncoding()
            : base(0x20, 0x7E)
        {
        }
    }

    internal abstract class RestrictedAsciiStringEncoding : SpanBasedEncoding
    {
        private readonly bool[] _isAllowed;

        protected RestrictedAsciiStringEncoding(IList<char> allowedChars)
        {
            bool[] isAllowed = new bool[0x7F];

            foreach (char c in allowedChars)
            {
                if (c > isAllowed.Length)
                {
                    throw new ArgumentOutOfRangeException(nameof(allowedChars));
                }

                Debug.Assert(isAllowed[c] == false);
                isAllowed[c] = true;
            }

            _isAllowed = isAllowed;
        }

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

                if (c > 0x7F || !_isAllowed[c])
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

                if (b >= 0x7F || !_isAllowed[b])
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

    internal class AsnWriter
    {
        private static readonly Text.Encoding s_bmpEncoding = new BMPEncoding();
        private static readonly Text.Encoding s_ia5Encoding = new IA5Encoding();
        private static readonly Text.Encoding s_utf8Encoding = new UTF8Encoding(false, true);

        private byte[] _buffer;
        private int _offset;
        private Stack<(Asn1Tag,int)> _nestingStack;

        public AsnEncodingRules RuleSet { get; }

        public AsnWriter(AsnEncodingRules ruleSet)
        {
            if (ruleSet != AsnEncodingRules.BER &&
                ruleSet != AsnEncodingRules.CER &&
                ruleSet != AsnEncodingRules.DER)
            {
                throw new ArgumentOutOfRangeException(nameof(ruleSet));
            }

            RuleSet = ruleSet;
        }

        private void EnsureWriteCapacity(int pendingCount)
        {
            if (_buffer == null || _buffer.Length - _offset < pendingCount)
            {
                const int BlockSize = 1024;
                // While the ArrayPool may have similar logic, make sure we don't run into a lot of
                // "grow a little" by asking in 1k steps.
                int blocks = (_offset + pendingCount + (BlockSize - 1)) / BlockSize;
                byte[] newBytes = ArrayPool<byte>.Shared.Rent(BlockSize * blocks);

                if (_buffer != null)
                {
                    Buffer.BlockCopy(_buffer, 0, newBytes, 0, _offset);
                    Array.Clear(_buffer, 0, _offset);
                    ArrayPool<byte>.Shared.Return(_buffer);
                }

#if DEBUG
                // Ensure no "implicit 0" is happening
                for (int i = _offset; i < newBytes.Length; i++)
                {
                    newBytes[i] ^= 0xFF;
                }
#endif

                _buffer = newBytes;
            }
        }

        private void WriteTag(Asn1Tag tag)
        {
            int spaceRequired = tag.CalculateEncodedSize();
            EnsureWriteCapacity(spaceRequired);

            if (!tag.TryWrite(_buffer.AsSpan().Slice(_offset, spaceRequired), out int written) ||
                written != spaceRequired)
            {
                Debug.Fail($"TryWrite failed or written was wrong value ({written} vs {spaceRequired})");
                throw new CryptographicException();
            }

            _offset += spaceRequired;
        }

        private void WriteLength(int length)
        {
            const byte MultiByteMarker = 0x80;
            Debug.Assert(length >= -1);

            if (length == -1)
            {
                EnsureWriteCapacity(1);
                _buffer[_offset] = MultiByteMarker;
                _offset++;
                return;
            }

            Debug.Assert(length >= 0);

            if (length < MultiByteMarker)
            {
                // Pre-allocate the pending data since we know how much.
                EnsureWriteCapacity(1 + length);
                _buffer[_offset] = (byte)length;
                _offset++;
                return;
            }

            var lengthLength = GetLengthLength(length);

            // Pre-allocate the pending data since we know how much.
            EnsureWriteCapacity(lengthLength + 1 + length);
            _buffer[_offset] = (byte)(MultiByteMarker | lengthLength);

            // No minus one because offset didn't get incremented yet.
            int idx = _offset + lengthLength;

            int remaining = length;

            do
            {
                _buffer[idx] = (byte)remaining;
                remaining >>= 8;
                idx--;
            } while (remaining > 0);

            Debug.Assert(idx == _offset);
            _offset += lengthLength + 1;
        }

        private static int GetLengthLength(int length)
        {
            if (length <= 0x7F)
                return 0;
            if (length <= byte.MaxValue)
                return 1;
            if (length <= ushort.MaxValue)
                return 2;
            if (length <= 0x00FFFFFF)
                return 3;

            return 4;
        }

        public void WriteBoolean(bool value)
        {
            WriteBoolean(new Asn1Tag(UniversalTagNumber.Boolean), value);
        }

        public void WriteBoolean(Asn1Tag tag, bool value)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed Boolean values are not supported", nameof(tag));

            WriteTag(tag);
            WriteLength(1);
            // Ensured by WriteLength
            Debug.Assert(_offset < _buffer.Length);
            _buffer[_offset] = (byte)(value ? 0xFF : 0x00);
            _offset++;
        }

        public void WriteInteger(long value)
        {
            WriteInteger(new Asn1Tag(UniversalTagNumber.Integer), value);
        }

        public void WriteInteger(ulong value)
        {
            WriteInteger(new Asn1Tag(UniversalTagNumber.Integer), value);
        }

        public void WriteInteger(BigInteger value)
        {
            WriteInteger(new Asn1Tag(UniversalTagNumber.Integer), value);
        }

        public void WriteInteger(Asn1Tag tag, long value)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed Integer values are not supported", nameof(tag));

            if (value >= 0)
            {
                WriteInteger(tag, (ulong)value);
                return;
            }

            int valueLength;

            if (value >= sbyte.MinValue)
                valueLength = 1;
            else if (value >= short.MinValue)
                valueLength = 2;
            else if (value >= unchecked((long)0xFFFFFFFF_FF800000))
                valueLength = 3;
            else if (value >= int.MinValue)
                valueLength = 4;
            else if (value >= unchecked((long)0xFFFFFF80_00000000))
                valueLength = 5;
            else if (value >= unchecked((long)0xFFFF8000_00000000))
                valueLength = 6;
            else if (value >= unchecked((long)0xFF800000_00000000))
                valueLength = 7;
            else
                valueLength = 8;
           
            WriteTag(tag);
            WriteLength(valueLength);

            long remaining = value;
            int idx = _offset + valueLength - 1;

            do
            {
                _buffer[idx] = (byte)(remaining & 0xFF);
                remaining >>= 8;
                idx--;
            } while (idx >= _offset);

#if DEBUG
            if (valueLength > 1)
            {
                // T-REC-X.690-201508 sec 8.1.2.2
                // Cannot start with 9 bits of 1 (or 9 bits of 0, but that's not this method).
                Debug.Assert(_buffer[_offset] != 0xFF || _buffer[_offset + 1] < 0x80);
            }
#endif

            _offset += valueLength;
        }

        public void WriteInteger(Asn1Tag tag, ulong value)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed Integer values are not supported", nameof(tag));

            int valueLength;
            
            // 0x80 needs two bytes: 0x00 0x80
            if (value < 0x80)
                valueLength = 1;
            else if (value < 0x8000)
                valueLength = 2;
            else if (value < 0x800000)
                valueLength = 3;
            else if (value < 0x80000000)
                valueLength = 4;
            else if (value < 0x80_00000000)
                valueLength = 5;
            else if (value < 0x8000_00000000)
                valueLength = 6;
            else if (value < 0x800000_00000000)
                valueLength = 7;
            else if (value < 0x800000_0000000000)
                valueLength = 8;
            else
                valueLength = 9;

            WriteTag(tag);
            WriteLength(valueLength);

            ulong remaining = value;
            int idx = _offset + valueLength - 1;

            do
            {
                _buffer[idx] = (byte)remaining;
                remaining >>= 8;
                idx--;
            } while (idx >= _offset);

#if DEBUG
            if (valueLength > 1)
            {
                // T-REC-X.690-201508 sec 8.1.2.2
                // Cannot start with 9 bits of 0 (or 9 bits of 1, but that's not this method).
                Debug.Assert(_buffer[_offset] != 0 || _buffer[_offset + 1] > 0x7F);
            }
#endif

            _offset += valueLength;
        }

        public void WriteInteger(Asn1Tag tag, BigInteger value)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed Integer values are not supported", nameof(tag));

            // TODO: Rewrite with Span operations after moving branch forward.
            byte[] encoded = value.ToByteArray();
            Array.Reverse(encoded);

            WriteTag(tag);
            WriteLength(encoded.Length);
            Buffer.BlockCopy(encoded, 0, _buffer, _offset, encoded.Length);
            _offset += encoded.Length;
        }

        public void WriteBitString(ReadOnlySpan<byte> bitString, int unusedBitCount=0)
        {
            WriteBitString(new Asn1Tag(UniversalTagNumber.BitString), bitString, unusedBitCount);
        }

        public void WriteBitString(Asn1Tag tag, ReadOnlySpan<byte> bitString, int unusedBitCount=0)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            // TODO: Find a section number for the 0 bound.
            // T-REC-X.690-201508 sec 8.6.2.2
            if (unusedBitCount < 0 || unusedBitCount > 7)
                throw new ArgumentOutOfRangeException(
                    nameof(unusedBitCount),
                    unusedBitCount,
                    $"Unused bit count must be between 0 and 7 inclusive");

            // T-REC-X.690-201508 sec 8.6.2.4
            if (bitString.Length == 0 && unusedBitCount != 0)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            // If 3 bits are "unused" then build a mask for the top 5 bits.
            // 0b1111_1111 >> (8 - 3)
            // 0b1111_1111 >> 5
            // 0b0000_0111
            // (then invert that)
            // 0b1111_1000
            byte mask = (byte)~(0xFF >> (8 - unusedBitCount));
            byte lastByte = bitString.IsEmpty ? (byte)0 : bitString[bitString.Length - 1];

            if ((lastByte & mask) != lastByte)
            {
                // TODO: Probably warrants a distinct message.
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            if (RuleSet == AsnEncodingRules.BER)
            {
                // Clear the constructed flag, if present.
                tag = new Asn1Tag(tag.TagClass, tag.TagValue);
            }
            else if (RuleSet == AsnEncodingRules.DER && tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            else if (RuleSet == AsnEncodingRules.CER)
            {
                // If it's within a primitive segment, just clear the constructed flag
                // (if present) and continue.
                // (strict less than because of the unused bit count byte)
                if (bitString.Length < AsnReader.MaxCERSegmentSize)
                {
                    tag = new Asn1Tag(tag.TagClass, tag.TagValue);
                }
                else
                {
                    WriteCERBitString(tag, bitString, unusedBitCount);
                    return;
                }
            }

            WriteTag(tag);
            // The unused bits byte requires +1.
            WriteLength(bitString.Length + 1);
            _buffer[_offset] = (byte)unusedBitCount;
            _offset++;
            bitString.CopyTo(_buffer.AsSpan().Slice(_offset));
            _offset += bitString.Length;
        }


        private void WriteCERBitString(Asn1Tag tag, ReadOnlySpan<byte> payload, int unusedBitCount)
        {
            const int MaxCERSegmentSize = AsnReader.MaxCERSegmentSize;
            // Every segment has an "unused bit count" byte.
            const int MaxCERContentSize = MaxCERSegmentSize - 1;
            Debug.Assert(payload.Length > MaxCERContentSize);

            WriteTag(new Asn1Tag(tag.TagClass, tag.TagValue, isConstructed: true));
            WriteLength(-1);

            int fullSegments = Math.DivRem(payload.Length, MaxCERContentSize, out int lastContentSize);
            // +Unused bit count byte.
            int lastSegmentSize = lastContentSize + 1;
            // The tag size of primitive OCTET STRING is 1 byte.
            // The lengthOrLengthLength byte is always 1 byte.
            // These calculations use segment size (vs content size) to pre-account for the unused count byte.
            int fullSegmentEncodedSize = 1 + 1 + MaxCERSegmentSize + GetLengthLength(MaxCERSegmentSize);
            Debug.Assert(fullSegmentEncodedSize == 1004);
            int remainingEncodedSize = 1 + 1 + lastSegmentSize + GetLengthLength(lastSegmentSize);

            if (lastContentSize == 0)
            {
                lastSegmentSize = remainingEncodedSize = 0;
            }

            // Reduce the number of copies by pre-calculating the size.
            // +2 for End-Of-Contents
            int expectedSize = fullSegments * fullSegmentEncodedSize + remainingEncodedSize + 2;
            EnsureWriteCapacity(expectedSize);

            byte[] ensureNoExtraCopy = _buffer;
            int savedOffset = _offset;

            ReadOnlySpan<byte> remainingData = payload;
            Span<byte> dest;
            Asn1Tag primitiveBitString = new Asn1Tag(UniversalTagNumber.BitString);

            while (remainingData.Length > MaxCERContentSize)
            {
                WriteTag(primitiveBitString);
                WriteLength(MaxCERSegmentSize);
                // 0 unused bits in this segment.
                _buffer[_offset] = 0;
                _offset++;

                dest = _buffer.AsSpan().Slice(_offset);
                remainingData.Slice(0, MaxCERContentSize).CopyTo(dest);

                remainingData = remainingData.Slice(MaxCERContentSize);
                _offset += MaxCERContentSize;
            }

            WriteTag(primitiveBitString);
            WriteLength(remainingData.Length + 1);

            _buffer[_offset] = (byte)unusedBitCount;
            _offset++;

            dest = _buffer.AsSpan().Slice(_offset);
            remainingData.CopyTo(dest);
            _offset += remainingData.Length;

            WriteTag(Asn1Tag.EndOfContents);
            WriteLength(0);

            Debug.Assert(_offset - savedOffset == expectedSize, $"expected size was {expectedSize}, actual was {_offset - savedOffset}");
            Debug.Assert(_buffer == ensureNoExtraCopy, $"_buffer was replaced during {nameof(WriteCERBitString)}");
        }

        public void WriteOctetString(ReadOnlySpan<byte> octetString)
        {
            WriteOctetString(new Asn1Tag(UniversalTagNumber.OctetString), octetString);
        }

        public void WriteOctetString(Asn1Tag tag, ReadOnlySpan<byte> octetString)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            if (RuleSet == AsnEncodingRules.BER)
            {
                // Clear the constructed flag, if present.
                tag = new Asn1Tag(tag.TagClass, tag.TagValue);
            }
            else if (RuleSet == AsnEncodingRules.DER && tag.IsConstructed)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            else if (RuleSet == AsnEncodingRules.CER)
            {
                // If it's within a primitive segment, just clear the constructed flag
                // (if present) and continue.
                if (octetString.Length <= AsnReader.MaxCERSegmentSize)
                {
                    tag = new Asn1Tag(tag.TagClass, tag.TagValue);
                }
                else
                {
                    WriteCEROctetString(tag, octetString);
                    return;
                }
            }

            WriteTag(tag);
            WriteLength(octetString.Length);
            octetString.CopyTo(_buffer.AsSpan().Slice(_offset));
            _offset += octetString.Length;
        }

        private void WriteCEROctetString(Asn1Tag tag, ReadOnlySpan<byte> payload)
        {
            const int MaxCERSegmentSize = AsnReader.MaxCERSegmentSize;
            Debug.Assert(payload.Length > MaxCERSegmentSize);

            WriteTag(new Asn1Tag(tag.TagClass, tag.TagValue, isConstructed: true));
            WriteLength(-1);

            int fullSegments = Math.DivRem(payload.Length, MaxCERSegmentSize, out int lastSegmentSize);
            // The tag size of primitive OCTET STRING is 1 byte.
            // The lengthOrLengthLength byte is always 1 byte.
            int fullSegmentEncodedSize = 1 + 1 + MaxCERSegmentSize + GetLengthLength(MaxCERSegmentSize);
            Debug.Assert(fullSegmentEncodedSize == 1004);
            int remainingEncodedSize = 1 + 1 + lastSegmentSize + GetLengthLength(lastSegmentSize);

            if (lastSegmentSize == 0)
            {
                remainingEncodedSize = 0;
            }

            // Reduce the number of copies by pre-calculating the size.
            // +2 for End-Of-Contents
            int expectedSize = fullSegments * fullSegmentEncodedSize + remainingEncodedSize + 2;
            EnsureWriteCapacity(expectedSize);

            byte[] ensureNoExtraCopy = _buffer;
            int savedOffset = _offset;

            ReadOnlySpan<byte> remainingData = payload;
            Span<byte> dest;
            Asn1Tag primitiveOctetString = new Asn1Tag(UniversalTagNumber.OctetString);

            while (remainingData.Length > MaxCERSegmentSize)
            {
                WriteTag(primitiveOctetString);
                WriteLength(MaxCERSegmentSize);

                dest = _buffer.AsSpan().Slice(_offset);
                remainingData.Slice(0, MaxCERSegmentSize).CopyTo(dest);

                _offset += MaxCERSegmentSize;
                remainingData = remainingData.Slice(MaxCERSegmentSize);
            }

            WriteTag(primitiveOctetString);
            WriteLength(remainingData.Length);
            dest = _buffer.AsSpan().Slice(_offset);
            remainingData.CopyTo(dest);
            _offset += remainingData.Length;

            WriteTag(Asn1Tag.EndOfContents);
            WriteLength(0);

            Debug.Assert(_offset - savedOffset == expectedSize, $"expected size was {expectedSize}, actual was {_offset - savedOffset}");
            Debug.Assert(_buffer == ensureNoExtraCopy, $"_buffer was replaced during {nameof(WriteCEROctetString)}");
        }

        public void WriteNull()
        {
            WriteNull(Asn1Tag.Null);
        }

        public void WriteNull(Asn1Tag tag)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed Null values are not supported", nameof(tag));

            WriteTag(tag);
            WriteLength(0);
        }

        public void WriteObjectIdentifier(Oid oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            WriteObjectIdentifier(oid.Value);
        }

        public void WriteObjectIdentifier(string oidValue)
        {
            if (oidValue == null)
                throw new ArgumentNullException(nameof(oidValue));

            WriteObjectIdentifier(oidValue.AsReadOnlySpan());
        }

        public void WriteObjectIdentifier(ReadOnlySpan<char> oidValue)
        {
            WriteObjectIdentifier(new Asn1Tag(UniversalTagNumber.ObjectIdentifier), oidValue);
        }

        public void WriteObjectIdentifier(Asn1Tag tag, Oid oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            WriteObjectIdentifier(tag, oid.Value);
        }

        public void WriteObjectIdentifier(Asn1Tag tag, string oidValue)
        {
            if (oidValue == null)
                throw new ArgumentNullException(nameof(oidValue));

            WriteObjectIdentifier(tag, oidValue.AsReadOnlySpan());
        }

        public void WriteObjectIdentifier(Asn1Tag tag, ReadOnlySpan<char> oidValue)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (tag.IsConstructed)
                throw new ArgumentException($"Constructed ObjectIdentifier values are not supported", nameof(tag));

            // TODO: Review exceptions.
            if (oidValue.Length < 3 /* "1.1" is the shortest value */)
                throw new CryptographicException(SR.Argument_InvalidOidValue);
            if (oidValue[1] != '.')
                throw new CryptographicException(SR.Argument_InvalidOidValue);

            // The worst case is "1.1.1.1.1", which takes 4 bytes (5 rids, with the first two condensed)
            // Longer numbers get smaller: "2.1.127" is only 2 bytes. (81d (0x51) and 127 (0x7F))
            // So length / 2 should prevent any reallocations.
            byte[] tmp = ArrayPool<byte>.Shared.Rent(oidValue.Length / 2);

            try
            {
                int firstRid;

                switch (oidValue[0])
                {
                    case '0':
                        firstRid = 0;
                        break;
                    case '1':
                        firstRid = 1;
                        break;
                    case '2':
                        firstRid = 2;
                        break;
                    default:
                        throw new CryptographicException(SR.Argument_InvalidOidValue);
                }

                // The first two RIDs are special:
                // ITU X.690 8.19.4:
                //   The numerical value of the first subidentifier is derived from the values of the first two
                //   object identifier components in the object identifier value being encoded, using the formula:
                //       (X*40) + Y
                //   where X is the value of the first object identifier component and Y is the value of the
                //   second object identifier component.
                //       NOTE � This packing of the first two object identifier components recognizes that only
                //          three values are allocated from the root node, and at most 39 subsequent values from
                //          nodes reached by X = 0 and X = 1.

                // skip firstRid and the trailing .
                ReadOnlySpan<char> remaining = oidValue.Slice(2);

                BigInteger rid = ParseOidRid(ref remaining);
                rid += 40 * firstRid;

                int tmpOffset = 0;
                int localLen = EncodeRid(tmp.AsSpan().Slice(tmpOffset), ref rid);
                tmpOffset += localLen;

                while (!remaining.IsEmpty)
                {
                    rid = ParseOidRid(ref remaining);
                    localLen = EncodeRid(tmp.AsSpan().Slice(tmpOffset), ref rid);
                    tmpOffset += localLen;
                }

                WriteTag(tag);
                WriteLength(tmpOffset);
                Buffer.BlockCopy(tmp, 0, _buffer, _offset, tmpOffset);
                _offset += tmpOffset;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(tmp);
            }
        }

        private static BigInteger ParseOidRid(ref ReadOnlySpan<char> oidValue)
        {
            int endIndex = oidValue.IndexOf('.');

            if (endIndex == -1)
            {
                endIndex = oidValue.Length;
            }
            else if (endIndex == oidValue.Length - 1)
            {
                throw new CryptographicException(SR.Argument_InvalidOidValue);
            }

            // The following code is equivalent to
            // BigInteger.TryParse(temp, NumberStyles.None, CultureInfo.InvariantCulture, out value)
            // TODO: Change it when BigInteger supports ROS<char>?
            BigInteger value = BigInteger.Zero;

            for (int position = 0; position < endIndex; position++)
            {
                if (position > 0 && value == 0)
                {
                    // T-REC X.680-201508 sec 12.26
                    throw new CryptographicException("Object identifier is in an invalid format");
                }

                value *= 10;
                value += AtoI(oidValue[position]);
            }

            oidValue = oidValue.Slice(Math.Min(oidValue.Length, endIndex + 1));
            return value;
        }

        private static int AtoI(char c)
        {
            if (c >= '0' && c <= '9')
                return c - '0';

            throw new CryptographicException(SR.Argument_InvalidOidValue);
        }

        private static int EncodeRid(Span<byte> dest, ref BigInteger rid)
        {
            Debug.Assert(dest.Length > 0);

            if (rid.IsZero)
            {
                dest[0] = 0;
                return 1;
            }
           
            BigInteger unencoded = rid;
            int idx = 0;

            do
            {
                BigInteger cur = unencoded & 0x7F;
                byte curByte = (byte)cur;

                if (rid != unencoded)
                {
                    curByte |= 0x80;
                }

                unencoded >>= 7;
                dest[idx] = curByte;
                idx++;
            }
            while (unencoded != BigInteger.Zero);

            Reverse(dest.Slice(0, idx));
            return idx;
        }

        public void WriteEnumeratedValue<TEnum>(TEnum value) where TEnum : struct
        {
            WriteEnumeratedValue(new Asn1Tag(UniversalTagNumber.Enumerated), value);
        }

        public void WriteEnumeratedValue<TEnum>(Asn1Tag tag, TEnum value) where TEnum : struct
        {
            Type tEnum = typeof(TEnum);

            if (!tEnum.IsEnum)
                throw new ArgumentException("Value type must be an Enum");
            if (tEnum.IsDefined(typeof(FlagsAttribute), false))
                throw new ArgumentException("[Flags] enums are not supported");

            Type backingType = tEnum.GetEnumUnderlyingType();

            if (backingType == typeof(ulong))
            {
                ulong numericValue = Convert.ToUInt64(value);
                WriteInteger(tag, numericValue);
            }
            else
            {
                // All other types fit in a (signed) long.
                long numericValue = Convert.ToInt64(value);
                WriteInteger(tag, numericValue);
            }
        }

        public void WriteUtf8String(string str)
        {
            if (str == null)
                throw new ArgumentNullException(nameof(str));

            WriteUtf8String(new Asn1Tag(UniversalTagNumber.UTF8String), str);
        }

        public void WriteUtf8String(ReadOnlySpan<char> str)
        {
            WriteUtf8String(new Asn1Tag(UniversalTagNumber.UTF8String), str);
        }

        public void WriteUtf8String(Asn1Tag tag, string str)
        {
            if (str == null)
                throw new ArgumentNullException(nameof(str));
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteUtf8String(tag, str.AsReadOnlySpan());
        }

        public void WriteUtf8String(Asn1Tag tag, ReadOnlySpan<char> str)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteCharacterString(tag, s_utf8Encoding, str);
        }

        public void PushSequence()
        {
            PushSequence(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true));
        }

        public void PushSequence(Asn1Tag tag)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (!tag.IsConstructed)
                throw new ArgumentException("Primitive Sequence vales are not supported", nameof(tag));

            PushTag(tag);
        }

        public void PopSequence()
        {
            PopSequence(new Asn1Tag(UniversalTagNumber.Sequence, isConstructed: true));
        }

        public void PopSequence(Asn1Tag tag)
        {
            PopTag(tag);
        }

        public void PushSetOf()
        {
            PushSetOf(new Asn1Tag(UniversalTagNumber.SetOf, isConstructed: true));
        }

        public void PushSetOf(Asn1Tag tag)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            // TODO: Spec ID?
            if (!tag.IsConstructed)
                throw new ArgumentException("Primitive SetOf vales are not supported", nameof(tag));

            PushTag(tag);
        }

        public void PopSetOf()
        {
            PopSetOf(new Asn1Tag(UniversalTagNumber.SetOf, isConstructed: true));
        }

        public void PopSetOf(Asn1Tag tag)
        {
            PopTag(tag);
        }

        public void WriteIA5String(string str)
        {
            if (str == null)
                throw new ArgumentNullException(nameof(str));

            WriteIA5String(new Asn1Tag(UniversalTagNumber.IA5String), str.AsReadOnlySpan());
        }

        public void WriteIA5String(ReadOnlySpan<char> str)
        {
            WriteIA5String(new Asn1Tag(UniversalTagNumber.IA5String), str);
        }

        public void WriteIA5String(Asn1Tag tag, string str)
        {
            if (str == null)
                throw new ArgumentNullException(nameof(str));
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteIA5String(tag, str.AsReadOnlySpan());
        }

        public void WriteIA5String(Asn1Tag tag, ReadOnlySpan<char> str)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteCharacterString(tag, s_ia5Encoding, str);
        }
        
        public void WriteUtcTime(DateTimeOffset value)
        {
            WriteUtcTime(new Asn1Tag(UniversalTagNumber.UtcTime), value);
        }

        public void WriteUtcTime(Asn1Tag tag, DateTimeOffset value)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteTag(tag);

            // BER allows for omitting the seconds, but that's not an option we need to expose.
            // BER allows for non-UTC values, but that's also not an option we need to expose.
            // So the format is always yyMMddHHmmssZ (13)
            const int UtcTimeValueLength = 13;
            WriteLength(UtcTimeValueLength);

            DateTimeOffset normalized = value.ToUniversalTime();

            int year = normalized.Year;
            int month = normalized.Month;
            int day = normalized.Day;
            int hour = normalized.Hour;
            int minute = normalized.Minute;
            int second = normalized.Second;

            year = WriteLeastSigificantDigitAndShift(year, _offset + 1);
            WriteLeastSigificantDigitAndShift(year, _offset);

            month = WriteLeastSigificantDigitAndShift(month, _offset + 3);
            WriteLeastSigificantDigitAndShift(month, _offset + 2);

            day = WriteLeastSigificantDigitAndShift(day, _offset + 5);
            WriteLeastSigificantDigitAndShift(day, _offset + 4);

            hour = WriteLeastSigificantDigitAndShift(hour, _offset + 7);
            WriteLeastSigificantDigitAndShift(hour, _offset + 6);

            minute = WriteLeastSigificantDigitAndShift(minute, _offset + 9);
            WriteLeastSigificantDigitAndShift(minute, _offset + 8);

            second = WriteLeastSigificantDigitAndShift(second, _offset + 11);
            WriteLeastSigificantDigitAndShift(second, _offset + 10);

            _buffer[_offset + 12] = (byte)'Z';

            _offset += UtcTimeValueLength;
        }

        public void WriteGeneralizedTime(DateTimeOffset value, bool omitFractionalSeconds = false)
        {
            WriteGeneralizedTime(new Asn1Tag(UniversalTagNumber.GeneralizedTime), value, omitFractionalSeconds);
        }

        public void WriteGeneralizedTime(Asn1Tag tag, DateTimeOffset value, bool omitFractionalSeconds = false)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            // GeneralizedTime under BER allows many different options:
            // * (HHmmss), (HHmm), (HH)
            // * "(value).frac", "(value),frac"
            // * frac == 0 may be omitted or emitted
            // non-UTC offset in various formats
            //
            // We're not allowing any of them.
            // Just encode as the CER/DER common restrictions.
            //
            // This results in the following formats:
            // yyyyMMddHHmmssZ
            // yyyyMMddHHmmss.f?Z
            //
            // where "f?" is anything from "f" to "fffffff" (tenth of a second down to 100ns/1-tick)
            // with no trailing zeros.
            DateTimeOffset normalized = value.ToUniversalTime();

            if (normalized.Year > 9999)
            {
                // This is unreachable since DateTimeOffset guards against this internally.
                throw new ArgumentOutOfRangeException(
                    nameof(value),
                    value,
                    "Date cannot be represented as a GeneralizedTime");
            }

            long fracValue = 0;
            int fracLength;

            if (omitFractionalSeconds)
            {
                fracLength = 0;
            }
            else
            {
                DateTimeOffset hhmmss = new DateTimeOffset(
                    normalized.Year,
                    normalized.Month,
                    normalized.Day,
                    normalized.Hour,
                    normalized.Minute,
                    normalized.Second,
                    normalized.Offset);

                long floatingTicks = normalized.Ticks - hhmmss.Ticks;

                if (floatingTicks == 0)
                {
                    fracLength = 0;
                }
                else
                {
                    fracLength = 7;
                    long tickTest = floatingTicks;

                    while (true)
                    {
                        long rem;
                        long div = Math.DivRem(tickTest, 10, out rem);

                        if (div * 10 != tickTest)
                        {
                            fracValue = tickTest;
                            break;
                        }

                        tickTest = div;
                        fracLength--;
                    }
                }
            }

            // yyyy, MM, dd, hh, mm, ss, Z
            int totalLength = 4 + 2 + 2 + 2 + 2 + 2 + 1;

            if (fracLength != 0)
            {
                // . and the fraction
                totalLength += 1 + fracLength;
            }

            WriteTag(tag);
            WriteLength(totalLength);

            int year = normalized.Year;
            int month = normalized.Month;
            int day = normalized.Day;
            int hour = normalized.Hour;
            int minute = normalized.Minute;
            int second = normalized.Second;

            year = WriteLeastSigificantDigitAndShift(year, _offset + 3);
            year = WriteLeastSigificantDigitAndShift(year, _offset + 2);
            year = WriteLeastSigificantDigitAndShift(year, _offset + 1);
            WriteLeastSigificantDigitAndShift(year, _offset);

            month = WriteLeastSigificantDigitAndShift(month, _offset + 5);
            WriteLeastSigificantDigitAndShift(month, _offset + 4);

            day = WriteLeastSigificantDigitAndShift(day, _offset + 7);
            WriteLeastSigificantDigitAndShift(day, _offset + 6);

            hour = WriteLeastSigificantDigitAndShift(hour, _offset + 9);
            WriteLeastSigificantDigitAndShift(hour, _offset + 8);

            minute = WriteLeastSigificantDigitAndShift(minute, _offset + 11);
            WriteLeastSigificantDigitAndShift(minute, _offset + 10);

            second = WriteLeastSigificantDigitAndShift(second, _offset + 13);
            WriteLeastSigificantDigitAndShift(second, _offset + 12);

            _offset += 14;

            if (fracLength > 0)
            {
                _buffer[_offset] = (byte)'.';

                int fracWrite = (int)fracValue;

                for (int i = 0; i < fracLength; i++)
                {
                    // a "-1" is not needed here because we didn't increment after the decimal point.
                    fracWrite = WriteLeastSigificantDigitAndShift(fracWrite, _offset - i + fracLength);
                }

                Debug.Assert(fracWrite == 0);
                Debug.Assert(_buffer[_offset + fracLength] != (byte)'0');

                // Digits and the decimal point.
                _offset += fracLength + 1;
            }

            _buffer[_offset] = (byte)'Z';
            _offset++;
        }

        public void WriteBMPString(string str)
        {
            if (str == null)
                throw new ArgumentNullException(nameof(str));

            WriteBMPString(new Asn1Tag(UniversalTagNumber.BMPString), str.AsReadOnlySpan());
        }

        public void WriteBMPString(ReadOnlySpan<char> str)
        {
            WriteBMPString(new Asn1Tag(UniversalTagNumber.BMPString), str);
        }

        public void WriteBMPString(Asn1Tag tag, string str)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));
            if (str == null)
                throw new ArgumentNullException(nameof(str));

            WriteBMPString(new Asn1Tag(UniversalTagNumber.BMPString), str.AsReadOnlySpan());
        }

        public void WriteBMPString(Asn1Tag tag, ReadOnlySpan<char> str)
        {
            // TODO: Spec ID?
            if (tag == default(Asn1Tag))
                throw new ArgumentException($"UNIVERSAL 0 tag may not be specified", nameof(tag));

            WriteCharacterString(tag, s_bmpEncoding, str);
        }

        public bool TryEncode(Span<byte> dest, out int bytesWritten)
        {
            if ((_nestingStack?.Count ?? 0) != 0)
                throw new InvalidOperationException($"Cannot Encode while a SetOf or Sequence is still open");

            // If the stack is closed out then everything is a definite encoding (BER, DER) or a
            // required indefinite encoding (CER). So we're correctly sized up, and ready to copy.
            if (dest.Length < _offset)
            {
                bytesWritten = 0;
                return false;
            }

            if (_offset == 0)
            {
                bytesWritten = 0;
                return true;
            }

            bytesWritten = _offset;
            _buffer.AsSpan().Slice(0, _offset).CopyTo(dest);
            return true;
        }

        public byte[] Encode()
        {
            if ((_nestingStack?.Count ?? 0) != 0)
                throw new InvalidOperationException($"Cannot Encode while a SetOf or Sequence is still open");

            if (_offset == 0)
                return Array.Empty<byte>();

            // If the stack is closed out then everything is a definite encoding (BER, DER) or a
            // required indefinite encoding (CER). So we're correctly sized up, and ready to copy.
            return _buffer.AsSpan().Slice(0, _offset).ToArray();
        }

        private void PushTag(Asn1Tag tag)
        {
            if (_nestingStack == null)
            {
                _nestingStack = new Stack<(Asn1Tag,int)>();
            }

            WriteTag(tag);
            _nestingStack.Push((tag, _offset));
            WriteLength(-1);
        }

        private void PopTag(Asn1Tag tag)
        {
            if (_nestingStack == null || _nestingStack.Count == 0)
                throw new ArgumentException("Cannot pop the requested tag as it is not currently open", nameof(tag));

            (Asn1Tag stackTag, int lenOffset) = _nestingStack.Peek();

            if (stackTag != tag)
                throw new ArgumentException("Cannot pop the requested tag as it is not currently open", nameof(tag));

            _nestingStack.Pop();

            if (RuleSet == AsnEncodingRules.CER)
            {
                // Write EndOfContents
                WriteTag(Asn1Tag.EndOfContents);
                WriteLength(0);
                return;
            }

            int containedLength = _offset - 1 - lenOffset;
            Debug.Assert(containedLength >= 0);

            int shiftSize = GetLengthLength(containedLength);

            // Best case, length fits in the compact byte
            if (shiftSize == 0)
            {
                _buffer[lenOffset] = (byte)containedLength;
                return;
            }

            // We're currently at the end, so ensure we have room for N more bytes.
            EnsureWriteCapacity(shiftSize);

            // Buffer.BlockCopy correctly does forward-overlapped, so use it.
            int start = lenOffset + 1;
            Buffer.BlockCopy(_buffer, start, _buffer, start + shiftSize, containedLength);

            int tmp = _offset;
            _offset = lenOffset;
            WriteLength(containedLength);
            Debug.Assert(_offset - lenOffset == shiftSize);
            _offset = tmp + shiftSize;
        }

        private void WriteCharacterString(Asn1Tag tag, Text.Encoding encoding, ReadOnlySpan<char> str)
        {
            if (RuleSet == AsnEncodingRules.BER)
            {
                // Clear the constructed tag, if present.
                tag = new Asn1Tag(tag.TagClass, tag.TagValue);
            }
            else if (RuleSet == AsnEncodingRules.DER && tag.IsConstructed)
            {
                // TODO: Spec-ID?
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }
            else
            {
                // TODO: Didn't this get spanified?
                unsafe
                {
                    fixed (char* strPtr = &str.DangerousGetPinnableReference())
                    {
                        int size = encoding.GetByteCount(strPtr, str.Length);

                        if (size > AsnReader.MaxCERSegmentSize)
                        {
                            WriteCERCharacterString(tag, encoding, str);
                            return;
                        }
                    }
                }

                // It fit in a primitive segment, so clear the constructed tag, if present.
                tag = new Asn1Tag(tag.TagClass, tag.TagValue);
            }

            // TODO: Didn't this get spanified?
            unsafe
            {
                fixed (char* strPtr = &str.DangerousGetPinnableReference())
                {
                    int size = encoding.GetByteCount(strPtr, str.Length);

                    WriteTag(tag);
                    WriteLength(size);
                    Span<byte> dest = _buffer.AsSpan().Slice(_offset, size);

                    fixed (byte* destPtr = &dest.DangerousGetPinnableReference())
                    {
                        int written = encoding.GetBytes(strPtr, str.Length, destPtr, dest.Length);

                        if (written != size)
                        {
                            Debug.Fail($"Encoding produced different answer for GetByteCount ({size}) and GetBytes ({written})");
                            throw new InvalidOperationException();
                        }
                    }

                    _offset += size;
                }
            }
        }

        private void WriteCERCharacterString(Asn1Tag tag, Text.Encoding encoding, ReadOnlySpan<char> str)
        {
            byte[] tmp;
            int size;

            // TODO: Didn't this get spanified?
            unsafe
            {
                fixed (char* strPtr = &str.DangerousGetPinnableReference())
                {
                    size = encoding.GetByteCount(strPtr, str.Length);
                    tmp = ArrayPool<byte>.Shared.Rent(size);

                    fixed (byte* destPtr = tmp)
                    {
                        int written = encoding.GetBytes(strPtr, str.Length, destPtr, tmp.Length);

                        if (written != size)
                        {
                            Debug.Fail(
                                $"Encoding produced different answer for GetByteCount ({size}) and GetBytes ({written})");
                            throw new InvalidOperationException();
                        }
                    }
                }
            }

            WriteCEROctetString(tag, tmp.AsSpan().Slice(0, size));
            Array.Clear(tmp, 0, size);
            ArrayPool<byte>.Shared.Return(tmp);
        }

        private int WriteLeastSigificantDigitAndShift(int value, int offset)
        {
            Debug.Assert(offset >= _offset);

            int div = Math.DivRem(value, 10, out int rem);

            const byte Char0 = (byte)'0';
            _buffer[offset] = (byte)(Char0 + rem);
            return div;
        }

        private static void Reverse(Span<byte> span)
        {
            int i = 0;
            int j = span.Length - 1;

            while (i < j)
            {
                byte tmp = span[i];
                span[i] = span[j];
                span[j] = tmp;

                i++;
                j--;
            }
        }
    }
}
