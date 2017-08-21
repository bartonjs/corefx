// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;

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

    internal struct AsnReader
    {
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
    }
}
