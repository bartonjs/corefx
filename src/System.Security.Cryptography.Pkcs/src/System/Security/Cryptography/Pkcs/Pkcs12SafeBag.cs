// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.Pkcs
{
    public abstract class Pkcs12SafeBag
    {
        private readonly string _bagIdValue;
        private Oid _bagOid;
        private CryptographicAttributeObjectCollection _attributes;

        public CryptographicAttributeObjectCollection Attributes
        {
            get
            {
                if (_attributes == null)
                {
                    _attributes = new CryptographicAttributeObjectCollection();
                }

                return _attributes;
            }

            internal set
            {
                Debug.Assert(value != null);
                _attributes = value;
            }
        }

        protected Pkcs12SafeBag(string bagIdValue)
        {
            if (string.IsNullOrEmpty(bagIdValue))
                throw new ArgumentNullException(nameof(bagIdValue));

            _bagIdValue = bagIdValue;
        }

        public byte[] Encode()
        {
            using (AsnWriter writer = EncodeToWriter())
            {
                return writer.Encode();
            }
        }

        public Oid GetBagId()
        {
            if (_bagOid == null)
            {
                _bagOid = new Oid(_bagIdValue);
            }

            return new Oid(_bagOid);
        }

        public bool TryEncode(Span<byte> destination, out int bytesWritten)
        {
            using (AsnWriter writer = EncodeToWriter())
            {
                ReadOnlySpan<byte> encoded = writer.EncodeAsSpan();

                if (destination.Length < encoded.Length)
                {
                    bytesWritten = 0;
                    return false;
                }

                encoded.CopyTo(destination);
                bytesWritten = encoded.Length;
                return true;
            }
        }

        private AsnWriter EncodeToWriter()
        {
            byte[] rented = ArrayPool<byte>.Shared.Rent(4096);
            Memory<byte> valueMemory = default;

            AsnWriter writer = null;
            try
            {
                int valueBytesWritten;

                while (!TryEncodeValue(rented, out valueBytesWritten))
                {
                    byte[] newRented = ArrayPool<byte>.Shared.Rent(rented.Length * 2);
                    ArrayPool<byte>.Shared.Return(rented);
                    rented = newRented;
                }

                valueMemory = rented.AsMemory(0, valueBytesWritten);

                writer = new AsnWriter(AsnEncodingRules.BER);
                writer.PushSequence();

                writer.WriteObjectIdentifier(_bagIdValue);

                Asn1Tag contextSpecific0 = new Asn1Tag(TagClass.ContextSpecific, 0);
                writer.PushSequence(contextSpecific0);
                writer.WriteEncodedValue(valueMemory);
                writer.PopSequence(contextSpecific0);

                if (_attributes?.Count > 0)
                {
                    List<AttributeAsn> attrs = CmsSigner.BuildAttributes(_attributes);

                    writer.PushSetOf();

                    foreach (AttributeAsn attr in attrs)
                    {
                        writer.PushSequence();
                        writer.WriteObjectIdentifier(attr.AttrType);
                        writer.WriteEncodedValue(attr.AttrValues);
                        writer.PopSequence();
                    }

                    writer.PopSetOf();
                }

                writer.PopSequence();
                return writer;
            }
            catch
            {
                writer?.Dispose();
                throw;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(valueMemory.Span);
                ArrayPool<byte>.Shared.Return(rented);
            }
        }

        protected abstract bool TryEncodeValue(Span<byte> destination, out int bytesWritten);
    }
}
