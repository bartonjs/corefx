using System.Collections.Generic;
using System.Diagnostics;

namespace System.Text.Json
{
    public readonly struct JsonElement
    {
        private readonly JsonDocument _parent;
        private readonly int _idx;

        internal JsonElement(JsonDocument parent, int idx)
        {
            _parent = parent;
            _idx = idx;
        }

        public JsonTokenType Type => _parent?.GetJsonTokenType(_idx) ?? JsonTokenType.None;

        public JsonElement this[int index]
        {
            get
            {
                if (_parent == null)
                {
                    throw new InvalidOperationException();
                }

                return _parent.GetArrayIndexElement(_idx, index);
            }
        }

        public JsonElement this[string propertyName]
        {
            get
            {
                if (propertyName == null)
                    throw new ArgumentNullException(nameof(propertyName));

                return this[propertyName.AsSpan()];
            }
        }

        public JsonElement this[ReadOnlySpan<char> propertyName]
        {
            get
            {
                if (_parent == null)
                {
                    throw new InvalidOperationException();
                }

                if (!_parent.TryGetNamedPropertyValue(_idx, propertyName, out JsonElement value))
                {
                    throw new KeyNotFoundException();
                }

                return value;
            }
        }

        public JsonElement this[ReadOnlySpan<byte> utf8PropertyName]
        {
            get
            {
                if (_parent == null)
                {
                    throw new InvalidOperationException();
                }

                if (!_parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out JsonElement value))
                {
                    throw new KeyNotFoundException();
                }

                return value;
            }
        }

        public int GetArrayLength()
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.GetArrayLength(_idx);
        }

        public bool TryGetProperty(string propertyName, out JsonElement value)
        {
            if (propertyName == null)
                throw new ArgumentNullException(nameof(propertyName));

            return TryGetProperty(propertyName.AsSpan(), out value);
        }

        public bool TryGetProperty(ReadOnlySpan<char> propertyName, out JsonElement value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetNamedPropertyValue(_idx, propertyName, out value);
        }

        public bool TryGetProperty(ReadOnlySpan<byte> utf8PropertyName, out JsonElement value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out value);
        }

        /// <summary>
        ///   Attempts to get the unprocessed memory contributing to the value of this element.
        /// </summary>
        /// <param name="rawValue">
        ///   Receives the unprocessed memory contributing to the value of this element.
        /// </param>
        /// <returns>
        ///   <c>true</c> if the parent <see cref="JsonDocument"/> was built from UTF-8 data,
        ///   and the entirety of the value for this element is in contiguous memory.
        /// </returns>
        /// <seealso cref="Utf8JsonReader.ValueSpan"/>
        public bool TryGetRawValue(out ReadOnlyMemory<byte> rawValue)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            // This method is try, but calls a non-try, because in the future
            // JsonDocument and JsonElement may support non-contiguous and/or
            // differently-encoded data.  JsonDocument's version of this method
            // would likewise become Try when that happens.
            rawValue = _parent.GetRawValue(_idx);
            return true;
        }

        /// <summary>
        ///   Attempt to copy the uninterpreted memory contributing to the value of this element
        ///   into <paramref name="destination"/> as UTF-8 code units.
        /// </summary>
        /// <param name="destination">
        ///   Buffer into which the uninterpreted value should be copied.
        /// </param>
        /// <param name="bytesWritten">
        ///   Receives the number of bytes written to <paramref name="destination"/>.
        /// </param>
        /// <returns>
        ///   <c>true</c> if <paramref name="destination"/> was big enough to receive the UTF-8
        ///   version of the uninterpreted element value, <c>false</c> otherwise.
        /// </returns>
        public bool TryCopyRawValue(Span<byte> destination, out int bytesWritten)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            // If non-contiguous memory is supported by JsonDocument, this method should determine
            // the total byte count and then write to destination.
            //
            // If non-UTF-8 encodings are supported by JsonDocument, this method should transcode.

            ReadOnlyMemory<byte> rawData = _parent.GetRawValue(_idx);

            if (rawData.Length > destination.Length)
            {
                bytesWritten = 0;
                return false;
            }

            rawData.Span.CopyTo(destination);
            bytesWritten = rawData.Length;
            return true;
        }

        public bool GetBoolean()
        {
            JsonTokenType type = Type;

            return
                type == JsonTokenType.True ? true :
                type == JsonTokenType.False ? false :
                throw new InvalidOperationException();
        }

        public string GetString()
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.GetString(_idx);
        }

        public bool TryGetValue(out int value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetValue(_idx, out value);
        }

        public int GetInt32()
        {
            if (TryGetValue(out int value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetValue(out long value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetValue(_idx, out value);
        }

        public long GetInt64()
        {
            if (TryGetValue(out long value))
            {
                return value;
            }

            throw new FormatException();
        }

        [CLSCompliant(false)]
        public bool TryGetValue(out ulong value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetValue(_idx, out value);
        }

        [CLSCompliant(false)]
        public ulong GetUInt64()
        {
            if (TryGetValue(out ulong value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetValue(out double value)
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetValue(_idx, out value);
        }

        public double GetDouble()
        {
            if (TryGetValue(out double value))
            {
                return value;
            }

            throw new FormatException();
        }

        public ChildEnumerator EnumerateChildren()
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return new ChildEnumerator(this);
        }

        public override string ToString()
        {
            switch (Type)
            {
                case JsonTokenType.None:
                case JsonTokenType.Null:
                    return string.Empty;
                case JsonTokenType.True:
                    return bool.TrueString;
                case JsonTokenType.False:
                    return bool.FalseString;
                case JsonTokenType.Number:
                case JsonTokenType.StartArray:
                case JsonTokenType.StartObject:
                case JsonTokenType.Comment:
                {
                    // null parent should have hit the None case
                    Debug.Assert(_parent != null);
                    return _parent.GetRawValueAsString(_idx);
                }
                case JsonTokenType.PropertyName:
                case JsonTokenType.String:
                    return GetString();
                case JsonTokenType.EndArray:
                case JsonTokenType.EndObject:
                default:
                    Debug.Fail($"No handler for {nameof(JsonTokenType)}.{Type}");
                    return string.Empty;
            }
        }

        public struct ChildEnumerator
        {
            private JsonElement _target;
            public JsonElement Current { get; private set; }
            private readonly int _endIdx;

            internal ChildEnumerator(JsonElement target)
            {
                _target = target;
                Current = default;
                _endIdx = _target._parent.GetEndIndex(_target._idx, includeEndElement: false);
            }

            public ChildEnumerator GetEnumerator()
            {
                ChildEnumerator ator = this;
                ator.Current = default;
                return ator;
            }

            public bool MoveNext()
            {
                if (Current._idx >= _endIdx)
                    return false;

                int nextIdx;

                if (Current._parent == null)
                {
                    nextIdx = _target._idx + JsonDocument.DbRow.Size;
                }
                else
                {
                    nextIdx = _target._parent.GetEndIndex(Current._idx, includeEndElement: true);
                }

                if (nextIdx >= _endIdx)
                {
                    Current = default;
                    return false;
                }

                Current = new JsonElement(_target._parent, nextIdx);
                return true;
            }
        }
    }
}
