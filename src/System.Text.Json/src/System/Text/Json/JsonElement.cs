using System.Collections.Generic;
using System.Diagnostics;

namespace System.Text.Json
{
    public struct JsonElement
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

        public bool TryGetRawData<T>(out ReadOnlyMemory<T> rawData) where T : struct
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }

            return _parent.TryGetRawData(_idx, out rawData);
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
                    Debug.Assert(_parent == null);
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

        public static explicit operator bool(JsonElement element) => element.GetBoolean();
        public static explicit operator string(JsonElement element) => element.GetString();
        public static explicit operator int(JsonElement element) => element.GetInt32();
        public static explicit operator long(JsonElement element) => element.GetInt64();
        [CLSCompliant(false)]
        public static explicit operator ulong(JsonElement element) => element.GetUInt64();
        public static explicit operator double(JsonElement element) => element.GetDouble();

        public struct ChildEnumerator
        {
            private JsonElement _target;
            public JsonElement Current { get; private set; }
            private readonly int _endIdx;

            internal ChildEnumerator(JsonElement target)
            {
                _target = target;
                Current = default;
                _endIdx = _target._parent.GetEndIndex(_target._idx);
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
                    nextIdx = _target._parent.GetEndIndex(Current._idx);
                }

                if (nextIdx >= _endIdx)
                {
                    Current = default;
                    return false;
                }

                if (_target.Type == JsonTokenType.StartObject)
                {
                    // Property name
                    Debug.Assert(_target._parent.GetJsonTokenType(nextIdx) == JsonTokenType.String);
                    nextIdx += JsonDocument.DbRow.Size;

                    if (nextIdx >= _endIdx)
                    {
                        Debug.Fail($"Unbalanced database, property had no value at {nextIdx}");
                        Current = default;
                        return false;
                    }
                }

                Current = new JsonElement(_target._parent, nextIdx);
                return true;
            }
        }
    }
}
