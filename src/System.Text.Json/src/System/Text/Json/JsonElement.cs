﻿// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
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

        internal JsonTokenType TokenType => _parent?.GetJsonTokenType(_idx) ?? JsonTokenType.None;

        public JsonValueType Type
        {
            get
            {
                JsonTokenType tokenType = TokenType;

                switch (tokenType)
                {
                    case JsonTokenType.None:
                        return JsonValueType.Undefined;
                    case JsonTokenType.StartArray:
                        return JsonValueType.Array;
                    case JsonTokenType.StartObject:
                        return JsonValueType.Object;
                    case JsonTokenType.String:
                    case JsonTokenType.Number:
                    case JsonTokenType.True:
                    case JsonTokenType.False:
                    case JsonTokenType.Null:
                        return (JsonValueType)((byte)tokenType - 3);
                    default:
                        Debug.Fail($"No mapping for token type {tokenType}");
                        return JsonValueType.Undefined;
                }
            }
        }

        public JsonElement this[int index]
        {
            get
            {
                CheckValidInstance();

                return _parent.GetArrayIndexElement(_idx, index);
            }
        }

        public int GetArrayLength()
        {
            CheckValidInstance();

            return _parent.GetArrayLength(_idx);
        }

        public JsonElement GetProperty(string propertyName)
        {
            if (propertyName == null)
                throw new ArgumentNullException(nameof(propertyName));

            if (TryGetProperty(propertyName, out JsonElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        public JsonElement GetProperty(ReadOnlySpan<char> propertyName)
        {
            if (TryGetProperty(propertyName, out JsonElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        public JsonElement GetProperty(ReadOnlySpan<byte> utf8PropertyName)
        {
            if (TryGetProperty(utf8PropertyName, out JsonElement property))
            {
                return property;
            }

            throw new KeyNotFoundException();
        }

        public bool TryGetProperty(string propertyName, out JsonElement value)
        {
            if (propertyName == null)
                throw new ArgumentNullException(nameof(propertyName));

            return TryGetProperty(propertyName.AsSpan(), out value);
        }

        public bool TryGetProperty(ReadOnlySpan<char> propertyName, out JsonElement value)
        {
            CheckValidInstance();

            return _parent.TryGetNamedPropertyValue(_idx, propertyName, out value);
        }

        public bool TryGetProperty(ReadOnlySpan<byte> utf8PropertyName, out JsonElement value)
        {
            CheckValidInstance();

            return _parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out value);
        }
        
        public bool GetBoolean()
        {
            // CheckValidInstance is redundant.  Asking for the type will
            // return None, which then throws the same exception in the return statement.

            JsonTokenType type = TokenType;

            return
                type == JsonTokenType.True ? true :
                type == JsonTokenType.False ? false :
                throw new InvalidOperationException();
        }

        public string GetString()
        {
            CheckValidInstance();

            return _parent.GetString(_idx, JsonTokenType.String);
        }

        public bool TryGetInt32(out int value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public int GetInt32()
        {
            if (TryGetInt32(out int value))
            {
                return value;
            }

            throw new FormatException();
        }

        [CLSCompliant(false)]
        public bool TryGetUInt32(out uint value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        [CLSCompliant(false)]
        public uint GetUInt32()
        {
            if (TryGetUInt32(out uint value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetInt64(out long value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public long GetInt64()
        {
            if (TryGetInt64(out long value))
            {
                return value;
            }

            throw new FormatException();
        }

        [CLSCompliant(false)]
        public bool TryGetUInt64(out ulong value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        [CLSCompliant(false)]
        public ulong GetUInt64()
        {
            if (TryGetUInt64(out ulong value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetDouble(out double value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public double GetDouble()
        {
            if (TryGetDouble(out double value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetSingle(out float value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public float GetSingle()
        {
            if (TryGetSingle(out float value))
            {
                return value;
            }

            throw new FormatException();
        }

        public bool TryGetDecimal(out decimal value)
        {
            CheckValidInstance();

            return _parent.TryGetValue(_idx, out value);
        }

        public decimal GetDecimal()
        {
            if (TryGetDecimal(out decimal value))
            {
                return value;
            }

            throw new FormatException();
        }

        internal string GetPropertyName()
        {
            CheckValidInstance();

            return _parent.GetNameOfPropertyValue(_idx);
        }

        public string GetRawText()
        {
            CheckValidInstance();

            return _parent.GetRawValueAsString(_idx);
        }

        internal string GetPropertyRawText()
        {
            CheckValidInstance();

            return _parent.GetPropertyRawValueAsString(_idx);
        }

        public ArrayEnumerator EnumerateArray()
        {
            CheckValidInstance();

            if (TokenType != JsonTokenType.StartArray)
            {
                throw new InvalidOperationException();
            }

            return new ArrayEnumerator(this);
        }

        public ObjectEnumerator EnumerateObject()
        {
            CheckValidInstance();

            if (TokenType != JsonTokenType.StartObject)
            {
                throw new InvalidOperationException();
            }

            return new ObjectEnumerator(this);
        }

        public override string ToString()
        {
            switch (TokenType)
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
                {
                    // null parent should have hit the None case
                    Debug.Assert(_parent != null);
                    return _parent.GetRawValueAsString(_idx);
                }
                case JsonTokenType.String:
                    return GetString();
                case JsonTokenType.Comment:
                case JsonTokenType.EndArray:
                case JsonTokenType.EndObject:
                default:
                    Debug.Fail($"No handler for {nameof(JsonTokenType)}.{Type}");
                    return string.Empty;
            }
        }

        private void CheckValidInstance()
        {
            if (_parent == null)
            {
                throw new InvalidOperationException();
            }
        }

        public struct ArrayEnumerator : IEnumerable<JsonElement>, IEnumerator<JsonElement>
        {
            private readonly JsonElement _target;
            private int _curIdx;
            private readonly int _endIdx;

            internal ArrayEnumerator(JsonElement target)
            {
                Debug.Assert(target.TokenType == JsonTokenType.StartArray);

                _target = target;
                _curIdx = -1;
                _endIdx = _target._parent.GetEndIndex(_target._idx, includeEndElement: false);
            }

            public JsonElement Current =>
                _curIdx < 0 ? default : new JsonElement(_target._parent, _curIdx);

            public ArrayEnumerator GetEnumerator()
            {
                ArrayEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

            IEnumerator<JsonElement> IEnumerable<JsonElement>.GetEnumerator() => GetEnumerator();

            public void Dispose()
            {
                _curIdx = _endIdx;
            }

            public void Reset()
            {
                _curIdx = -1;
            }

            object IEnumerator.Current => Current;

            public bool MoveNext()
            {
                if (_curIdx >= _endIdx)
                    return false;

                if (_curIdx < 0)
                {
                    _curIdx = _target._idx + JsonDocument.DbRow.Size;
                }
                else
                {
                    _curIdx = _target._parent.GetEndIndex(_curIdx, includeEndElement: true);
                }

                return _curIdx < _endIdx;
            }
        }

        public struct ObjectEnumerator : IEnumerable<JsonProperty>, IEnumerator<JsonProperty>
        {
            private readonly JsonElement _target;
            private int _curIdx;
            private readonly int _endIdx;

            internal ObjectEnumerator(JsonElement target)
            {
                Debug.Assert(target.TokenType == JsonTokenType.StartObject);

                _target = target;
                _curIdx = -1;
                _endIdx = _target._parent.GetEndIndex(_target._idx, includeEndElement: false);
            }

            public JsonProperty Current =>
                _curIdx < 0 ?
                    default :
                    new JsonProperty(new JsonElement(_target._parent, _curIdx));

            public ObjectEnumerator GetEnumerator()
            {
                ObjectEnumerator ator = this;
                ator._curIdx = -1;
                return ator;
            }

            IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

            IEnumerator<JsonProperty> IEnumerable<JsonProperty>.GetEnumerator() => GetEnumerator();

            public void Dispose()
            {
                _curIdx = _endIdx;
            }

            public void Reset()
            {
                _curIdx = -1;
            }

            object IEnumerator.Current => Current;

            public bool MoveNext()
            {
                if (_curIdx >= _endIdx)
                    return false;

                if (_curIdx < 0)
                {
                    _curIdx = _target._idx + JsonDocument.DbRow.Size;
                }
                else
                {
                    _curIdx = _target._parent.GetEndIndex(_curIdx, includeEndElement: true);
                }

                // _curIdx is now pointing at a property name, move one more to get the value
                _curIdx += JsonDocument.DbRow.Size;

                return _curIdx < _endIdx;
            }
        }
    }
}
