// Licensed to the .NET Foundation under one or more agreements.
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

        public JsonTokenType Type => _parent?.GetJsonTokenType(_idx) ?? JsonTokenType.None;

        public JsonElement this[int index]
        {
            get
            {
                CheckValidInstance();

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
                CheckValidInstance();

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
                CheckValidInstance();

                if (!_parent.TryGetNamedPropertyValue(_idx, utf8PropertyName, out JsonElement value))
                {
                    throw new KeyNotFoundException();
                }

                return value;
            }
        }

        public int GetArrayLength()
        {
            CheckValidInstance();

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

            JsonTokenType type = Type;

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

        public bool TryGetValue(out int value)
        {
            CheckValidInstance();

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
            CheckValidInstance();

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
            CheckValidInstance();

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
            CheckValidInstance();

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

        internal string GetPropertyName()
        {
            CheckValidInstance();

            return _parent.GetNameOfPropertyValue(_idx);
        }

        public ArrayEnumerator EnumerateArray()
        {
            CheckValidInstance();

            if (Type != JsonTokenType.StartArray)
            {
                throw new InvalidOperationException();
            }

            return new ArrayEnumerator(this);
        }

        public ObjectEnumerator EnumerateObject()
        {
            CheckValidInstance();

            if (Type != JsonTokenType.StartObject)
            {
                throw new InvalidOperationException();
            }

            return new ObjectEnumerator(this);
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
                {
                    // null parent should have hit the None case
                    Debug.Assert(_parent != null);
                    return _parent.PrettyPrintProperty(_idx);
                }
                case JsonTokenType.String:
                    return GetString();
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
                Debug.Assert(target.Type == JsonTokenType.StartArray);

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
                Debug.Assert(target.Type == JsonTokenType.StartObject);

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
