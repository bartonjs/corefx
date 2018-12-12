// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Text.Json
{
    public struct JsonProperty
    {
        private string _name;
        public JsonElement Value { get; }

        internal JsonProperty(JsonElement value)
        {
            _name = null;
            Value = value;
        }

        public string Name
        {
            get
            {
                if (_name == null)
                {
                    _name = Value.GetPropertyName();
                }

                return _name;
            }
        }
    }
}
