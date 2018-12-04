// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using System.IO;
using Xunit;

namespace System.Text.Json.Tests
{
    public static class JsonDocumentTests
    {
        public static IEnumerable<object[]> TestCases
        {
            get
            {
                return new List<object[]>
                {
                    new object[] { true, Tests.TestCaseType.Basic, SR.BasicJson},
                    new object[] { true, Tests.TestCaseType.BasicLargeNum, SR.BasicJsonWithLargeNum}, // Json.NET treats numbers starting with 0 as octal (0425 becomes 277)
                    new object[] { true, Tests.TestCaseType.BroadTree, SR.BroadTree}, // \r\n behavior is different between Json.NET and System.Text.Json
                    new object[] { true, Tests.TestCaseType.DeepTree, SR.DeepTree},
                    new object[] { true, Tests.TestCaseType.FullSchema1, SR.FullJsonSchema1},
                    new object[] { true, Tests.TestCaseType.HelloWorld, SR.HelloWorld},
                    new object[] { true, Tests.TestCaseType.LotsOfNumbers, SR.LotsOfNumbers},
                    new object[] { true, Tests.TestCaseType.LotsOfStrings, SR.LotsOfStrings},
                    new object[] { true, Tests.TestCaseType.ProjectLockJson, SR.ProjectLockJson},
                    new object[] { true, Tests.TestCaseType.Json400B, SR.Json400B},
                    new object[] { true, Tests.TestCaseType.Json4KB, SR.Json4KB},
                    new object[] { true, Tests.TestCaseType.Json40KB, SR.Json40KB},
                    new object[] { true, Tests.TestCaseType.Json400KB, SR.Json400KB},

                    new object[] { false, Tests.TestCaseType.Basic, SR.BasicJson},
                    new object[] { false, Tests.TestCaseType.BasicLargeNum, SR.BasicJsonWithLargeNum}, // Json.NET treats numbers starting with 0 as octal (0425 becomes 277)
                    new object[] { false, Tests.TestCaseType.BroadTree, SR.BroadTree}, // \r\n behavior is different between Json.NET and System.Text.Json
                    new object[] { false, Tests.TestCaseType.DeepTree, SR.DeepTree},
                    new object[] { false, Tests.TestCaseType.FullSchema1, SR.FullJsonSchema1},
                    new object[] { false, Tests.TestCaseType.HelloWorld, SR.HelloWorld},
                    new object[] { false, Tests.TestCaseType.LotsOfNumbers, SR.LotsOfNumbers},
                    new object[] { false, Tests.TestCaseType.LotsOfStrings, SR.LotsOfStrings},
                    new object[] { false, Tests.TestCaseType.ProjectLockJson, SR.ProjectLockJson},
                    new object[] { false, Tests.TestCaseType.Json400B, SR.Json400B},
                    new object[] { false, Tests.TestCaseType.Json4KB, SR.Json4KB},
                    new object[] { false, Tests.TestCaseType.Json40KB, SR.Json40KB},
                    new object[] { false, Tests.TestCaseType.Json400KB, SR.Json400KB},
                };
            }
        }

        // TestCaseType is only used to give the json strings a descriptive name within the unit tests.
        public enum TestCaseType
        {
            HelloWorld,
            Basic,
            BasicLargeNum,
            SpecialNumForm,
            SpecialStrings,
            ProjectLockJson,
            FullSchema1,
            FullSchema2,
            DeepTree,
            BroadTree,
            LotsOfNumbers,
            LotsOfStrings,
            Json400B,
            Json4KB,
            Json40KB,
            Json400KB,
        }

        private static string ReadHelloWorld(JToken obj)
        {
            string message = (string)obj["message"];
            return message;
        }

        private static string ReadJson400KB(JToken obj)
        {
            var sb = new StringBuilder();
            foreach (JToken token in obj)
            {
                sb.Append((string)token["_id"]);
                sb.Append((int)token["index"]);
                sb.Append((string)token["guid"]);
                sb.Append((bool)token["isActive"]);
                sb.Append((string)token["balance"]);
                sb.Append((string)token["picture"]);
                sb.Append((int)token["age"]);
                sb.Append((string)token["eyeColor"]);
                sb.Append((string)token["name"]);
                sb.Append((string)token["gender"]);
                sb.Append((string)token["company"]);
                sb.Append((string)token["email"]);
                sb.Append((string)token["phone"]);
                sb.Append((string)token["address"]);
                sb.Append((string)token["about"]);
                sb.Append((string)token["registered"]);
                sb.Append((double)token["latitude"]);
                sb.Append((double)token["longitude"]);

                JToken tags = token["tags"];
                foreach (JToken tag in tags)
                {
                    sb.Append((string)tag);
                }
                JToken friends = token["friends"];
                foreach (JToken friend in friends)
                {
                    sb.Append((int)friend["id"]);
                    sb.Append((string)friend["name"]);
                }
                sb.Append((string)token["greeting"]);
                sb.Append((string)token["favoriteFruit"]);

            }
            return sb.ToString();
        }

        private static string ReadHelloWorld(JsonElement obj)
        {
            string message = (string)obj["message"];
            return message;
        }

        private static string ReadJson400KB(JsonElement obj)
        {
            var sb = new StringBuilder();
            int length = obj.GetArrayLength();
            for (int i = 0; i < length; i++)
            {
                sb.Append((string)obj[i]["_id"]);
                sb.Append((int)obj[i]["index"]);
                sb.Append((string)obj[i]["guid"]);
                sb.Append((bool)obj[i]["isActive"]);
                sb.Append((string)obj[i]["balance"]);
                sb.Append((string)obj[i]["picture"]);
                sb.Append((int)obj[i]["age"]);
                sb.Append((string)obj[i]["eyeColor"]);
                sb.Append((string)obj[i]["name"]);
                sb.Append((string)obj[i]["gender"]);
                sb.Append((string)obj[i]["company"]);
                sb.Append((string)obj[i]["email"]);
                sb.Append((string)obj[i]["phone"]);
                sb.Append((string)obj[i]["address"]);
                sb.Append((string)obj[i]["about"]);
                sb.Append((string)obj[i]["registered"]);
                sb.Append((double)obj[i]["latitude"]);
                sb.Append((double)obj[i]["longitude"]);

                JsonElement tags = obj[i]["tags"];
                for (int j = 0; j < tags.GetArrayLength(); j++)
                {
                    sb.Append((string)tags[j]);
                }
                JsonElement friends = obj[i]["friends"];
                for (int j = 0; j < friends.GetArrayLength(); j++)
                {
                    sb.Append((int)friends[j]["id"]);
                    sb.Append((string)friends[j]["name"]);
                }
                sb.Append((string)obj[i]["greeting"]);
                sb.Append((string)obj[i]["favoriteFruit"]);
            }
            return sb.ToString();
        }

        // TestCaseType is only used to give the json strings a descriptive name.
        [Theory]
        [MemberData(nameof(TestCases))]
        public static void ParseJson(bool compactData, TestCaseType type, string jsonString)
        {
            // Remove all formatting/indendation
            if (compactData)
            {
                using (JsonTextReader jsonReader = new JsonTextReader(new StringReader(jsonString)))
                {
                    jsonReader.FloatParseHandling = FloatParseHandling.Decimal;
                    JToken jtoken = JToken.ReadFrom(jsonReader);
                    var stringWriter = new StringWriter();
                    using (JsonTextWriter jsonWriter = new JsonTextWriter(stringWriter))
                    {
                        jtoken.WriteTo(jsonWriter);
                        jsonString = stringWriter.ToString();
                    }
                }
            }

            byte[] dataUtf8 = Encoding.UTF8.GetBytes(jsonString);

            using (JsonDocument doc = JsonDocument.Parse(dataUtf8, default))
            {
                using (var stream = new MemoryStream(dataUtf8))
                using (var streamReader = new StreamReader(stream, Encoding.UTF8, false, 1024, true))
                using (JsonTextReader jsonReader = new JsonTextReader(streamReader))
                {
                    JToken jToken = JToken.ReadFrom(jsonReader);

                    string expectedString = "";
                    string actualString = "";

                    if (type == TestCaseType.Json400KB)
                    {
                        expectedString = ReadJson400KB(jToken);
                        actualString = ReadJson400KB(doc.RootElement);
                    }
                    else if (type == TestCaseType.HelloWorld)
                    {
                        expectedString = ReadHelloWorld(jToken);
                        actualString = ReadHelloWorld(doc.RootElement);
                    }

                    Assert.Equal(expectedString, actualString);
                }

                string actual = doc.PrintJson();

                TextReader reader = new StringReader(jsonString);
                string expected = JsonTestHelper.NewtonsoftReturnStringHelper(reader);

                Assert.Equal(expected, actual);

            }
        }

        private static string PrintJson(this JsonDocument document, int sizeHint=0)
        {
            return PrintJson(document.RootElement, sizeHint);
        }

        private static string PrintJson(this JsonElement element, int sizeHint=0)
        {
            StringBuilder sb = new StringBuilder(sizeHint);
            DepthFirstAppend(sb, element);
            return sb.ToString();
        }

        private static void DepthFirstAppend(StringBuilder buf, JsonElement element)
        {
            JsonTokenType type = element.Type;

            switch (type)
            {
                case JsonTokenType.False:
                case JsonTokenType.True:
                case JsonTokenType.String:
                case JsonTokenType.Comment:
                case JsonTokenType.Number:
                case JsonTokenType.PropertyName:
                {
                    buf.Append(element.ToString());
                    buf.Append(", ");
                    break;
                }
                case JsonTokenType.StartArray:
                case JsonTokenType.StartObject:
                {
                    foreach (JsonElement child in element.EnumerateChildren())
                    {
                        DepthFirstAppend(buf, child);
                    }

                    break;
                }
            }
        }

        [Theory]
        [InlineData("[{\"arrayWithObjects\":[\"text\",14,[],null,false,{},{\"time\":24},[\"1\",\"2\",\"3\"]]}]")]
        [InlineData("[{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]")]
        [InlineData("[{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}},{\"a\":{}}]")]
        [InlineData("{\"a\":\"b\"}")]
        [InlineData("{}")]
        [InlineData("[]")]
        public static void CustomParseJson(string jsonString)
        {
            byte[] dataUtf8 = Encoding.UTF8.GetBytes(jsonString);

            using (JsonDocument doc = JsonDocument.Parse(dataUtf8, default))
            {
                string actual = doc.PrintJson();

                TextReader reader = new StringReader(jsonString);
                string expected = JsonTestHelper.NewtonsoftReturnStringHelper(reader);

                Assert.Equal(expected, actual);
            }
        }

        [Fact]
        public static void ParseArray()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.SimpleArrayJson, 60);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement root = doc.RootElement;

                Assert.Equal(2, root.GetArrayLength());

                var phoneNumber = (string)root[0];
                var age = (int)root[1];

                Assert.Equal("425-214-3151", phoneNumber);
                Assert.Equal(25, age);

                Assert.Throws<IndexOutOfRangeException>(() => root[2]);
            }
        }

        [Fact]
        public static void ParseSimpleObject()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.SimpleObjectJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;

                var age = (int)parsedObject["age"];
                var ageString = parsedObject["age"].ToString();
                var first = (string)parsedObject["first"];
                var last = (string)parsedObject["last"];
                var phoneNumber = (string)parsedObject["phoneNumber"];
                var street = (string)parsedObject["street"];
                var city = (string)parsedObject["city"];
                var zip = (int)parsedObject["zip"];

                Assert.True(parsedObject.TryGetProperty("age", out JsonElement age2));
                Assert.Equal((int)age2, 30);

                Assert.Equal(age, 30);
                Assert.Equal(ageString, "30");
                Assert.Equal(first, "John");
                Assert.Equal(last, "Smith");
                Assert.Equal(phoneNumber, "425-214-3151");
                Assert.Equal(street, "1 Microsoft Way");
                Assert.Equal(city, "Redmond");
                Assert.Equal(zip, 98052);
            }
        }

        [Fact]
        public static void ParseNestedJson()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace(SR.ParseJson);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;

                Assert.Equal(1, parsedObject.GetArrayLength());
                var person = parsedObject[0];
                var age = (double)person["age"];
                var first = (string)person["first"];
                var last = (string)person["last"];
                var phoneNums = person["phoneNumbers"];
                Assert.Equal(2, phoneNums.GetArrayLength());
                var phoneNum1 = (string)phoneNums[0];
                var phoneNum2 = (string)phoneNums[1];
                var address = person["address"];
                var street = (string)address["street"];
                var city = (string)address["city"];
                var zipCode = (double)address["zip"];

                Assert.Equal(30, age);
                Assert.Equal("John", first);
                Assert.Equal("Smith", last);
                Assert.Equal("425-000-1212", phoneNum1);
                Assert.Equal("425-000-1213", phoneNum2);
                Assert.Equal("1 Microsoft Way", street);
                Assert.Equal("Redmond", city);
                Assert.Equal(98052, zipCode);

                Assert.Throws<InvalidOperationException>(() => person.GetArrayLength());
                Assert.Throws<IndexOutOfRangeException>(() => phoneNums[2]);
                Assert.Throws<InvalidOperationException>(() => phoneNums["2"]);
                Assert.Throws<KeyNotFoundException>(() => address["2"]);
                Assert.Throws<InvalidOperationException>(() => (double)address["city"]);
                Assert.Throws<InvalidOperationException>(() => (bool)address["city"]);
                Assert.Throws<InvalidOperationException>(() => (string)address["zip"]);
                Assert.Throws<InvalidOperationException>(() => (string)person["phoneNumbers"]);
                Assert.Throws<InvalidOperationException>(() => (string)person);
            }
        }

        [Fact]
        public static void ParseBoolean()
        {
            ArraySegment<byte> buffer = StringToUtf8BufferWithEmptySpace("[true,false]", 60);

            using (JsonDocument doc = JsonDocument.Parse(buffer, default))
            {
                JsonElement parsedObject = doc.RootElement;
                var first = (bool)parsedObject[0];
                var second = (bool)parsedObject[1];
                Assert.Equal(true, first);
                Assert.Equal(false, second);
            }
        }

        private static ArraySegment<byte> StringToUtf8BufferWithEmptySpace(string testString, int emptySpaceSize = 2048)
        {
            int expectedLength = Encoding.UTF8.GetByteCount(testString);
            var buffer = new byte[expectedLength + emptySpaceSize];
            int actualLength = Encoding.UTF8.GetBytes(testString, buffer.AsSpan());
            
            return new ArraySegment<byte>(buffer, 0, actualLength);
        }
    }
}
