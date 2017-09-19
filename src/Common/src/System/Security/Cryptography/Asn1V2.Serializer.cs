// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Threading;

namespace System.Security.Cryptography.Asn1
{
    internal class AsnSerializationConstraintException : CryptographicException
    {
        public AsnSerializationConstraintException()
        {
        }

        public AsnSerializationConstraintException(string message)
            : base(message)
        {
        }

        public AsnSerializationConstraintException(string message, Exception inner)
            : base(message, inner)
        {
        }
    }

    internal class AsnAmbiguousFieldTypeException : AsnSerializationConstraintException
    {
        public AsnAmbiguousFieldTypeException(FieldInfo fieldInfo, Type ambiguousType)
            : base($"Field {fieldInfo.Name} of type {fieldInfo.DeclaringType.FullName} has ambiguous type '{ambiguousType.Name}', an attribute derived from {nameof(AsnTypeAttribute)} is required.")
        {
        }
    }

    internal class AsnSerializerInvalidDefaultException : AsnSerializationConstraintException
    {
        internal AsnSerializerInvalidDefaultException()
        {
        }

        internal AsnSerializerInvalidDefaultException(FieldInfo fieldInfo)
            : base($"Field {fieldInfo.Name} of type {fieldInfo.DeclaringType.FullName} has a default value that cannot be read.")
        {
        }

        internal AsnSerializerInvalidDefaultException(Exception innerException)
            : base(String.Empty, innerException)
        {
        }

        internal AsnSerializerInvalidDefaultException(FieldInfo fieldInfo, Exception innerException)
            : base(
                  $"Field {fieldInfo.Name} of type {fieldInfo.DeclaringType.FullName} has a default value that cannot be read.",
                  innerException)
        {
        }
    }

    internal static class AsnSerializer
    {
        private const BindingFlags FieldFlags =
            BindingFlags.Public |
            BindingFlags.NonPublic |
            BindingFlags.Instance;

        private delegate object Deserializer(ref AsnReader reader);
        private delegate bool TryDeserializer<T>(ref AsnReader reader, out T value);

        private static Deserializer TryOrFail<T>(TryDeserializer<T> tryDeserializer)
        {
            return (ref AsnReader reader) =>
            {
                if (tryDeserializer(ref reader, out T value))
                    return value;

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            };
        }

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
                    throw new AsnSerializationConstraintException($"{nameof(ChoiceAttribute)}.{nameof(ChoiceAttribute.AllowNull)} is not valid because type {typeT.FullName} cannot be assigned to null");
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
                    throw new AsnSerializationConstraintException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' can not be assigned a null value.");
                }

                fieldType = UnpackNullable(fieldType);

                if (currentSet.Contains(fieldInfo))
                {
                    throw new AsnSerializationConstraintException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' has introduced a type chain cycle.");
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
                        out _,
                        out _,
                        out Asn1Tag expectedTag);

                    if (defaultContents != null)
                    {
                        // TODO/Review: This might be legal?
                        throw new AsnSerializationConstraintException($"Field '{fieldInfo.Name}' on [{nameof(ChoiceAttribute)}] type '{fieldInfo.DeclaringType.FullName}' has a default value.");
                    }

                    var key = (expectedTag.TagClass, expectedTag.TagValue);

                    if (lookup.TryGetValue(key, out LinkedList<FieldInfo> existingSet))
                    {
                        FieldInfo existing = existingSet.Last.Value;

                        // TODO/Review: Exception type and message?
                        throw new AsnSerializationConstraintException(
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

        private static Deserializer ExplicitValueDeserializer(Deserializer valueDeserializer)
        {
            return (ref AsnReader reader) => ExplicitValueDeserializer(ref reader, valueDeserializer);
        }

        private static object ExplicitValueDeserializer(
            ref AsnReader reader,
            Deserializer valueDeserializer)
        {
            AsnReader innerReader = reader.ReadSequence();
            object val = valueDeserializer(ref innerReader);

            if (innerReader.HasData)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return val;
        }

        private static Deserializer CheckTagDeserializer(Deserializer valueDeserializer, Asn1Tag expectedTag)
        {
            return (ref AsnReader reader) =>
            {
                Asn1Tag actualTag = reader.PeekTag();

                bool isExactMatch =
                    actualTag.TagClass == expectedTag.TagClass &&
                    actualTag.TagValue == expectedTag.TagValue;
                
                // If the actual tag is universal let the value deserializer handle it.
                if (isExactMatch || actualTag.TagClass == TagClass.Universal)
                {
                    return valueDeserializer(ref reader);
                }

                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            };
        }

        private static Deserializer DefaultValueDeserializer(
            Deserializer valueDeserializer,
            bool isOptional,
            byte[] defaultContents,
            UniversalTagNumber tagType,
            Asn1Tag expectedTag)
        {
            return (ref AsnReader reader) =>
                DefaultValueDeserializer(
                    ref reader,
                    expectedTag,
                    tagType,
                    valueDeserializer,
                    defaultContents,
                    isOptional);
        }

        private static object DefaultValueDeserializer(
            ref AsnReader reader,
            Asn1Tag expectedTag,
            UniversalTagNumber tagType,
            Deserializer valueDeserializer,
            byte[] defaultContents,
            bool isOptional)
        {
            if (reader.HasData)
            {
                Asn1Tag actualTag = reader.PeekTag();

                if (actualTag.TagClass == expectedTag.TagClass &&
                    actualTag.TagValue == expectedTag.TagValue)
                {
                    return valueDeserializer(ref reader);
                }
            }

            if (isOptional)
            {
                return null;
            }

            if (defaultContents != null)
            {
                return DefaultValue(defaultContents, valueDeserializer);
            }

            throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
        }

        private static Deserializer GetDeserializer(Type typeT, FieldInfo fieldInfo)
        {
            Deserializer literalValueDeserializer = GetSimpleDeserializer(
                typeT,
                fieldInfo,
                out UniversalTagNumber tagType,
                out byte[] defaultContents,
                out bool isExplicitTag,
                out bool isOptional,
                out Asn1Tag expectedTag);

            Deserializer deserializer = literalValueDeserializer;

            if (isExplicitTag)
            {
                deserializer = ExplicitValueDeserializer(deserializer);
            }

            if (isOptional || defaultContents != null)
            {
                deserializer = DefaultValueDeserializer(deserializer, isOptional, defaultContents, tagType, expectedTag);
            }
            else if (expectedTag != Asn1Tag.EndOfContents)
            {
                deserializer = CheckTagDeserializer(deserializer, expectedTag);
            }

            return deserializer;
        }

        private static Deserializer GetSimpleDeserializer(
            Type typeT,
            FieldInfo fieldInfo,
            out UniversalTagNumber tagType2,
            out byte[] defaultContents,
            out bool isExplicitTag,
            out bool isOptional,
            out Asn1Tag expectedTag)
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
                out defaultContents,
                out isExplicitTag,
                out isOptional,
                out expectedTag);

            tagType2 = tagType;
            typeT = UnpackNullable(typeT);

            if (typeT.IsPrimitive)
            {
                if (wasCustomized)
                {
                    // TODO/Review: Exception type and message?
                    throw new AsnSerializationConstraintException();
                }

                return GetPrimitiveDeserializer(typeT);
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
                if (tagType == UniversalTagNumber.ObjectIdentifier)
                {
                    if ((oidAttr?.PopulateFriendlyName).GetValueOrDefault())
                    {
                        // TODO/Review: Exception type and message?
                        // Friendly name requested on a string output.
                        throw new AsnSerializationConstraintException();
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
                    throw new AsnSerializationConstraintException();
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

            if (typeT == typeof(DateTimeOffset))
            {
                if (tagType == UniversalTagNumber.UtcTime)
                {
                    return (ref AsnReader reader) => reader.GetUtcTime();
                }

                if (tagType == UniversalTagNumber.GeneralizedTime)
                {
                    return (ref AsnReader reader) => reader.GetGeneralizedTime();
                }

                Debug.Fail($"No DateTimeOffset handler for {tagType}");
                throw new CryptographicException();
            }

            if (typeT.IsLayoutSequential)
            {
                if (GetChoiceAttribute(typeT) != null)
                {
                    return (ref AsnReader reader) => DeserializeChoice(ref reader, typeT);
                }

                if (tagType == UniversalTagNumber.Sequence)
                {
                    return (ref AsnReader reader) => DeserializeCustomType(ref reader, typeT);
                }
            }

            // TODO/Review: Exception type and message?
            throw new AsnSerializationConstraintException($"No deserializer for {typeT.FullName} was found");
        }
        
        private static object DefaultValue(
            byte[] defaultContents,
            Deserializer valueDeserializer)
        {
            Debug.Assert(defaultContents != null);

            try
            {
                // TODO: DER? BER? The current mode?
                AsnReader defaultValueReader = new AsnReader(defaultContents, AsnEncodingRules.DER);

                object obj = valueDeserializer(ref defaultValueReader);

                if (defaultValueReader.HasData)
                {
                    throw new AsnSerializerInvalidDefaultException();
                }

                return obj;
            }
            catch (AsnSerializerInvalidDefaultException)
            {
                throw;
            }
            catch (CryptographicException e)
            {
                throw new AsnSerializerInvalidDefaultException(e);
            }
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
            out bool isExplicitTag,
            out bool isOptional,
            out Asn1Tag expectedTag)
        {
            object[] typeAttrs = fieldInfo?.GetCustomAttributes(typeof(AsnTypeAttribute), false) ??
                                 Array.Empty<object>();

            if (typeAttrs.Length > 1)
            {
                // TODO/Review: Exception type and message?
                throw new AsnSerializationConstraintException();
            }

            Type unpackedType = UnpackNullable(typeT);

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
                else if (attr is UtcTimeAttribute)
                {
                    expectedTypes = new[] { typeof(DateTimeOffset) };
                    tagType = UniversalTagNumber.UtcTime;
                }
                else if (attr is GeneralizedTimeAttribute)
                {
                    expectedTypes = new[] { typeof(DateTimeOffset) };
                    tagType = UniversalTagNumber.GeneralizedTime;
                }
                else
                {
                    Debug.Fail($"Unregistered {nameof(AsnTypeAttribute)} kind: {attr.GetType().FullName}");
                    // TODO/Review: Exception type and message?
                    throw new CryptographicException();
                }

                if (!isCollection && Array.IndexOf(expectedTypes, unpackedType) < 0)
                {
                    // TODO/Review: Exception type and message?
                    throw new AsnSerializationConstraintException();
                }
            }

            var defaultValueAttr = fieldInfo?.GetCustomAttribute<DefaultValueAttribute>(false);
            defaultContents = defaultValueAttr?.EncodedBytes;

            if (tagType == 0 && !isAny)
            {
                if (unpackedType == typeof(bool))
                {
                    tagType = UniversalTagNumber.Boolean;
                }
                else if (unpackedType == typeof(sbyte) ||
                         unpackedType == typeof(byte) ||
                         unpackedType == typeof(short) ||
                         unpackedType == typeof(ushort) ||
                         unpackedType == typeof(int) ||
                         unpackedType == typeof(uint) ||
                         unpackedType == typeof(long) ||
                         unpackedType == typeof(ulong))
                {
                    tagType = UniversalTagNumber.Integer;
                }
                else if (unpackedType.IsLayoutSequential)
                {
                    tagType = UniversalTagNumber.Sequence;
                }
                else if (unpackedType == typeof(byte[]) ||
                    unpackedType == typeof(string) ||
                    unpackedType == typeof(DateTimeOffset))
                {
                    // TODO/Review: Exception type and message?
                    throw new AsnAmbiguousFieldTypeException(fieldInfo, unpackedType);
                }
                else if (unpackedType == typeof(Oid))
                {
                    tagType = UniversalTagNumber.ObjectIdentifier;
                }
                else if (unpackedType.IsArray)
                {
                    tagType = UniversalTagNumber.SequenceOf;
                }
                else if (unpackedType.IsEnum)
                {
                    if (typeT.GetCustomAttributes(typeof(FlagsAttribute), false).Length > 0)
                    {
                        tagType = UniversalTagNumber.BitString;
                    }
                    else
                    {
                        tagType = UniversalTagNumber.Enumerated;
                    }
                }
                else if (fieldInfo != null)
                {
                    Debug.Fail($"No tag type bound for {fieldInfo.DeclaringType.FullName}.{fieldInfo.Name}");
                    throw new CryptographicException();
                }
            }

            isOptional = fieldInfo?.GetCustomAttribute<OptionalValueAttribute>(false) != null;

            if (isOptional && !CanBeNull(typeT))
            {
                // TODO/Review: Exception type and message?
                throw new AsnSerializationConstraintException();
            }

            bool isChoice = GetChoiceAttribute(typeT) != null;

            var tagOverride = fieldInfo?.GetCustomAttribute<ExpectedTagAttribute>(false);

            if (tagOverride != null)
            {
                if (isChoice)
                {
                    throw new AsnSerializationConstraintException($"{nameof(ExpectedTagAttribute)} cannot be combined with {nameof(ChoiceAttribute)}");
                }

                // This will throw for unmapped TagClass values and specifying Universal.
                expectedTag = new Asn1Tag(tagOverride.TagClass, tagOverride.TagValue);
                isExplicitTag = tagOverride.ExplicitTag;
                return;
            }

            if (isChoice)
            {
                tagType = 0;
            }

            isExplicitTag = false;
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
                return (ref AsnReader reader) => reader.ReadBoolean();
            if (typeT == typeof(int))
                return TryOrFail((ref AsnReader reader, out int value) => reader.TryReadInt32(out value));
            if (typeT == typeof(uint))
                return TryOrFail((ref AsnReader reader, out uint value) => reader.TryReadUInt32(out value));
            if (typeT == typeof(short))
                return TryOrFail((ref AsnReader reader, out short value) => reader.TryReadInt16(out value));
            if (typeT == typeof(ushort))
                return TryOrFail((ref AsnReader reader, out ushort value) => reader.TryReadUInt16(out value));
            if (typeT == typeof(byte))
                return TryOrFail((ref AsnReader reader, out byte value) => reader.TryReadUInt8(out value));
            if (typeT == typeof(sbyte))
                return TryOrFail((ref AsnReader reader, out sbyte value) => reader.TryReadInt8(out value));
            if (typeT == typeof(long))
                return TryOrFail((ref AsnReader reader, out long value) => reader.TryReadInt64(out value));
            if (typeT == typeof(ulong))
                return TryOrFail((ref AsnReader reader, out ulong value) => reader.TryReadUInt64(out value));

            // TODO/Review: Exception type and message?
            throw new AsnSerializationConstraintException();
        }

        public static T Deserialize<T>(ReadOnlySpan<byte> source, AsnEncodingRules ruleSet)
        {
            Deserializer deserializer = GetDeserializer(typeof(T), null);

            AsnReader reader = new AsnReader(source, ruleSet);

            T t = (T)deserializer(ref reader);

            if (reader.HasData)
            {
                throw new CryptographicException(SR.Cryptography_Der_Invalid_Encoding);
            }

            return t;
        }
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class ExpectedTagAttribute : Attribute
    {
        public TagClass TagClass { get; }
        public int TagValue { get; }
        public bool ExplicitTag { get; set; }

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
    internal sealed class UtcTimeAttribute : AsnTypeAttribute
    {
    }

    [AttributeUsage(AttributeTargets.Field)]
    internal sealed class GeneralizedTimeAttribute : AsnTypeAttribute
    {
        public bool DisallowFractions { get; set; }
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
}
