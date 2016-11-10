// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_rsa.h"
#include <stdio.h>

static int ExecuteSignTransform(SecTransformRef signer, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut);
static int ExecuteVerifyTransform(SecTransformRef verifier, CFErrorRef* pErrorOut);

static int ConfigureSignVerifyTransform(
    SecTransformRef xform, CFDataRef cfDataHash, PAL_HashAlgorithm, bool useDigestAlgorithm, CFErrorRef* pErrorOut);

static int GenerateSignature(SecKeyRef privateKey,
                             uint8_t* pbDataHash,
                             int32_t cbDataHash,
                             PAL_HashAlgorithm hashAlgorithm,
                             bool useHashAlgorithm,
                             CFDataRef* pSignatureOut,
                             CFErrorRef* pErrorOut)
{
    if (privateKey == nullptr || pbDataHash == nullptr || cbDataHash < 0 || pSignatureOut == nullptr ||
        pErrorOut == nullptr)
    {
        return kErrorBadInput;
    }

    *pErrorOut = nullptr;
    *pSignatureOut = nullptr;

    int ret = INT_MIN;
    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(nullptr, pbDataHash, cbDataHash, kCFAllocatorNull);
    SecTransformRef signer = SecSignTransformCreate(privateKey, pErrorOut);

    if (signer == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (!ConfigureSignVerifyTransform(signer, dataHash, hashAlgorithm, useHashAlgorithm, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteSignTransform(signer, pSignatureOut, pErrorOut);

cleanup:
    if (signer != nullptr)
    {
        CFRelease(signer);
    }

    CFRelease(dataHash);
    return ret;
}

extern "C" int AppleCryptoNative_GenerateSignature(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    return GenerateSignature(privateKey, pbDataHash, cbDataHash, PAL_Unknown, false, pSignatureOut, pErrorOut);
}

extern "C" int AppleCryptoNative_GenerateSignatureWithHashAlgorithm(SecKeyRef privateKey,
                                                                    uint8_t* pbDataHash,
                                                                    int32_t cbDataHash,
                                                                    PAL_HashAlgorithm hashAlgorithm,
                                                                    CFDataRef* pSignatureOut,
                                                                    CFErrorRef* pErrorOut)
{
    return GenerateSignature(privateKey, pbDataHash, cbDataHash, hashAlgorithm, true, pSignatureOut, pErrorOut);
}

static int VerifySignature(SecKeyRef publicKey,
                           uint8_t* pbDataHash,
                           int32_t cbDataHash,
                           uint8_t* pbSignature,
                           int32_t cbSignature,
                           PAL_HashAlgorithm hashAlgorithm,
                           bool useHashAlgorithm,
                           CFErrorRef* pErrorOut)
{
    if (publicKey == nullptr || pbDataHash == nullptr || cbDataHash < 0 || pbSignature == nullptr || cbSignature < 0 ||
        pErrorOut == nullptr)
        return kErrorBadInput;

    *pErrorOut = nullptr;

    int ret = INT_MIN;
    CFDataRef dataHash = CFDataCreateWithBytesNoCopy(nullptr, pbDataHash, cbDataHash, kCFAllocatorNull);
    CFDataRef signature = CFDataCreateWithBytesNoCopy(nullptr, pbSignature, cbSignature, kCFAllocatorNull);
    SecTransformRef verifier = SecVerifyTransformCreate(publicKey, signature, pErrorOut);

    if (verifier == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (!ConfigureSignVerifyTransform(verifier, dataHash, hashAlgorithm, useHashAlgorithm, pErrorOut))
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = ExecuteVerifyTransform(verifier, pErrorOut);

cleanup:
    if (verifier != nullptr)
    {
        CFRelease(verifier);
    }

    CFRelease(dataHash);
    CFRelease(signature);

    return ret;
}

extern "C" int AppleCryptoNative_VerifySignatureWithHashAlgorithm(SecKeyRef publicKey,
                                                                  uint8_t* pbDataHash,
                                                                  int32_t cbDataHash,
                                                                  uint8_t* pbSignature,
                                                                  int32_t cbSignature,
                                                                  PAL_HashAlgorithm hashAlgorithm,
                                                                  CFErrorRef* pErrorOut)
{
    return VerifySignature(publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, hashAlgorithm, true, pErrorOut);
}

extern "C" int AppleCryptoNative_VerifySignature(SecKeyRef publicKey,
                                                 uint8_t* pbDataHash,
                                                 int32_t cbDataHash,
                                                 uint8_t* pbSignature,
                                                 int32_t cbSignature,
                                                 CFErrorRef* pErrorOut)
{
    return VerifySignature(publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, PAL_Unknown, false, pErrorOut);
}

extern "C" int AppleCryptoNative_DsaSign(
    SecKeyRef privateKey, uint8_t* pbDataHash, int32_t cbDataHash, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    return AppleCryptoNative_GenerateSignature(privateKey, pbDataHash, cbDataHash, pSignatureOut, pErrorOut);
}

extern "C" int AppleCryptoNative_DsaVerify(SecKeyRef publicKey,
                                           uint8_t* pbDataHash,
                                           int32_t cbDataHash,
                                           uint8_t* pbSignature,
                                           int32_t cbSignature,
                                           CFErrorRef* pErrorOut)
{
    return AppleCryptoNative_VerifySignature(publicKey, pbDataHash, cbDataHash, pbSignature, cbSignature, pErrorOut);
}

static int ExecuteSignTransform(SecTransformRef signer, CFDataRef* pSignatureOut, CFErrorRef* pErrorOut)
{
    assert(signer != nullptr);
    assert(pSignatureOut != nullptr);
    assert(pErrorOut != nullptr);

    int ret = INT_MIN;
    CFTypeRef signerResponse = SecTransformExecute(signer, pErrorOut);
    CFDataRef signature = nullptr;

    if (signerResponse == nullptr || *pErrorOut != nullptr)
    {
        ret = kErrorSeeError;
        goto cleanup;
    }

    if (CFGetTypeID(signerResponse) != CFDataGetTypeID())
    {
        ret = kErrorUnknownState;
        goto cleanup;
    }

    signature = reinterpret_cast<CFDataRef>(const_cast<void*>(signerResponse));

    if (CFDataGetLength(signature) > 0)
    {
        // We're going to call CFRelease in cleanup, so this keeps it alive
        // to be interpreted by the managed code.
        CFRetain(signature);
        *pSignatureOut = signature;
        ret = 1;
    }
    else
    {
        ret = kErrorUnknownState;
        *pSignatureOut = nullptr;
    }

cleanup:
    if (signerResponse != nullptr)
    {
        CFRelease(signerResponse);
    }

    return ret;
}

static int ExecuteVerifyTransform(SecTransformRef verifier, CFErrorRef* pErrorOut)
{
    assert(verifier != nullptr);
    assert(pErrorOut != nullptr);

    int ret = INT_MIN;
    CFTypeRef verifierResponse = SecTransformExecute(verifier, pErrorOut);

    if (verifierResponse == nullptr || *pErrorOut != nullptr)
    {
        CFShow(*pErrorOut);
        ret = kErrorSeeError;
        goto cleanup;
    }

    ret = (verifierResponse == kCFBooleanTrue);

cleanup:

    if (verifierResponse != nullptr)
    {
        CFRelease(verifierResponse);
    }

    return ret;
}

static int ConfigureSignVerifyTransform(SecTransformRef xform,
                                        CFDataRef cfDataHash,
                                        PAL_HashAlgorithm hashAlgorithm,
                                        bool includeHashAlgorithm,
                                        CFErrorRef* pErrorOut)
{
    if (!SecTransformSetAttribute(xform, kSecInputIsAttributeName, kSecInputIsDigest, pErrorOut))
    {
        return 0;
    }

    if (!SecTransformSetAttribute(xform, kSecTransformInputAttributeName, cfDataHash, pErrorOut))
    {
        return 0;
    }

    if (includeHashAlgorithm)
    {
        CFStringRef cfHashName = nullptr;
        int hashSize = 0;

        switch (hashAlgorithm)
        {
            case PAL_MD5:
                cfHashName = kSecDigestMD5;
                break;
            case PAL_SHA1:
                cfHashName = kSecDigestSHA1;
                break;
            case PAL_SHA256:
                cfHashName = kSecDigestSHA2;
                hashSize = 256;
                break;
            case PAL_SHA384:
                cfHashName = kSecDigestSHA2;
                hashSize = 384;
                break;
            case PAL_SHA512:
                cfHashName = kSecDigestSHA2;
                hashSize = 512;
                break;
            default:
                return kErrorUnknownAlgorithm;
        }

        if (!SecTransformSetAttribute(xform, kSecDigestTypeAttribute, cfHashName, pErrorOut))
        {
            return 0;
        }

        if (hashSize != 0)
        {
            CFNumberRef cfHashSize = CFNumberCreate(nullptr, kCFNumberIntType, &hashSize);

            if (!SecTransformSetAttribute(xform, kSecDigestLengthAttribute, cfHashSize, pErrorOut))
            {
                CFRelease(cfHashSize);
                return 0;
            }

            CFRelease(cfHashSize);
        }
    }

    return 1;
}
