// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

#include "pal_symmetric.h"

extern "C" void AppleCryptoNative_CryptorFree(CCCryptorRef cryptor)
{
	if (cryptor != nullptr)
	{
		CCCryptorRelease(cryptor);
	}
}

extern "C" int AppleCryptoNative_CryptorCreate(
	PAL_SymmetricOperation operation,
	PAL_SymmetricAlgorithm algorithm,
	PAL_ChainingMode chainingMode,
	PAL_PaddingMode paddingMode,
	const uint8_t* pbKey,
	int32_t cbKey,
	const uint8_t* pbIv,
	PAL_SymmetricOptions options,
	CCCryptorRef* ppCryptorOut,
	int32_t* pkCCStatus)
{
    if (pbKey == nullptr || cbKey < 1 || ppCryptorOut == nullptr)
        return -1;
	if (pbIv == nullptr && chainingMode != PAL_ChainingModeECB)
		return -1;

	// Ensure we aren't passing through things we don't understand
#if DEBUG
	switch (operation)
	{
		case PAL_OperationEncrypt:
		case PAL_OperationDecrypt:
			break;
		default:
			return -1;
	}

	switch (algorithm)
	{
		case PAL_AlgorithmAES:
		case PAL_Algorithm3DES:
			break;
		default:
			return -1;
	}

	switch (chainingMode)
	{
		case PAL_ChainingModeECB:
		case PAL_ChainingModeCBC:
			break;
		default:
			return -1;
	}

	switch (paddingMode)
	{
		case PAL_PaddingModeNone:
		case PAL_PaddingModePkcs7:
			break;
		default:
			return -1;
	}

	if (options != 0)
		return -1;
#endif

    CCStatus status = CCCryptorCreateWithMode(
		operation,
		chainingMode,
		algorithm,
		paddingMode,
		pbIv,
		pbKey,
		static_cast<size_t>(cbKey),
		/* tweak is not supported */nullptr,
		0,
		/* numRounds is not supported */0,
		options,
		ppCryptorOut);

    *pkCCStatus = status;
    return status == kCCSuccess;
}

extern "C" int AppleCryptoNative_CryptorUpdate(
	CCCryptorRef cryptor,
	const uint8_t* pbData,
	int32_t cbData,
	uint32_t* pbOutput,
	int32_t cbOutput,
	int32_t* pcbWritten,
	int32_t* pkCCStatus)
{
	if (pbData == nullptr || cbData < 0 || pbOutput == nullptr || cbOutput < cbData || pcbWritten == nullptr || pkCCStatus == nullptr)
		return -1;

	CCStatus status = CCCryptorUpdate(
		cryptor,
		pbData,
		static_cast<size_t>(cbData),
		pbOutput,
		static_cast<size_t>(cbOutput),
		reinterpret_cast<size_t*>(pcbWritten));

    *pkCCStatus = status;
    return status == kCCSuccess;
}

extern "C" int AppleCryptoNative_CryptorFinal(
	CCCryptorRef cryptor,
	uint8_t* pbOutput,
	int32_t cbOutput,
	int32_t* pcbWritten,
	int32_t* pkCCStatus)
{
	if (pbOutput == nullptr || cbOutput < 0 || pcbWritten == nullptr || pkCCStatus == nullptr)
		return -1;

	CCStatus status = CCCryptorFinal(
		cryptor,
		pbOutput,
		static_cast<size_t>(cbOutput),
		reinterpret_cast<size_t*>(pcbWritten));

    *pkCCStatus = status;
    return status == kCCSuccess;
}

extern "C" int AppleCryptoNative_CryptorReset(
	CCCryptorRef cryptor,
	const uint8_t* pbIv,
	int32_t* pkCCStatus)
{
	if (cryptor == nullptr || pkCCStatus == nullptr)
		return -1;

	CCStatus status = CCCryptorReset(cryptor, pbIv);
	*pkCCStatus = status;
	return status == kCCSuccess;
}
