// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using System.Globalization;
using System.Net.Security;

namespace System.Net
{
    // Need a global so we can pass the interfaces as variables.
    internal static class GlobalSSPI
    {
        internal static SSPIInterface SSPIAuth = new SSPIAuthType();
        internal static SSPIInterface SSPISecureChannel = new SSPISecureChannelType();
    }

    // Used to define the interface for security to use.
    internal interface SSPIInterface
    {
        SecurityPackageInfoClass[] SecurityPackages { get; set; }
        int EnumerateSecurityPackages(out int pkgnum, out SafeFreeContextBuffer pkgArray);
        int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.AuthIdentity authdata, out SafeFreeCredentials outCredential);
        int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref SafeSspiAuthDataHandle authdata, out SafeFreeCredentials outCredential);
        int AcquireDefaultCredential(string moduleName, Interop.Secur32.CredentialUse usage, out SafeFreeCredentials outCredential);
        int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.SecureCredential authdata, out SafeFreeCredentials outCredential);
        int AcceptSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer inputBuffer, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags);
        int AcceptSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer[] inputBuffers, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags);
        int InitializeSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer inputBuffer, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags);
        int InitializeSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags);
        int EncryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber);
        int DecryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber);
        int MakeSignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber);
        int VerifySignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber);

        int QueryContextChannelBinding(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, out SafeFreeContextBufferChannelBinding refHandle);
        int QueryContextAttributes(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, byte[] buffer, Type handleType, out SafeHandle refHandle);
        int SetContextAttributes(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, byte[] buffer);
        int QuerySecurityContextToken(SafeDeleteContext phContext, out SecurityContextTokenHandle phToken);
        int CompleteAuthToken(ref SafeDeleteContext refContext, SecurityBuffer[] inputBuffers);
    }

    // For SSL connections:
    internal class SSPISecureChannelType : SSPIInterface
    {
        private static volatile SecurityPackageInfoClass[] s_securityPackages;

        public SecurityPackageInfoClass[] SecurityPackages
        {
            get
            {
                return s_securityPackages;
            }
            set
            {
                s_securityPackages = value;
            }
        }

        public int EnumerateSecurityPackages(out int pkgnum, out SafeFreeContextBuffer pkgArray)
        {
            GlobalLog.Print("SSPISecureChannelType::EnumerateSecurityPackages()");
            return SafeFreeContextBuffer.EnumeratePackages(out pkgnum, out pkgArray);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.AuthIdentity authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref SafeSspiAuthDataHandle authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcquireDefaultCredential(string moduleName, Interop.Secur32.CredentialUse usage, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireDefaultCredential(moduleName, usage, out outCredential);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.SecureCredential authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcceptSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer inputBuffer, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.AcceptSecurityContext(ref credential, ref context, inFlags, endianness, inputBuffer, null, outputBuffer, ref outFlags);
        }

        public int AcceptSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer[] inputBuffers, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.AcceptSecurityContext(ref credential, ref context, inFlags, endianness, null, inputBuffers, outputBuffer, ref outFlags);
        }

        public int InitializeSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer inputBuffer, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.InitializeSecurityContext(ref credential, ref context, targetName, inFlags, endianness, inputBuffer, null, outputBuffer, ref outFlags);
        }

        public int InitializeSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.InitializeSecurityContext(ref credential, ref context, targetName, inFlags, endianness, null, inputBuffers, outputBuffer, ref outFlags);
        }

        public int EncryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.EncryptMessage(ref context._handle, 0, inputOutput, sequenceNumber);
                    context.DangerousRelease();
                }
            }
            return status;
        }

        public unsafe int DecryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;
            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.DecryptMessage(ref context._handle, inputOutput, sequenceNumber, null);
                    context.DangerousRelease();
                }
            }
            return status;
        }

        public int MakeSignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            throw NotImplemented.ByDesignWithMessage(SR.net_MethodNotImplementedException);
        }

        public int VerifySignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            throw NotImplemented.ByDesignWithMessage(SR.net_MethodNotImplementedException);
        }

        public unsafe int QueryContextChannelBinding(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, out SafeFreeContextBufferChannelBinding refHandle)
        {
            refHandle = SafeFreeContextBufferChannelBinding.CreateEmptyHandle();

            // Bindings is on the stack, so there's no need for a fixed block.
            Bindings bindings = new Bindings();
            return SafeFreeContextBufferChannelBinding.QueryContextChannelBinding(phContext, attribute, &bindings, refHandle);
        }

        public unsafe int QueryContextAttributes(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, byte[] buffer, Type handleType, out SafeHandle refHandle)
        {
            refHandle = null;
            if (handleType != null)
            {
                if (handleType == typeof(SafeFreeContextBuffer))
                {
                    refHandle = SafeFreeContextBuffer.CreateEmptyHandle();
                }
                else if (handleType == typeof(SafeFreeCertContext))
                {
                    refHandle = new SafeFreeCertContext();
                }
                else
                {
                    throw new ArgumentException(SR.Format(SR.SSPIInvalidHandleType, handleType.FullName), "handleType");
                }
            }
            fixed (byte* bufferPtr = buffer)
            {
                return SafeFreeContextBuffer.QueryContextAttributes(phContext, attribute, bufferPtr, refHandle);
            }
        }

        public int SetContextAttributes(SafeDeleteContext phContext, Interop.Secur32.ContextAttribute attribute, byte[] buffer)
        {
            return SafeFreeContextBuffer.SetContextAttributes(phContext, attribute, buffer);
        }

        public int QuerySecurityContextToken(SafeDeleteContext phContext, out SecurityContextTokenHandle phToken)
        {
            throw new NotSupportedException();
        }

        public int CompleteAuthToken(ref SafeDeleteContext refContext, SecurityBuffer[] inputBuffers)
        {
            throw new NotSupportedException();
        }
    }


    // For Authentication (Kerberos, NTLM, Negotiate and WDigest):
    internal class SSPIAuthType : SSPIInterface
    {
        private static volatile SecurityPackageInfoClass[] s_securityPackages;

        public SecurityPackageInfoClass[] SecurityPackages
        {
            get
            {
                return s_securityPackages;
            }
            set
            {
                s_securityPackages = value;
            }
        }

        public int EnumerateSecurityPackages(out int pkgnum, out SafeFreeContextBuffer pkgArray)
        {
            GlobalLog.Print("SSPIAuthType::EnumerateSecurityPackages()");
            return SafeFreeContextBuffer.EnumeratePackages(out pkgnum, out pkgArray);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.AuthIdentity authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref SafeSspiAuthDataHandle authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcquireDefaultCredential(string moduleName, Interop.Secur32.CredentialUse usage, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireDefaultCredential(moduleName, usage, out outCredential);
        }

        public int AcquireCredentialsHandle(string moduleName, Interop.Secur32.CredentialUse usage, ref Interop.Secur32.SecureCredential authdata, out SafeFreeCredentials outCredential)
        {
            return SafeFreeCredentials.AcquireCredentialsHandle(moduleName, usage, ref authdata, out outCredential);
        }

        public int AcceptSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer inputBuffer, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.AcceptSecurityContext(ref credential, ref context, inFlags, endianness, inputBuffer, null, outputBuffer, ref outFlags);
        }

        public int AcceptSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, SecurityBuffer[] inputBuffers, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.AcceptSecurityContext(ref credential, ref context, inFlags, endianness, null, inputBuffers, outputBuffer, ref outFlags);
        }

        public int InitializeSecurityContext(ref SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer inputBuffer, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.InitializeSecurityContext(ref credential, ref context, targetName, inFlags, endianness, inputBuffer, null, outputBuffer, ref outFlags);
        }

        public int InitializeSecurityContext(SafeFreeCredentials credential, ref SafeDeleteContext context, string targetName, Interop.Secur32.ContextFlags inFlags, Interop.Secur32.Endianness endianness, SecurityBuffer[] inputBuffers, SecurityBuffer outputBuffer, ref Interop.Secur32.ContextFlags outFlags)
        {
            return SafeDeleteContext.InitializeSecurityContext(ref credential, ref context, targetName, inFlags, endianness, null, inputBuffers, outputBuffer, ref outFlags);
        }


        public int EncryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.EncryptMessage(ref context._handle, 0, inputOutput, sequenceNumber);
                    context.DangerousRelease();
                }
            }
            return status;
        }

        public unsafe int DecryptMessage(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;
            uint qop = 0;

            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.DecryptMessage(ref context._handle, inputOutput, sequenceNumber, &qop);
                    context.DangerousRelease();
                }
            }

            const uint SECQOP_WRAP_NO_ENCRYPT = 0x80000001;
            if (status == 0 && qop == SECQOP_WRAP_NO_ENCRYPT)
            {
                GlobalLog.Assert("Secur32.DecryptMessage", "Expected qop = 0, returned value = " + qop.ToString("x", CultureInfo.InvariantCulture));
                throw new InvalidOperationException(SR.net_auth_message_not_encrypted);
            }


            return status;
        }

        public int MakeSignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    const uint SECQOP_WRAP_NO_ENCRYPT = 0x80000001;
                    status = Interop.Secur32.EncryptMessage(ref context._handle, SECQOP_WRAP_NO_ENCRYPT, inputOutput, sequenceNumber);
                    context.DangerousRelease();
                }
            }
            return status;
        }

        public unsafe int VerifySignature(SafeDeleteContext context, Interop.Secur32.SecurityBufferDescriptor inputOutput, uint sequenceNumber)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;

            uint qop = 0;
            try
            {
                context.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    context.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.DecryptMessage(ref context._handle, inputOutput, sequenceNumber, &qop);
                    context.DangerousRelease();
                }
            }

            return status;
        }

        public int QueryContextChannelBinding(SafeDeleteContext context, Interop.Secur32.ContextAttribute attribute, out SafeFreeContextBufferChannelBinding binding)
        {
            // Querying an auth SSP for a CBT doesn't make sense
            binding = null;
            throw new NotSupportedException();
        }

        public unsafe int QueryContextAttributes(SafeDeleteContext context, Interop.Secur32.ContextAttribute attribute, byte[] buffer, Type handleType, out SafeHandle refHandle)
        {
            refHandle = null;
            if (handleType != null)
            {
                if (handleType == typeof(SafeFreeContextBuffer))
                {
                    refHandle = SafeFreeContextBuffer.CreateEmptyHandle();
                }
                else if (handleType == typeof(SafeFreeCertContext))
                {
                    refHandle = new SafeFreeCertContext();
                }
                else
                {
                    throw new ArgumentException(SR.Format(SR.SSPIInvalidHandleType, handleType.FullName), "handleType");
                }
            }

            fixed (byte* bufferPtr = buffer)
            {
                return SafeFreeContextBuffer.QueryContextAttributes(context, attribute, bufferPtr, refHandle);
            }
        }

        public int SetContextAttributes(SafeDeleteContext context, Interop.Secur32.ContextAttribute attribute, byte[] buffer)
        {
            throw NotImplemented.ByDesignWithMessage(SR.net_MethodNotImplementedException);
        }

        public int QuerySecurityContextToken(SafeDeleteContext phContext, out SecurityContextTokenHandle phToken)
        {
            return GetSecurityContextToken(phContext, out phToken);
        }

        public int CompleteAuthToken(ref SafeDeleteContext refContext, SecurityBuffer[] inputBuffers)
        {
            return SafeDeleteContext.CompleteAuthToken(ref refContext, inputBuffers);
        }

        private static int GetSecurityContextToken(SafeDeleteContext phContext, out SecurityContextTokenHandle safeHandle)
        {
            int status = (int)Interop.SecurityStatus.InvalidHandle;
            bool b = false;
            safeHandle = null;

            try
            {
                phContext.DangerousAddRef(ref b);
            }
            catch (Exception e)
            {
                if (b)
                {
                    phContext.DangerousRelease();
                    b = false;
                }
                if (!(e is ObjectDisposedException))
                    throw;
            }
            finally
            {
                if (b)
                {
                    status = Interop.Secur32.QuerySecurityContextToken(ref phContext._handle, out safeHandle);
                    phContext.DangerousRelease();
                }
            }

            return status;
        }
    }
}
