from .defines import *
import enum
import datetime
import ctypes

# call API to get max token size, or..
maxtoken_size = 2880 # bytes

_FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
def FiletimeToDateTime(ft):
	timestamp = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
	print(timestamp)
	return _FILETIME_null_date + datetime.timedelta(microseconds=timestamp/10)

#timestamp is LARGE_INTEGER
#same as FILETIME structure

#https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-filetime
class FILETIME(Structure):
	_fields_ = [
		("dwLowDateTime",   DWORD),
		("dwHighDateTime",   DWORD),
	]
PFILETIME = POINTER(FILETIME)
TimeStamp = FILETIME
PTimeStamp = PFILETIME

SEC_CHAR = CHAR
PSEC_CHAR = PCHAR

class LUID(Structure):
	_fields_ = [
		("LowPart",	 DWORD),
		("HighPart",	LONG),
	]

PLUID = POINTER(LUID)

class SECPKG_ATTR(enum.Enum):
	SESSION_KEY = 9
	C_ACCESS_TOKEN = 0x80000012 #The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
	C_FULL_ACCESS_TOKEN = 0x80000082 #The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
	CERT_TRUST_STATUS = 0x80000084 #The pBuffer parameter contains a pointer to a CERT_TRUST_STATUS structure that specifies trust information about the certificate.This attribute is supported only on the client.
	CREDS = 0x80000080 # The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. The client credentials can be either user name and password or user name and smart card PIN. This attribute is supported only on the server.
	CREDS_2 = 0x80000086 #The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. If the client credential is user name and password, the buffer is a packed KERB_INTERACTIVE_LOGON structure. If the client credential is user name and smart card PIN, the buffer is a packed KERB_CERTIFICATE_LOGON structure. If the client credential is an online identity credential, the buffer is a marshaled SEC_WINNT_AUTH_IDENTITY_EX2 structure. This attribute is supported only on the CredSSP server. Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
	NEGOTIATION_PACKAGE = 0x80000081 #The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfo structure that specifies the name of the authentication package negotiated by the Microsoft Negotiate provider.
	PACKAGE_INFO = 10 #The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfostructure.Returns information on the SSP in use.
	SERVER_AUTH_FLAGS = 0x80000083 #The pBuffer parameter contains a pointer to a SecPkgContext_Flags structure that specifies information about the flags in the current security context. This attribute is supported only on the client.
	SIZES = 0x0 #The pBuffer parameter contains a pointer to a SecPkgContext_Sizes structure. Queries the sizes of the structures used in the per-message functions and authentication exchanges.
	SUBJECT_SECURITY_ATTRIBUTES = 124 #	The pBuffer parameter contains a pointer to a SecPkgContext_SubjectAttributes structure. This value returns information about the security attributes for the connection. This value is supported only on the CredSSP server. Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.

# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-_secbuffer
class SECBUFFER_TYPE(enum.Enum):
	SECBUFFER_ALERT = 17 #The buffer contains an alert message.
	SECBUFFER_ATTRMASK = 4026531840 #The buffer contains a bitmask for a SECBUFFER_READONLY_WITH_CHECKSUM buffer.
	SECBUFFER_CHANNEL_BINDINGS = 14  #	The buffer contains channel binding information.
	SECBUFFER_CHANGE_PASS_RESPONSE = 15 #The buffer contains a DOMAIN_PASSWORD_INFORMATION structure.
	SECBUFFER_DATA = 1 #The buffer contains common data. The security package can read and write this data, for example, to encrypt some or all of it.
	SECBUFFER_DTLS_MTU = 24#The buffer contains the setting for the maximum transmission unit (MTU) size for DTLS only. The default value is 1096 and the valid configurable range is between 200 and 64*1024.
	SECBUFFER_EMPTY = 0 #This is a placeholder in the buffer array. The caller can supply several such entries in the array, and the security package can return information in them. For more information, see SSPI Context Semantics.
	SECBUFFER_EXTRA = 5 #The security package uses this value to indicate the number of extra or unprocessed bytes in a message.
	SECBUFFER_MECHLIST = 11 #The buffer contains a protocol-specific list of object identifiers (OIDs). It is not usually of interest to callers.
	SECBUFFER_MECHLIST_SIGNATURE = 12 #The buffer contains a signature of a SECBUFFER_MECHLIST buffer. It is not usually of interest to callers.
	SECBUFFER_MISSING = 4 #The security package uses this value to indicate the number of missing bytes in a particular message. The pvBuffer member is ignored in this type.
	SECBUFFER_PKG_PARAMS = 3 #These are transport-to-package–specific parameters. For example, the NetWare redirector may supply the server object identifier, while DCE RPC can supply an association UUID, and so on.
	SECBUFFER_PRESHARED_KEY = 22 #The buffer contains the preshared key. The maximum allowed PSK buffer size is 256 bytes.
	SECBUFFER_PRESHARED_KEY_IDENTITY = 23 #The buffer contains the preshared key identity.
	SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20 #The buffer contains the SRTP master key identifier.
	SECBUFFER_SRTP_PROTECTION_PROFILES = 19 #The buffer contains the list of SRTP protection profiles, in descending order of preference.
	SECBUFFER_STREAM_HEADER = 7 #The buffer contains a protocol-specific header for a particular record. It is not usually of interest to callers.
	SECBUFFER_STREAM_TRAILER = 6 #The buffer contains a protocol-specific trailer for a particular record. It is not usually of interest to callers.
	SECBUFFER_TARGET = 13 #This flag is reserved. Do not use it.
	SECBUFFER_TARGET_HOST = 16 #The buffer specifies the service principal name (SPN) of the target.
								#This value is supported by the Digest security package when used with channel bindings.
								#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
	SECBUFFER_TOKEN = 2 #The buffer contains the security token portion of the message. This is read-only for input parameters or read/write for output parameters.
	SECBUFFER_TOKEN_BINDING = 21 #The buffer contains the supported token binding protocol version and key parameters, in descending order of preference.
	SECBUFFER_APPLICATION_PROTOCOLS = 18 #The buffer contains a list of application protocol IDs, one list per application protocol negotiation extension type to be enabled.
	SECBUFFER_PADDING = 9 
	"""
	In addition, BufferType can combine the following flags with any of the flags in the preceding table by using a bitwise-OR operation.
	Value 	Meaning

	SECBUFFER_READONLY
	2147483648 (0x80000000)

		The buffer is read-only with no checksum. This flag is intended for sending header information to the security package for computing the checksum. The package can read this buffer, but cannot modify it.

	SECBUFFER_READONLY_WITH_CHECKSUM
	268435456 (0x10000000)

		The buffer is read-only with a checksum
	"""
	
# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-secpkgcontext_sessionkey
class SecPkgContext_SessionKey(Structure):
	_fields_ = [('SessionKeyLength',ULONG),('SessionKey',LPBYTE)]
	
	@property
	def Buffer(self):
		return ctypes.string_at(self.SessionKey, size=self.SessionKeyLength)

# https://github.com/benjimin/pywebcorp/blob/master/pywebcorp/ctypes_sspi.py
class SecHandle(Structure): 
	
	_fields_ = [('dwLower',POINTER(ULONG)),('dwUpper',POINTER(ULONG))]
	def __init__(self): # populate deeply (empty memory fields) rather than shallow null POINTERs.
		super(Structure, self).__init__(byref(ULONG()), byref(ULONG()))

class SecBuffer(Structure):
	"""Stores a memory buffer: size, type-flag, and POINTER. 
	The type can be empty (0) or token (2).
	InitializeSecurityContext will write to the buffer that is flagged "token"
	and update the size, or else fail 0x80090321=SEC_E_BUFFER_TOO_SMALL."""	
	_fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',PVOID)]
	def __init__(self, token=b'\x00'*maxtoken_size, buffer_type = SECBUFFER_TYPE.SECBUFFER_TOKEN):
		buf = ctypes.create_string_buffer(token, size=len(token)) 
		Structure.__init__(self,sizeof(buf),buffer_type.value,ctypes.cast(byref(buf),PVOID))
	@property
	def Buffer(self):
		return (SECBUFFER_TYPE(self.BufferType), ctypes.string_at(self.pvBuffer, size=self.cbBuffer))	 
	
#class SecBufferDesc(Structure):
#	"""Descriptor stores SECBUFFER_VERSION=0, number of buffers (e.g. one),
#	and POINTER to an array of SecBuffer structs."""
#	_fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
#	def __init__(self, *args, **kwargs):
#		Structure.__init__(self,0,1,byref(SecBuffer(*args, **kwargs)))
#	def __getitem__(self, index):
#		return self.pBuffers[index]
#		
#	@property
#	def Buffers(self):
#		data = []
#		for i in range(self.cBuffers):
#			data.append(self.pBuffers[i].Buffer)
#		return data

class SecBufferDesc(Structure):
	"""Descriptor stores SECBUFFER_VERSION=0, number of buffers (e.g. one),
	and POINTER to an array of SecBuffer structs."""
	_fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
	def __init__(self, secbuffers = None):
		#secbuffers = a list of security buffers (SecBuffer)
		if secbuffers is not None:
			Structure.__init__(self,0,len(secbuffers),(SecBuffer * len(secbuffers))(*secbuffers))
		else:
			Structure.__init__(self,0,1,byref(SecBuffer()))
	def __getitem__(self, index):
		return self.pBuffers[index]
		
	@property
	def Buffers(self):
		data = []
		for i in range(self.cBuffers):
			data.append(self.pBuffers[i].Buffer)
		return data
		
PSecBufferDesc = POINTER(SecBufferDesc)

PSecHandle = POINTER(SecHandle)
CredHandle = SecHandle
PCredHandle = PSecHandle
CtxtHandle = SecHandle
PCtxtHandle = PSecHandle


# https://apidock.com/ruby/Win32/SSPI/SSPIResult
class SEC_E(enum.Enum):
	OK = 0x00000000 
	CONTINUE_NEEDED = 0x00090312 
	INSUFFICIENT_MEMORY = 0x80090300 #There is not enough memory available to complete the requested action.
	INTERNAL_ERROR = 0x80090304 #An error occurred that did not map to an SSPI error code.
	INVALID_HANDLE = 0x80090301
	INVALID_TOKEN = 0x80090308
	LOGON_DENIED = 0x8009030C
	NO_AUTHENTICATING_AUTHORITY = 0x80090311
	NO_CREDENTIALS = 0x8009030E #No credentials are available in the security package.
	TARGET_UNKNOWN = 0x80090303
	UNSUPPORTED_FUNCTION = 0x80090302
	WRONG_PRINCIPAL = 0x80090322
	NOT_OWNER = 0x80090306 #The caller of the function does not have the necessary credentials.
	SECPKG_NOT_FOUND = 0x80090305 #The requested security package does not exist.
	UNKNOWN_CREDENTIALS = 0x8009030D #The credentials supplied to the package were not recognized.
	#SEC_I
	RENEGOTIATE = 590625
	COMPLETE_AND_CONTINUE = 590612
	COMPLETE_NEEDED = 590611
	INCOMPLETE_CREDENTIALS = 590624

class SECPKG_CRED(enum.IntFlag):
	AUTOLOGON_RESTRICTED = 0x00000010 	#The security does not use default logon credentials or credentials from Credential Manager.
										#This value is supported only by the Negotiate security package.
										#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.

	BOTH = 3							#Validate an incoming credential or use a local credential to prepare an outgoing token. This flag enables both other flags. This flag is not valid with the Digest and Schannel SSPs.
	INBOUND = 1							#Validate an incoming server credential. Inbound credentials might be validated by using an authenticating authority when InitializeSecurityContext (General) or AcceptSecurityContext (General) is called. If such an authority is not available, the function will fail and return SEC_E_NO_AUTHENTICATING_AUTHORITY. Validation is package specific.
	OUTBOUND = 2						#Allow a local client credential to prepare an outgoing token.
	PROCESS_POLICY_ONLY = 0x00000020 	#The function processes server policy and returns SEC_E_NO_CREDENTIALS, indicating that the application should prompt for credentials.
										#This value is supported only by the Negotiate security package.
										#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.


class ISC_REQ(enum.IntFlag):
	DELEGATE = 1
	MUTUAL_AUTH = 2
	REPLAY_DETECT = 4
	SEQUENCE_DETECT = 8
	CONFIDENTIALITY = 16
	USE_SESSION_KEY = 32
	PROMPT_FOR_CREDS = 64
	USE_SUPPLIED_CREDS = 128
	ALLOCATE_MEMORY = 256
	USE_DCE_STYLE = 512
	DATAGRAM = 1024
	CONNECTION = 2048
	CALL_LEVEL = 4096
	FRAGMENT_SUPPLIED = 8192
	EXTENDED_ERROR = 16384
	STREAM = 32768
	INTEGRITY = 65536
	IDENTIFY = 131072
	NULL_SESSION = 262144
	MANUAL_CRED_VALIDATION = 524288
	RESERVED1 = 1048576
	FRAGMENT_TO_FIT = 2097152
	HTTP = 0x10000000

class DecryptFlags(enum.Enum):										
	SIGN_ONLY = 0
	SECQOP_WRAP_NO_ENCRYPT = 2147483649 # same as KERB_WRAP_NO_ENCRYPT
	
def FreeContextBuffer(secbuff):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('DecryptMessage', result, SEC_E(result)))
	
	_FreeContextBuffer = windll.Secur32.FreeContextBuffer
	_FreeContextBuffer.argtypes = [PVOID]
	_FreeContextBuffer.restype  = DWORD
	_FreeContextBuffer.errcheck  = errc
	
	res = _FreeContextBuffer(byref(secbuff))
	return

#https://github.com/mhammond/pywin32/blob/d64fac8d7bda2cb1d81e2c9366daf99e802e327f/win32/Lib/sspi.py#L108
#https://docs.microsoft.com/en-us/windows/desktop/secauthn/using-sspi-with-a-windows-sockets-client
#https://msdn.microsoft.com/en-us/library/Aa374712(v=VS.85).aspx
def AcquireCredentialsHandle(client_name, package_name, tragetspn, cred_usage, pluid = None, authdata = None):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return result
		raise Exception('%s failed with error code %s (%s)' % ('AcquireCredentialsHandle', result, SEC_E(result)))
		
	_AcquireCredentialsHandle = windll.Secur32.AcquireCredentialsHandleA
	_AcquireCredentialsHandle.argtypes = [PSEC_CHAR, PSEC_CHAR, ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp]
	_AcquireCredentialsHandle.restype  = DWORD
	_AcquireCredentialsHandle.errcheck  = errc
	
	#TODO: package_name might be different from version to version. implement functionality to poll it properly!
	
	cn = None
	if client_name:
		cn = LPSTR(client_name.encode('ascii'))
	pn = LPSTR(package_name.encode('ascii'))
	
	creds = CredHandle()
	ts = TimeStamp()
	res = _AcquireCredentialsHandle(cn, pn, cred_usage, pluid, authdata, None, None, byref(creds), byref(ts))
	return creds
	
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa375507(v=vs.85).aspx
def InitializeSecurityContext(creds, target, ctx = None, flags = ISC_REQ.INTEGRITY | ISC_REQ.CONFIDENTIALITY | ISC_REQ.SEQUENCE_DETECT | ISC_REQ.REPLAY_DETECT, TargetDataRep  = 0, token = None):
	#print('==== InitializeSecurityContext ====')
	#print('Creds: %s' % creds)
	#print('Target: %s' % target)
	#print('ctx: %s' % ctx)
	#print('token: %s' % token)
	def errc(result, func, arguments):
		if SEC_E(result) in [SEC_E.OK, SEC_E.COMPLETE_AND_CONTINUE, SEC_E.COMPLETE_NEEDED, SEC_E.CONTINUE_NEEDED, SEC_E.INCOMPLETE_CREDENTIALS]:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('InitializeSecurityContext', result, SEC_E(result)))
		
	_InitializeSecurityContext = windll.Secur32.InitializeSecurityContextA
	_InitializeSecurityContext.argtypes = [PCredHandle, PCtxtHandle, PSEC_CHAR, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp]
	_InitializeSecurityContext.restype  = DWORD
	_InitializeSecurityContext.errcheck  = errc
	
	if target:
		ptarget = LPSTR(target.encode('ascii'))
	else:
		ptarget = None
	newbuf = SecBufferDesc()
	outputflags = ULONG()
	expiry = TimeStamp()
	
	if token:
		token = SecBufferDesc([SecBuffer(token)])
		
	
	if not ctx:
		ctx = CtxtHandle()
		res = _InitializeSecurityContext(byref(creds), None, ptarget, int(flags), 0 ,TargetDataRep, byref(token) if token else None, 0, byref(ctx), byref(newbuf), byref(outputflags), byref(expiry))
	else:
		res = _InitializeSecurityContext(byref(creds), byref(ctx), ptarget, int(flags), 0 ,TargetDataRep, byref(token) if token else None, 0, byref(ctx), byref(newbuf), byref(outputflags), byref(expiry))
	
	data = newbuf.Buffers
	
	return res, ctx, data, outputflags, expiry
	
def DecryptMessage(ctx, data, message_no = 0):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('DecryptMessage', result, SEC_E(result)))
		
	_DecryptMessage = windll.Secur32.DecryptMessage
	_DecryptMessage.argtypes = [PCtxtHandle, PSecBufferDesc, ULONG, PULONG]
	_DecryptMessage.restype  = DWORD
	_DecryptMessage.errcheck  = errc
	
	secbuffers = []
	secbuffers.append(SecBuffer(token=data, buffer_type = SECBUFFER_TYPE.SECBUFFER_DATA))
	
	data = SecBufferDesc(secbuffers)
	
	flags = ULONG()
	message_no = ULONG(message_no)

	res = _DecryptMessage(byref(ctx), byref(data), message_no, byref(flags))
	
	return data.Buffers
	
def EncryptMessage(ctx, data, message_no = 0, fQOP = None):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('EncryptMessage', result, SEC_E(result)))
		
	_EncryptMessage = windll.Secur32.EncryptMessage
	_EncryptMessage.argtypes = [PCtxtHandle, ULONG, PSecBufferDesc, ULONG]
	_EncryptMessage.restype  = DWORD
	_EncryptMessage.errcheck  = errc
	
	print(ctx)
	print('Encryptmessage: %s' % data)
	secbuffers = []
	secbuffers.append(SecBuffer(token = b'', buffer_type = SECBUFFER_TYPE.SECBUFFER_STREAM_HEADER))
	secbuffers.append(SecBuffer(token=data, buffer_type = SECBUFFER_TYPE.SECBUFFER_DATA))
	secbuffers.append(SecBuffer(token = b'',buffer_type = SECBUFFER_TYPE.SECBUFFER_STREAM_TRAILER))
	secbuffers.append(SecBuffer(token = b'',buffer_type = SECBUFFER_TYPE.SECBUFFER_EMPTY))
	
	data = SecBufferDesc(secbuffers)
	print(data.cBuffers)
	print(data.Buffers)
	
	flags = ULONG()
	message_no = ULONG(message_no)

	res = _EncryptMessage(byref(ctx), flags, byref(data), message_no)
	
	return data.Buffers
	

	
# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/nf-sspi-querycontextattributesa
def QueryContextAttributes(ctx, attr, sec_struct):
	#attr = SECPKG_ATTR enum
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('QueryContextAttributes', result, SEC_E(result)))
		
	_QueryContextAttributes = windll.Secur32.QueryContextAttributesW
	_QueryContextAttributes.argtypes = [PCtxtHandle, ULONG, PVOID]
	_QueryContextAttributes.restype  = DWORD
	_QueryContextAttributes.errcheck  = errc
	
	res = _QueryContextAttributes(byref(ctx), attr.value, byref(sec_struct))
	
	return
	