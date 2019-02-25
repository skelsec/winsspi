import enum
import queue
from winsspi.common.function_defs import *
from winsspi.common.gssapi.asn1_structs import *

class SSPIResult(enum.Enum):
	OK = 'OK'
	CONTINUE = 'CONT'
	ERR = 'ERR'
	
class SSPIModule(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	DIGEST = 'DIGEST'
	NEGOTIATE = 'NEGOTIATE'
	CREDSSP = 'CREDSSP'
	SCHANNEL = 'SCHANNEL'
	
class SSPI:
	def __init__(self, package_name):
		self.cred_struct = None
		self.context = None
		self.package_name = package_name
		
	def _get_credentials(self, client_name, target_name, flags = SECPKG_CRED.BOTH):
		self.cred_struct = AcquireCredentialsHandle(client_name, self.package_name.value, target_name, flags)
		
	def _init_ctx(self, target, token_data = None, flags = ISC_REQ.INTEGRITY | ISC_REQ.CONFIDENTIALITY | ISC_REQ.SEQUENCE_DETECT | ISC_REQ.REPLAY_DETECT):
		res, self.context, newbuf, outputflags, expiry = InitializeSecurityContext(self.cred_struct, target, token = token_data, ctx = self.context, flags = flags)
		print( ISC_REQ(outputflags.value))
		if res == SEC_E.OK:
			return SSPIResult.OK, newbuf[0].Buffer
		else:
			return SSPIResult.CONTINUE, newbuf[0].Buffer
			
	def _unwrap(self, data, message_no = 0):
		data_buff = DecryptMessage(self.context, data, message_no)
		return data_buff[0].Buffer
	
	def authGSSClientInit(self, client_name, target_name):
		raise Exception('Not implemented!')
	def authGSSClientStep(self, token_data):
		raise Exception('Not implemented!')
	def authGSSClientResponse(self):
		raise Exception('Not implemented!')	
	def authGSSClientResponseConf(self):
		raise Exception('Not implemented!')	
	def authGSSClientUserName(self):
		raise Exception('Not implemented!')	
	def authGSSClientUnwrap(self):
		raise Exception('Not implemented!')	
	def authGSSClientUnwrap(self):
		raise Exception('Not implemented!')	
	def authGSSClientClean(self):
		raise Exception('Not implemented!')	
	def channelBindings(self):
		raise Exception('Not implemented!')	
	def authGSSServerInit(self):
		raise Exception('Not implemented!')	
	def authGSSServerStep(self):
		raise Exception('Not implemented!')	
	def authGSSServerResponse(self):
		raise Exception('Not implemented!')
	def authGSSServerUserName(self):
		raise Exception('Not implemented!')
	def authGSSServerClean(self):
		raise Exception('Not implemented!')	

"""
.. autofunction:: authGSSClientInit
   .. autofunction:: authGSSClientStep
   .. autofunction:: authGSSClientResponse
   .. autofunction:: authGSSClientResponseConf
   .. autofunction:: authGSSClientUserName
   .. autofunction:: authGSSClientUnwrap
   .. autofunction:: authGSSClientWrap
   .. autofunction:: authGSSClientClean
   .. autofunction:: channelBindings
   .. autofunction:: authGSSServerInit
   .. autofunction:: authGSSServerStep
   .. autofunction:: authGSSServerResponse
   .. autofunction:: authGSSServerUserName
   .. autofunction:: authGSSServerClean
"""

class NegotiateSSPI(SSPI):
	def __init__(self):
		SSPI.__init__(self, SSPIModule.NEGOTIATE)
		self.client_name = None
		self.target_name = None
		self.response_data = queue.Queue()
		
	def authGSSClientInit(self, target_name, client_name = None):
		self.target_name = target_name
		self.client_name = client_name
		self._get_credentials(client_name, target_name)
		
	def authGSSClientStep(self, token_data = None):
		res, data = self._init_ctx(self.target_name, token_data)
		self.response_data.put(data)
		return res
		
	def authGSSClientResponse(self):
		return self.response_data.get()
		
	def authGSSClientUnwrap(self, data, message_no = 0):
		return self._unwrap(data, message_no)
		
class KerberosSSPI(SSPI):
	def __init__(self):
		SSPI.__init__(self, SSPIModule.KERBEROS)
		self.client_name = None
		self.target_name = None		
		self.response_data = queue.Queue()
		
	def authGSSClientInit(self, target_name, client_name = None):
		self.target_name = target_name
		self._get_credentials(self, client_name, target_name)
		
	def authGSSClientStep(self, token_data = None):
		res, data = self._init_ctx(self.target_name, token_data)
		self.response_data.put(data)
		return res
		
	def authGSSClientResponse(self):
		return self.response_data.get()
		
	def authGSSClientUnwrap(self, data, message_no = 0):
		return self._unwrap(data, message_no)
		
class KerberoastSSPI(SSPI):
	def __init__(self):
		SSPI.__init__(self, SSPIModule.KERBEROS)
		self.target_name = None
		
	def get_ticket_for_spn(self, target_name):
		self.target_name = target_name
		self._get_credentials(None, target_name)
		res, data = self._init_ctx(self.target_name, None)
		token = InitialContextToken.load(data)
		return token.native['innerContextToken'] #this is the AP_REQ
		

class LDAP3NTLMSSPI(SSPI):
	def __init__(self, user_name = None, domain = None, password = None):
		SSPI.__init__(self, SSPIModule.NTLM)
		self.client_name = None
		self.target_name = None
		
		self.authenticate_data = None
		self.flags = ISC_REQ.USE_DCE_STYLE | ISC_REQ.DELEGATE | ISC_REQ.MUTUAL_AUTH |ISC_REQ.REPLAY_DETECT |ISC_REQ.SEQUENCE_DETECT |ISC_REQ.CONFIDENTIALITY |ISC_REQ.CONNECTION
		
	def create_negotiate_message(self):
		print('MONKEY - create_negotiate_message')
		self._get_credentials(self.client_name, self.target_name, flags = SECPKG_CRED.OUTBOUND)
		res, data = self._init_ctx(self.target_name, None, flags = self.flags )
		return data
		
	def create_authenticate_message(self):
		print('MONKEY - create_authenticate_message')
		return self.authenticate_data
		
	def parse_challenge_message(self, autorize_data):
		print('MONKEY - parse_challenge_message')
		res, self.authenticate_data = self._init_ctx(self.target_name, autorize_data, flags = self.flags)
