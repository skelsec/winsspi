"""

Uses ctypes to wrap API for win32 SSPI

The two basic calls are:
    AcquireCredentialsHandle
    InitializeSecurityContext

The main complexity is management of the memory structures which must be passed
back and forth with these calls. In particular, a third call is necessary to 
ascertain the size of the buffer for receiving the security token (or
otherwise to deallocate it).

Taking care that memory does not leak and is not prematurely deallocated,
container types need to reference objects or cast pointer objects.

"""
import ctypes

from ctypes import Structure, POINTER, pointer, c_void_p as PVOID, sizeof, cast, c_wchar_p, byref
from ctypes.wintypes import ULONG


# call API to get max token size, or..
maxtoken = 2880 # bytes

########################  TYPE DECLARATIONS #########################

SecStatus = ULONG # Security status type
# winerror.h : SEC_E_OK = 0 (unqualified success)
#              SEC_I_CONTINUE_NEEDED = 0x00090312 = 590610 (success but must call again)

TimeStamp = ctypes.c_int64 # SECURITY_INTEGER type: 100ns intervals since 1601 UTC.
                           # Never == within hours of overflow
class SecHandle(Structure): 
    """ Type definition for CredHandle and CtxtHandle objects """
    _fields_ = [('dwLower',POINTER(ULONG)),('dwUpper',POINTER(ULONG))]
    def __init__(self): # populate deeply (empty memory fields) rather than shallow null pointers.
        Structure.__init__(self, pointer(ULONG()), pointer(ULONG()))
 
class SecBuffer(Structure):
    """Stores a memory buffer: size, type-flag, and pointer. 
    The type can be empty (0) or token (2).
    InitializeSecurityContext will write to the buffer that is flagged "token"
    and update the size, or else fail 0x80090321=SEC_E_BUFFER_TOO_SMALL."""    
    _fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',PVOID)]
    def __init__(self, token=maxtoken):
        buf = ctypes.create_string_buffer(token) 
        Structure.__init__(self,sizeof(buf),2,cast(pointer(buf),PVOID))
    @property
    def Buffer(self):
        return ctypes.string_at(self.pvBuffer, size=self.cbBuffer)     
    
class SecBufferDesc(Structure):
    """Descriptor stores SECBUFFER_VERSION=0, number of buffers (e.g. one),
    and pointer to an array of SecBuffer structs."""
    _fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
    def __init__(self, *args):
        Structure.__init__(self,0,1,pointer(SecBuffer(*args)))
    def __getitem__(self, index):
        return self.pBuffers[index]

########################  SSPI API CALLS #########################

acquire = ctypes.windll.secur32.AcquireCredentialsHandleW
acquire.argtypes = [c_wchar_p]*2 + [ULONG] + [PVOID]*4 + [POINTER(SecHandle), POINTER(TimeStamp)]
acquire.restype = SecStatus

init = ctypes.windll.secur32.InitializeSecurityContextW
init.argtypes = [PVOID]*2 + [c_wchar_p] + [ULONG]*3 + [PVOID,ULONG] + [PVOID]*4
init.restype = SecStatus

########################  External Interface #########################


class ClientAuth():
    def __init__(self, scheme=u'NTLM'):
        self.context = None
        self.credential = SecHandle()        
        expiry = TimeStamp()
        r = acquire(None,u'NTLM',2,None,None,None,None,byref(self.credential),byref(expiry))
        assert r==0
    def authorize(self, challenge=None, flags=65564):       
        expiry = TimeStamp()
        outputflags = ULONG()
        newbuf = SecBufferDesc()
        
        if challenge is None: # first invocation
            self.context = SecHandle()            
            r = init(byref(self.credential), None, None, 
                     flags, 0, 0, None, 0, byref(self.context),
                     byref(newbuf), byref(outputflags), byref(expiry))            
        else: # second invocation
            assert self.context is not None
            oldbuf = SecBufferDesc(challenge)   
            r = init(byref(self.credential), byref(self.context), None, 
                     flags, 0, 0, byref(oldbuf), 0, byref(self.context),
                     byref(newbuf), byref(outputflags), byref(expiry))                     
        return r, newbuf
        














