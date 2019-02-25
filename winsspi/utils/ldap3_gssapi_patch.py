from minikerberos.sspi.kerberosspi import KerberosSSPI, SSPIResult
from ldap3.protocol.sasl.sasl import send_sasl_negotiation, abort_sasl_negotiation

def sasl_gssapi(connection, controls):
	print('MONKEY!')
	print(connection)
	print(controls)
	
	
	target_name = None
	authz_id = b""
	raw_creds = None
	creds = None
	if connection.sasl_credentials:
		if len(connection.sasl_credentials) >= 1 and connection.sasl_credentials[0]:
			if connection.sasl_credentials[0] is True:
				hostname = socket.gethostbyaddr(connection.socket.getpeername()[0])[0]
				target_name = 'ldap@' + hostname
			else:
				target_name = 'ldap@' + connection.sasl_credentials[0]
		if len(connection.sasl_credentials) >= 2 and connection.sasl_credentials[1]:
			authz_id = connection.sasl_credentials[1].encode("utf-8")
		if len(connection.sasl_credentials) >= 3 and connection.sasl_credentials[2]:
			raw_creds = connection.sasl_credentials[2]
	if target_name is None:
		target_name = 'ldap@' + connection.server.host

	print('target_name : %s' % target_name)
	print('authz_id : %s' % authz_id)
	print('raw_creds : %s' % raw_creds)
	
	target = 'ldap/WIN2019AD.test.corp'
	#target = target_name
	
	ksspi = KerberosSSPI(target)
	in_token = None
	res = None
	#while True:
	#result = send_sasl_negotiation(connection, controls, '')
	while res != SSPIResult.OK:
		res, out_token = ksspi.init_ctx(in_token)
		print(out_token)
		result = send_sasl_negotiation(connection, controls, out_token)
		in_token = result['saslCreds']
		print(in_token)
	
	
	
"""
raise Exception('Not implemented!')
	if raw_creds is not None:
		creds = gssapi.Credentials(base=raw_creds, usage='initiate', store=connection.cred_store)
	else:
		creds = gssapi.Credentials(name=gssapi.Name(connection.user), usage='initiate', store=connection.cred_store) if connection.user else None
ctx = gssapi.SecurityContext(name=target_name, mech=gssapi.MechType.kerberos, creds=creds)
    in_token = None
    try:
        while True:
            out_token = ctx.step(in_token)
            if out_token is None:
                out_token = ''
            result = send_sasl_negotiation(connection, controls, out_token)
            in_token = result['saslCreds']
            try:
                # This raised an exception in gssapi<1.1.2 if the context was
                # incomplete, but was fixed in
                # https://github.com/pythongssapi/python-gssapi/pull/70
                if ctx.complete:
                    break
            except gssapi.exceptions.MissingContextError:
                pass

        unwrapped_token = ctx.unwrap(in_token)
        if len(unwrapped_token.message) != 4:
            raise LDAPCommunicationError("Incorrect response from server")

        server_security_layers = unwrapped_token.message[0]
        if not isinstance(server_security_layers, int):
            server_security_layers = ord(server_security_layers)
        if server_security_layers in (0, NO_SECURITY_LAYER):
            if unwrapped_token.message[1:] != '\x00\x00\x00':
                raise LDAPCommunicationError("Server max buffer size must be 0 if no security layer")
        if not (server_security_layers & NO_SECURITY_LAYER):
            raise LDAPCommunicationError("Server requires a security layer, but this is not implemented")

        client_security_layers = bytearray([NO_SECURITY_LAYER, 0, 0, 0])
        out_token = ctx.wrap(bytes(client_security_layers)+authz_id, False)
        return send_sasl_negotiation(connection, controls, out_token.message)
    except (gssapi.exceptions.GSSError, LDAPCommunicationError):
        abort_sasl_negotiation(connection, controls)
raise
"""