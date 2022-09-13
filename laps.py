
import ssl
import ldap3
from binascii import unhexlify
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.formatters.formatters import format_sid

def init_ldap_connection(domain, tls_version, username, password):
    user = '%s\\%s' % (domain, username)
    if tls_version is not None:
        use_ssl = True
        port = 636
        tls = ldap3.Tls(validate=ssl.CERT_NONE, version=tls_version)
    else:
        use_ssl = False
        port = 389
        tls = None
    ldap_server = ldap3.Server(domain, get_info=ldap3.ALL, port=port, use_ssl=use_ssl, tls=tls)
    ldap_session = ldap3.Connection(ldap_server, user=user, password=password, authentication=ldap3.NTLM, auto_bind=True)

    return ldap_server, ldap_session


def init_ldap_session( domain, username, password):


    try:
        return init_ldap_connection(domain, ssl.PROTOCOL_TLSv1_2, username, password)
    except ldap3.core.exceptions.LDAPSocketOpenError:
        return init_ldap_connection(domain, ssl.PROTOCOL_TLSv1, username, password)

class LAPSio(object):
    def __init__(self, AUTH_DOMAIN, AUTH_USERNAME, AUTH_PASSWORD):

        ldap_server, ldap_session = init_ldap_session(
            domain=AUTH_DOMAIN,
            username=AUTH_USERNAME,
            password=AUTH_PASSWORD
        )

        super(LAPSio, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.domain = AUTH_DOMAIN

 
    def get(self, since=None):
       
        print("[+] Extracting LAPS passwords of all computers ... ")
        self.ldap_session.search(
            self.ldap_server.info.other["defaultNamingContext"],
            '(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName=*))',
            attributes=['sAMAccountName', 'objectSid', 'ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime']
        )

        results = []
        for entry in self.ldap_session.response:
            if entry['type'] != 'searchResEntry':
                continue
            entry = entry["raw_attributes"]
            results.append(entry)

        sorted(results, key=lambda x:x["sAMAccountName"][0].decode('UTF-8'))
        return results
