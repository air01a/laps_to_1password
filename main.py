import onepasswordconnectsdk
from onepassword import OnePassword
from laps import LAPSio
from os import environ


VAULT_ID = environ['VAULT_ID'] 
AUTH_DOMAINS = environ['AUTH_DOMAIN'].split(';')
AUTH_USERNAME = environ['AUTH_USERNAME']
AUTH_PASSWORD = environ['AUTH_PASSWORD']
print("[+] Connecting to 1password")
one_password = OnePassword(VAULT_ID)

for domain in AUTH_DOMAINS:
    print("[+] Connecting to domain %s" % domain)
    _LAPSio = LAPSio(domain, AUTH_USERNAME, AUTH_PASSWORD)
    print("[+] Get Passwords")
    results = _LAPSio.get()
    print("[+] Push Passwords to 1password")
    for result in results:
        computer_name = result['sAMAccountName'][0].decode("utf-8") 
        computer_password = result['ms-Mcs-AdmPwd'][0].decode("utf-8")     
        print(computer_name)    
        one_password.update_or_create_token(computer_name, "administrator", computer_password)
    print("-----------\n\n")