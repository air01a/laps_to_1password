import onepasswordconnectsdk
from onepassword import OnePassword
from laps import LAPSio
from os import environ
from datetime import datetime
from json import dumps, loads


VAULT_ID = environ['VAULT_ID'] 
AUTH_DOMAINS = environ['AUTH_DOMAIN'].split(';')
AUTH_USERNAME = environ['AUTH_USERNAME']
AUTH_PASSWORD = environ['AUTH_PASSWORD']

def main():

    print("[+] Connecting to 1password")
    one_password = OnePassword(VAULT_ID)

    print("[+] Retrieving database")
    json_db=one_password.read_token("db")
    db = loads(json_db.fields[0].value)

    for domain in AUTH_DOMAINS:
        print("[+] Connecting to domain %s" % domain)
        _LAPSio = LAPSio(domain, AUTH_USERNAME, AUTH_PASSWORD)
        print("[+] Get Passwords")
        results = _LAPSio.get()
        print("[+] Push Passwords to 1password")

        for result in results:
            computer_name = result['sAMAccountName'][0].decode("utf-8") 
            computer_password = result['ms-Mcs-AdmPwd'][0].decode("utf-8") 
            expiration_time =result['ms-Mcs-AdmPwdExpirationTime'][0].decode("utf-8")     
            
            if computer_name not in db.keys() or db[computer_name]!=expiration_time:
                print("         UPDATING %s" % computer_name) 
                one_password.update_or_create_token(computer_name, "administrator", computer_password)
            else:
                print("         %s password has not been changed" % computer_name)

            db[computer_name]=expiration_time

        print("-----------\n\n")

    print("[+] Updating DB")
    json_db.fields[0].value = dumps(db)
    one_password.update_token(json_db)


if __name__ == "__main__":
    main()
