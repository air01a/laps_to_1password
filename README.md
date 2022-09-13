# laps_to_1password
Export LAPS password from AD to 1password vault

# Env variable
AUTH_USERNAME=ad_user
AUTH_PASSWORD=ad_password
AUTH_DOMAIN=ad_domain_name
OP_CONNECT_HOST=http://ip_1password_connector:8080
OP_CONNECT_TOKEN=1password_connect_token
VAULT_ID=1password_vault_id

# Create DB on vault 
In order to avoid to refresh all laps password in 1password, the script store the expiration date on a "secured note" on 1 password. For the script to run, you must create this secure note (name db) on the vault used for storing LAPS password. The initial value must be {}

