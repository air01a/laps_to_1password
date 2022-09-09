
from onepasswordconnectsdk.client import (
        new_client_from_environment
    )
from onepasswordconnectsdk.models import (ItemVault, Field)
import onepasswordconnectsdk

class OnePassword:
        
    def create_token(self, server, username, password):
        item = onepasswordconnectsdk.models.Item(vault=ItemVault(id=self.vault_id),
                                        
                                        title=server,
                                        category="LOGIN",
                                        tags=["laps"],
                                        fields=[Field(value=username,
                                                                    purpose="USERNAME"), Field(value=password,purpose="PASSWORD")],
                                        )
        self.client.create_item(self.vault_id, item)

    def read_token(self, server):
        try:
            return self.client.get_item_by_title(server, self.vault_id)
        except:
            return None

    def update_token(self, item, new_password):
        for field in item.fields:
            if field.id=="password":
                field.value = new_password
        self.client.update_item(item.id, self.vault_id, item)
                            
    def update_or_create_token(self, servername, username, password):
        item = self.read_token(servername)
        if item:
            self.update_token(item, password)
        else:
            self.create_token(servername, username, password)
        

    def __init__(self, vault_id):
        self.vault_id = vault_id
        self.client = new_client_from_environment()
