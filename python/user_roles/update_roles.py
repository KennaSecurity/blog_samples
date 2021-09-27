import os
import sys
import json
import requests
from csv import reader

# User class with email, user ID, and role IDs.
class User:
    def __init__(self, user):
        self.email = user['email']
        self.id = user['id']
        self.role_ids = list(user['role_ids'])
        self.role_ids.sort()

    def get_id(self):
        return self.id

    def get_role_ids(self):
        return self.role_ids
        
# Retuns a dictionary of user's email to user object.
def get_user_ids(base_url, headers):
    users = {}
    list_users_url = f"{base_url}users"

    response = requests.get(list_users_url, headers=headers)
    if response.status_code != 200:
        print(f"List Users Error: {response.status_code} with {list_users_url}")
        sys.exit(1)
    
    resp_json = response.json()
    users_resp = resp_json['users']

    for user in users_resp:
        #print(f"{user['email']} : {user['id']}")
        a_user = User(user)
        users[user['email']] = a_user
    
    return users

# Returns a dictionary of role names to role ID.
def get_role_ids(base_url, headers):
    roles = {}
    list_roles_url = f"{base_url}roles"

    response = requests.get(list_roles_url, headers=headers)
    if response.status_code != 200:
        print(f"List Roles Error: {response.status_code} with {list_roles_url}")
        sys.exit(1)
    
    resp_json = response.json()
    roles_resp = resp_json['roles']

    for role in roles_resp:
        #print(f"{role['name']} : {role['id']}")
        roles[role['name']] = role['id']
    
    return roles

# Returns the role IDs for a list of role_name using the role_name_to_id dictionary.
def map_role_names_to_ids(role_name_to_id, role_names):
    role_ids = []
    role_names = [role.strip(' ') for role in role_names]

    for role_name in role_names:
        role_id = role_name_to_id.get(role_name)
        if not role_id:
            print(f"{role_name} is not on system")
            continue
        role_ids.append(role_id)

    role_ids.sort()
    return role_ids

# Updates the user with new roles.
def update_user(base_url, headers, user_id, role_ids_to_update):
    update_user_url = f"{base_url}users/{user_id}"

    update_params = {
        "user": {
            "role_ids": role_ids_to_update
        }
    }

    print(f"Updating: {user_id} - {role_ids_to_update}")

    response = requests.put(update_user_url, headers=headers, data=json.dumps(update_params))
    if response.status_code != 204:
        print(f"Update User Error: {response.status_code} with {update_user_url}")
        return
    

if __name__ == "__main__":
    print("Update User Roles")
    print("")

    csv_file_name = "user_roles.csv"
    if len(sys.argv) > 1:
        csv_file_name = sys.argv[1]

    # Obtain the Kenna Security API key from an environment variable.
    api_key = os.getenv('KENNA_API_KEY')
    if api_key is None:
        print("API key is non-existent")
        sys.exit(1)
    
    # HTTP headers.
    headers = {'X-Risk-Token': api_key,
               'Content-Type': 'application/json; charset=utf-8',
               'User-Agent': 'sample.connector_ui/1.0.0 (Cisco Secure)'}
    
    # You might have to change this depending on your deployment.
    base_url = "https://api.kennasecurity.com/"
    
    # Obtain the mapping dictionaries
    user_name_to_id = get_user_ids(base_url, headers)
    role_name_to_id = get_role_ids(base_url, headers)

    # Read each row in the CSV file and process. Skip over comments.
    with open(csv_file_name, 'r') as reader_obj:
        csv_reader = reader(reader_obj)
        for row in csv_reader:
            if row[0].startswith('#'):
                continue
            print(f"Processing: {row[0]} - {row[1:]}")
            email_from_csv = row[0]
            user_obj = user_name_to_id.get(email_from_csv)
            if not user_obj:
                print(f"{email_from_csv} is not a valid user")
                continue
            
            roles_from_csv = row[1:]
            role_ids_from_csv = map_role_names_to_ids(role_name_to_id, roles_from_csv)
            #print(f"{email_from_csv} : {role_ids_from_csv}")

            curr_roles = user_obj.get_role_ids()
            if curr_roles == role_ids_from_csv:
                print("Current roles are the same as roles to update.")
            else:
                update_user(base_url, headers, user_obj.get_id(), role_ids_from_csv)
