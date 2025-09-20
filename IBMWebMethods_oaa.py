
#!env python3
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
import os
import sys
import requests

from dotenv import load_dotenv
load_dotenv()

def get_token():

    # Get token
    resp = requests.post("http://127.0.0.1:5000/oauth/token", data={
        "grant_type": "client_credentials",
        "client_id": os.getenv('client_id'),
        "client_secret": os.getenv('client_secret')
    })
    return resp.json()["access_token"]


def connect_to_veza():
    veza_url = os.getenv('VEZA_URL')
    veza_api_key = os.getenv('VEZA_API_KEY')
    if None in (veza_url, veza_api_key):
        print("Unable to find all environment variables")
        sys.exit(1)

    return OAAClient(url=veza_url, api_key=veza_api_key)

def get_ibm_webmethods_users(token):
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/users', headers=headers)
    return response.json()

def get_ibm_webmethods_teams(token):
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/accessProfiles', headers=headers)
    return response.json()

def get_ibm_webmethods_groups(token):
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/groups', headers=headers)
    return response.json()

def main():


    # Create an instance of the OAA CustomApplication class, modeling the application name and type
    custom_app = CustomApplication(name="IBMWebMethods", application_type="IBMWebMethods")

    #Role properties definition
    custom_app.property_definitions.define_local_role_property('id', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('description', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('systemDefined', OAAPropertyType.STRING)

    #Grouop properties definition
    custom_app.property_definitions.define_local_group_property('description', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_group_property('type', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_group_property('name', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_group_property('systemDefined', OAAPropertyType.BOOLEAN)
    
 
    # In the OAA payload, each permission native to the custom app is mapped to the Veza effective permission (data/non-data C/R/U/D).
    # Permissions must be defined before they can be referenced, as they are discovered or ahead of time.
    # For each custom application permission, bind them to the Veza permissions using the `OAAPermission` enum:
    custom_app.add_custom_permission("ManageAPIs", [OAAPermission.DataRead, OAAPermission.DataWrite,OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("API-Gateway-Administrators", [OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage APIs", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage aliases", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage policy templates", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Activate / Deactivate APIs", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage global policies", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage threat protection configurations", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage applications", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Activate / Deactivate global policies", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Publish API to service registry", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Publish to API Portal", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal configurations", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal themes", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal pages", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal users", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal assets", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage portal notifications", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage scope mapping", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage access profiles", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage role mapping", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage users", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage groups", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage system configurations", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage security configurations", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage email server settings", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    custom_app.add_custom_permission("Manage external authentications", [OAAPermission.MetadataCreate, OAAPermission.MetadataDelete, OAAPermission.MetadataWrite, OAAPermission.MetadataRead])
    
    # Privilege mapping: index in string to permission name
    privilege_map = {
        0: "Manage APIs",
        1: "Manage aliases",
        2: "Manage policy templates",
        3: "Activate / Deactivate APIs",
        4: "Manage global policies",
        5: "Manage threat protection configurations",
        6: "Manage applications",
        7: "Activate / Deactivate global policies",
        8: "Publish API to service registry",
        9: "Publish to API Portal",
        10: "Manage scope mapping",
        11: "Manage access profiles",
        12: "Manage role mapping",
        13: "Manage users",
        14: "Manage groups",
        15: "Manage system configurations",
        16: "Manage security configurations",
        17: "Manage email server settings",
        18: "Manage external authentications"
    }

    # Define USers Custom Properties    
    custom_app.property_definitions.define_local_user_property('firstName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('lastName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('language', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('type', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('active', OAAPropertyType.BOOLEAN)
    custom_app.property_definitions.define_local_user_property('allowDigestAuth', OAAPropertyType.BOOLEAN)
    
    #Get Token
    try:
        token = get_token()
    except Exception as e:
        print("Error getting token:", e)

    #Add Users
    response = get_ibm_webmethods_users(token)
    for user in response['users']:
        # Add local user.
        new_user = custom_app.add_local_user(
                                                user.get('loginId'),
                                                unique_id=user.get('id')
                                            )
        new_user.set_property('firstName', user.get('firstName'))
        new_user.set_property('lastName', user.get('lastName'))
        new_user.set_property('type', user.get('type'))
        new_user.set_property('active', user.get('active'))
        new_user.set_property('allowDigestAuth', user.get('allowDigestAuth'))

    #add Groups
    response = get_ibm_webmethods_groups(token)
    for group in response['groups']:
        # Add local group.
        new_group = custom_app.add_local_group(group.get('name'), unique_id=group.get('id'))
        new_group.set_property('description', group.get('description'))
        new_group.set_property('type', group.get('type'))
        new_group.set_property('systemDefined', group.get('systemDefined'))
        new_group.set_property('name', group.get('name'))
        # Add users to the group 
        for user_id in group.get('userIds', []):
            member = custom_app.local_users.get(user_id)
            member.add_group(group.get('id'))

    #add Teams/AccessProfiles
    accessProfiles = get_ibm_webmethods_teams(token)
    for profile in accessProfiles['members']:
        privilege_str = profile.get('privilege', '')
        permissions = []
        for idx, char in enumerate(privilege_str):
            if char == '1' and idx in privilege_map:
                permissions.append(privilege_map[idx])
        # Add local role with mapped permissions
        new_role = custom_app.add_local_role(profile.get('name'), unique_id=profile.get('id'))
        new_role.set_property('description', profile.get('description'))
        new_role.set_property('systemDefined', profile.get('systemDefined'))
        new_role.set_property('id', profile.get('id'))    
        new_role.add_permissions(permissions=permissions)
        # assign roles to groups
        group_ids = profile.get('groupIds', [])
        for group_id in group_ids:
            group = custom_app.local_groups.get(group_id)
            if group:
                group.add_role(profile.get('id'), apply_to_application=True)
        
    #push data to Veza
    veza_con = connect_to_veza()
    provider_name = "IBMWebMethods"
    provider = veza_con.get_provider(provider_name)
    if provider:
        print("-- Found existing provider")
    else:
        print(f"++ Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    print(f"-- Provider: {provider['name']} ({provider['id']})")

    # Push the metadata payload:

    try:
        response = veza_con.push_application(provider_name,
                                               data_source_name=f"{custom_app.name} ({custom_app.application_type})",
                                               application_object=custom_app,
                                               save_json=False
                                               )
        if response.get("warnings", None):
            # Veza may return warnings on a successful uploads. These are informational warnings that did not stop the processing
            # of the OAA data but may be important. Specifically identities that cannot be resolved will be returned here.
            print("-- Push succeeded with warnings:")
            for e in response["warnings"]:
                print(f"  - {e}")
    except OAAClientError as e:
        # If there are any errors connecting to the Veza API or processing the payload the client will raise an `OAAClientError`
        print(f"-- Error: {e.error}: {e.message} ({e.status_code})", file=sys.stderr)
        if hasattr(e, "details"):
            # Error details will have specifics on any issues encountered processing the payload
            for d in e.details:
                print(f"  -- {d}", file=sys.stderr)
    return



if __name__ == '__main__':
    main()
