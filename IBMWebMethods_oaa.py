#!env python3
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
import os
import sys
import requests

from dotenv import load_dotenv
load_dotenv()


def connect_to_veza():
    veza_url = os.getenv('VEZA_URL')
    veza_api_key = os.getenv('VEZA_API_KEY')
    if None in (veza_url, veza_api_key):
        print("Unable to find all environment variables")
        sys.exit(1)

    return OAAClient(url=veza_url, api_key=veza_api_key)

def get_ibm_webmethods_users():
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {ibm_webmethods_api_key}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/users', headers=headers)
    return response.json()

def get_ibm_webmethods_teams():
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {ibm_webmethods_api_key}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/accessProfiles', headers=headers)
    return response.json()

def get_ibm_webmethods_groups():
    ibm_webmethods_url = os.getenv('IBMWebMethods_URL')
    ibm_webmethods_api_key = os.getenv('IBMWebMethods_API_KEY')
    if None in (ibm_webmethods_url, ibm_webmethods_api_key):
        print("Unable to find all environment variables for IBM WebMethods")
        sys.exit(1)

    headers = {
        'Authorization': f'Bearer {ibm_webmethods_api_key}',
        'Accept': 'application/json'
    }

    response = requests.get(f'{ibm_webmethods_url}/groups', headers=headers)
    return response.json()

def main():


    # Create an instance of the OAA CustomApplication class, modeling the application name and type
    custom_app = CustomApplication(name="IBMWebMethods", application_type="IBMWebMethods")
 
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
    
    # Add Local Users
    response = get_ibm_webmethods_users()
    for user in response['users']:
        # Add local user.
        new_user = custom_app.add_local_user(user.get('loginId'), 
                                        identities=[user.get('email')])


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

    accessProfiles = get_ibm_webmethods_teams()
    for profile in accessProfiles['members']:
        privilege_str = profile.get('privilege', '')
        permissions = []
        for idx, char in enumerate(privilege_str):
            if char == '1' and idx in privilege_map:
                permissions.append(privilege_map[idx])
        # Add local role with mapped permissions
        new_role = custom_app.add_local_role(profile.get('name'))
        new_role.add_permissions(permissions=permissions)
        
    #add Groups
    response = get_ibm_webmethods_groups()
    for group in response['groups']:
        # Add local group.
        new_group = custom_app.add_local_group(group.get('name'))
        # Add users to the group
        for user_id in group.get('userIds', []):
            member = custom_app.local_users.get(user_id)
            member.add_group(new_group.name)

    # assign roles to groups
    for profile in accessProfiles['members']:
        group_ids = profile.get('groupIds', [])
        for group_id in group_ids:
            group = custom_app.local_groups.get(group_id)
            if group:
                group.add_role(profile.get('name'), apply_to_application=True)

    
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
