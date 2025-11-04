
#!env python3
import argparse
from oaaclient.client import OAAClient, OAAClientError
from oaaclient.templates import CustomApplication, OAAPermission, OAAPropertyType
import os
import sys
import requests
import logging

from dotenv import load_dotenv
from IBMWebMethods_CacheAuth import logging_in_extract_json
load_dotenv()


def setup_logging(enable_logging=True, log_file=None):
    if enable_logging:
        logging.basicConfig(
            format='%(asctime)s %(levelname)s: %(message)s',
            level=logging.getLevelName(os.environ.get('LOG_LEVEL', 'INFO').upper()),
            filename=log_file
        )
    else:
        logging.disable(logging.CRITICAL)
    return logging.getLogger(__name__)

def get_token():

    # Get token
    resp = requests.post(os.getenv('IBMWebMethods_TokenURL'), data={
        "grant_type": "client_credentials",
        "client_id": os.getenv('client_id'),
        "client_secret": os.getenv('client_secret')
        #"scope": "profile"
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

def main():
    # Parse command-line arguments for logging
    parser = argparse.ArgumentParser(description='IBMWebMethod OAA Script')
    parser.add_argument('--log', dest='enable_logging', action='store_true', help='Enable logging to file')
    parser.add_argument('--no-log', dest='enable_logging', action='store_false', help='Disable logging')
    parser.set_defaults(enable_logging=True)
    parser.add_argument('--log-file', type=str, default='ibmWebMethodOAA.log', help='Log file name (default: ibmWebMethodOAA.log)')
    parser.add_argument('--log-level', type=str, default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], help='Set log level')
    args = parser.parse_args()

    # Set log level as environment variable for setup_logging
    os.environ['LOG_LEVEL'] = args.log_level
    log = setup_logging(args.enable_logging, args.log_file)

    log.info("Starting ConceptOne OAA Script...")
    # Create an instance of the OAA CustomApplication class, modeling the application name and type
    custom_app = CustomApplication(name="IBMWebMethods", application_type="IBMWebMethods")

    log.info("Defining role properties...")
    #Role properties definition
    custom_app.property_definitions.define_local_role_property('id', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('containerId', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('name', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('description', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('productRole', OAAPropertyType.BOOLEAN)
    custom_app.property_definitions.define_local_role_property('clientId', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('clientName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_role_property('wellKnowSwagRealmRole', OAAPropertyType.BOOLEAN)

    log.info("Defining user properties...")
    # Define Users Custom Properties
    custom_app.property_definitions.define_local_user_property('firstName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('lastName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('idpDispName', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('localUser', OAAPropertyType.BOOLEAN)
    custom_app.property_definitions.define_local_user_property('username', OAAPropertyType.STRING)
    custom_app.property_definitions.define_local_user_property('email', OAAPropertyType.STRING)

    # Use cached authentication helper to get token and users JSON
    try:
        result = logging_in_extract_json()
        # check if result contains "error"
        if result.__contains__('ERROR'):
            log.error("No result returned from logging_in_extract_json")
            print("No result returned from logging_in_extract_json")
            sys.exit(1)
        else:
            response = result
            log.debug(f"logging_in_extract_json result: {response}")
        log.info("Obtained authentication/users via logging_in_extract_json")
    except Exception as e:
        log.error(f"Error calling logging_in_extract_json: {e}")
        sys.exit(1)
    for user in response['userList']:
        log.debug(f"Processing user: {user.get('username')}")
        # Add local user.
        new_user = custom_app.add_local_user(
            user.get('username'),
            unique_id=user.get('id')
        )
        log.debug(f"Added user: {user.get('username')} with ID: {user.get('id')}")
        log.debug(f"User details: {user}")
        new_user.set_property('firstName', user.get('firstName'))
        new_user.set_property('lastName', user.get('lastName'))
        new_user.is_active = True
        idp_disp_name = user.get('idpDispName')
        new_user.set_property('idpDispName', user.get('idpDispName'))
        if idp_disp_name == "IBM webMethods iPaaS":
            new_user.set_property('localUser', True)
            log.debug(f"User {user.get('username')} set as localUser=True")
        else:
            new_user.set_property('localUser', False)
            log.debug(f"User {user.get('username')} set as localUser=False")
        new_user.set_property('email', user.get('email'))
        # Create and assign roles to user
        log.debug(f"Assigning roles {user.get('roles', [])} to user: {user.get('username')}")
        for role in user.get('roles', []):
            existing_role = custom_app.local_roles.get(role.get('id'))
            log.debug(f"Processing role: {role.get('name')} for user: {user.get('username')}")
            if existing_role is None:
                log.debug(f"Role do not exist. Creating new role: {role.get('name')} with ID: {role.get('id')}")
                new_role = custom_app.add_local_role(role.get('name'), unique_id=role.get('id'), permissions=None)
                new_role.set_property('description', role.get('description'))
                new_role.set_property('containerId', role.get('containerId'))
                new_role.set_property('productRole', role.get('productRole'))
                new_role.set_property('clientId', role.get('clientId'))
                new_role.set_property('clientName', role.get('clientName'))
                new_role.set_property('wellKnowSwagRealmRole', role.get('wellKnowSwagRealmRole'))
            #add user to role
            log.debug(f"Adding role: {role.get('name')} to user: {user.get('username')}")
            new_user.add_role(role.get('id'), apply_to_application=True)
    log.info("Users processed successfully.")
        
    #push data to Veza
    log.info("Connecting to Veza...")
    veza_con = connect_to_veza()
    provider_name = "IBMWebMethods"
    provider = veza_con.get_provider(provider_name)
    if provider:
        log.info("-- Found existing provider")
    else:
        log.info(f"++ Creating Provider {provider_name}")
        provider = veza_con.create_provider(provider_name, "application")
    log.info(f"-- Provider: {provider['name']} ({provider['id']})")

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
            log.info("-- Push succeeded with warnings")
            print(f"-- Push succeeded with warnings")
            for e in response["warnings"]:
                log.debug(f"Warning during push: {e}")
        else:
            log.info("-- Push succeeded without warnings")
            print(f"-- Push succeeded without warnings")
    except OAAClientError as e:
        # If there are any errors connecting to the Veza API or processing the payload the client will raise an `OAAClientError`
        log.error(f"-- Error: {e.error}: {e.message} ({e.status_code})")
        if hasattr(e, "details"):
            # Error details will have specifics on any issues encountered processing the payload
            for d in e.details:
                log.error(f"  -- {d}")
    return



if __name__ == '__main__':
    main()
