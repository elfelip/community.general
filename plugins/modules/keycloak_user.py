#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2019, INSPQ <philippe.gauthier@inspq.qc.ca>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: keycloak_user
short_description: create and Configure a user in Keycloak
description:
    - This module creates, removes or update Keycloak users.
version_added: "2.9"
options:
    realm:
        description:
            - The name of the realm in which is the client.
        default: master
        type: str
    username:
        description:
            - username for the user.
        required: true
        type: str
    id:
        description:
            - ID of the user on the keycloak server if known
        type: str
    enabled:
        description:
            - Enabled user.
        default: true
        type: bool
    email_verified:
        description:
            - check the validity of user email.
        default: false
        type: bool
        aliases:
            - emailVerified
    first_name:
        description:
            - User firstName.
        required: false
        type: str
        aliases:
            - firstName
    last_name:
        description:
            - User lastName.
        required: false
        type: str
        aliases:
            - lastName
    email:
        description:
            - User email.
        required: false
        type: str
    federation_link:
        description:
            - Federation Link.
        required: false
        type: str
        aliases:
            - federationLink
    service_account_client_id:
        description:
            - Description of the client Application.
        required: false
        type: str
        aliases:
            - serviceAccountClientId
    realm_roles:
        description:
            - List of realm roles for the user.
        required: false
        type: list
        elements: str
        aliases:
            - realmRoles
    client_roles:
        description:
            - List of ClientRoles for the user.
        required: false
        type: list
        elements: dict
        aliases:
            - clientRoles
        suboptions:
            client_id:
                description:
                    - Client ID for the role
                type: str
                required: true
                aliases:
                    - clientId
            roles:
                description:
                    - List of roles for this client to grant to the user.
                type: list
                required: true
                elements: str
    client_consents:
        description:
            - client Authenticator Type.
        required: false
        type: list
        elements: dict
        aliases:
            - clientConsents
        suboptions:
            client_id:
                description:
                - Client ID of the client role. Not the technical id of the client.
                type: str
                required: true
                aliases:
                    - clientId
            roles:
                description:
                - List of client roles to assign to the user
                type: list
                required: true
    groups:
        description:
            - List of groups for the user.
        type: list
        elements: str
    credentials:
        description:
            - User credentials.
        required: false
        type: list
        elements: dict
        suboptions:
            type:
                description:
                    - Credential type
                type: str
                required: true
            value:
                description:
                    - Value of the credential
                type: list
                required: true
            temporary:
                description:
                    - If true, the users require to reset this credentials at next logon.
                type: bool
                default: false
    required_actions:
        description:
            - requiredActions user Auth.
        required: false
        type: list
        aliases:
            - requiredActions
    federated_identities:
        description:
            - list of IDP of user.
        required: false
        type: list
        elements: str
        aliases:
            - federatedIdentities
    attributes:
        description:
            - list user attributes.
        required: false
        type: dict
    access:
        description:
            - list user access.
        required: false
        type: dict
    disableable_credential_types:
        description:
            - list user Credential Type.
        required: false
        type: list
        elements: str
        aliases:
            - disableableCredentialTypes
    origin:
        description:
            - user origin.
        required: false
        type: str
    self:
        description:
            - user self administration.
        required: false
        type: str
    state:
        description:
            - Control if the user must exists or not
        choices: [ "present", "absent" ]
        default: present
        required: false
        type: str
    force:
        description:
            - If true, allows to remove user and recreate it.
        type: bool
        default: false
extends_documentation_fragment:
    - keycloak
notes:
    - module does not modify userId.
author:
    - Philippe Gauthier (@elfelip)
'''

EXAMPLES = '''
    - name: Create a user user1
      keycloak_user:
        auth_keycloak_url: http://localhost:8080/auth
        auth_sername: admin
        auth_password: password
        realm: master
        username: user1
        firstName: user1
        lastName: user1
        email: user1
        enabled: true
        emailVerified: false
        credentials:
          - type: password
            value: password
            temporary: false
        attributes:
          attr1:
            - value1
          attr2:
            - value2
        clientRoles:
          - clientId: client1
            roles:
            - role1
          - clientId: client2
            roles:
            - role2
        groups:
          - group1
        realmRoles:
          - Role1
        state: present

    - name: Re-create a User
      keycloak_user:
        auth_keycloak_url: http://localhost:8080/auth
        auth_username: admin
        auth_password: password
        realm: master
        username: user1
        firstName: user1
        lastName: user1
        email: user1
        enabled: true
        emailVerified: false
        credentials:
          - type: password
            value: password
            temporary: false
        attributes:
          attr1:
            - value1
          attr2:
            - value2
        clientRoles:
          - clientId: client1
            roles:
            - role1
          - clientId: client2
            roles:
            - role2
        groups:
          - group1
        realmRoles:
          - Roles1
        state: present
        force: yes

    - name: Remove User.
      keycloak_user:
        auth_keycloak_url: http://localhost:8080/auth
        auth_sername: admin
        auth_password: password
        realm: master
        username: user1
        state: absent
'''

RETURN = '''
user:
  description: JSON representation for the user.
  returned: on success
  type: dict
msg:
  description: Message if it is the case
  returned: always
  type: str
changed:
  description: Return True if the operation changed the client on the keycloak server, false otherwise.
  returned: always
  type: bool
'''
from ansible_collections.community.general.plugins.module_utils.identity.keycloak.keycloak import KeycloakAPI, camel, \
    keycloak_argument_spec, get_token, KeycloakError, is_struct_included
from ansible.module_utils.basic import AnsibleModule
import copy


def main():
    argument_spec = keycloak_argument_spec()

    client_role_spec = dict(
        client_id=dict(type='str', required=True, aliases=['clientId']),
        roles=dict(type='list', required=True, elements='str'),
    )
    credential_spec = dict(
        type=dict(type='str', required=True),
        value=dict(type='str', required=True),
        temporary=dict(type='bool', default=False)
    )
    meta_args = dict(
        realm=dict(type='str', default='master'),
        self=dict(type='str'),
        id=dict(type='str'),
        username=dict(type='str', required=True),
        first_name=dict(type='str', aliases=['firstName']),
        last_name=dict(type='str', aliases=['lastName']),
        email=dict(type='str'),
        enabled=dict(type='bool', default=True),
        email_verified=dict(type='bool', default=False, aliases=['emailVerified']),
        federation_link=dict(type='str', aliases=['federationLink']),
        service_account_client_id=dict(type='str', alises=['serviceAccountClientId']),
        attributes=dict(type='dict'),
        access=dict(type='dict'),
        client_roles=dict(type='list', default=[], options=client_role_spec, aliases=['clientRoles'], elements='dict'),
        realm_roles=dict(type='list', default=[], aliases=['realmRoles'], elements='str'),
        groups=dict(type='list', default=[], elements='str'),
        disableable_credential_types=dict(type='list', default=[], aliases=['disableableCredentialTypes'], elements='str'),
        required_actions=dict(type='list', default=[], aliases=['requiredActions'], elements='str'),
        credentials=dict(type='list', default=[], elements='dict', options=credential_spec),
        federated_identities=dict(type='list', default=[], aliases=['federatedIdentities'], elements='str'),
        client_consents=dict(type='list', default=[], aliases=['clientConsents'], elements='str'),
        origin=dict(type='str'),
        state=dict(choices=["absent", "present"], default='present'),
        force=dict(type='bool', default=False),
    )
    argument_spec.update(meta_args)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True,
                           required_one_of=([['token', 'auth_realm', 'auth_username', 'auth_password']]),
                           required_together=([['auth_realm', 'auth_username', 'auth_password']]))

    result = dict(changed=False, msg='', diff={}, proposed={}, existing={}, end_state={})

    # Obtain access token, initialize API
    try:
        connection_header = get_token(module.params)
    except KeycloakError as e:
        module.fail_json(msg=str(e))

    kc = KeycloakAPI(module, connection_header)

    realm = module.params.get('realm')
    state = module.params.get('state')
    force = module.params.get('force')
    username = module.params.get('username')
    realm_roles = module.params.get('realm_roles')
    client_roles = module.params.get('client_roles')

    # Filter and map the parameters names that apply to the user
    user_params = [x for x in module.params
                   if x not in list(keycloak_argument_spec().keys()) + ['state', 'realm', 'realm_roles', 'client_roles', 'force'] and
                   module.params.get(x) is not None]

    before_user = kc.search_user_by_username(username=username, realm=realm)

    if before_user is None:
        before_user = {}

    changeset = {}

    for param in user_params:
        new_param_value = module.params.get(param)
        old_value = before_user[param] if param in before_user else None
        if new_param_value != old_value:
            changeset[camel(param)] = new_param_value
    # Prepare the desired values using the existing values (non-existence results in a dict that is save to use as a basis)
    desired_user = copy.deepcopy(before_user)
    desired_user.update(changeset)

    result['proposed'] = changeset
    result['existing'] = before_user

    changed = False

    # Cater for when it doesn't exist (an empty dict)
    if state == 'absent':
        if not before_user:
            # Do nothing and exit
            if module._diff:
                result['diff'] = dict(before='', after='')
            result['changed'] = False
            result['end_state'] = {}
            result['msg'] = 'Role does not exist, doing nothing.'
            module.exit_json(**result)
        else:
            # Delete user
            kc.delete_user(user_id=before_user['id'], realm=realm)
            result["msg"] = 'User %s deleted' % (before_user['id'])
            changed = True

    else:
        after_user = {}
        if force:  # If the force option is set to true
            # Delete the existing user
            kc.delete_user(user_id=before_user["id"], realm=realm)
            
        if not before_user or force:
            # Process a creation
            changed = True

            if username is None:
                module.fail_json(msg='username must be specified when creating a new user')

            if module._diff:
                result['diff'] = dict(before='', after=desired_user)

            if module.check_mode:
                module.exit_json(**result)
            # Create the user
            after_user = kc.create_user(userrep=desired_user, realm=realm)
            # Add user ID to new representation
            desired_user['id'] = after_user["id"]
        else:
            excludes = [
                "access",
                "notBefore",
                "createdTimestamp",
                "totp",
                "credentials",
                "disableableCredentialTypes",
                "realmRoles",
                "clientRoles",
                "groups",
                "clientConsents",
                "federatedIdentities",
                "requiredActions"]
            # Add user ID to new representation
            desired_user['id'] = before_user["id"]
            
            # Compare users
            if not (is_struct_included(desired_user, before_user, excludes)):  # If the new user does not introduce a change to the existing user
                # Update the user
                after_user = kc.update_user(userrep=desired_user, realm=realm)
                changed = True
                
        # Assign roles to user
        if kc.assing_realm_roles_to_user(user_id=desired_user["id"], roles=realm_roles, realm=realm):
            changed = True
        if kc.assing_client_roles_to_user(user_id=desired_user["id"], roles=client_roles, realm=realm):
            changed = True
        # set user groups
        if kc.update_user_groups_membership(userrep=desired_user, realm=realm):
            changed = True
        # Get the updated user realm roles
        after_user["realmRoles"] = kc.get_user_realm_roles(user_id=desired_user["id"], realm=realm)
        # Get the user clientRoles
        after_user["clientRoles"] = kc.get_user_client_roles(user_id=desired_user["id"], realm=realm)
        # Get the user groups
        after_user["groups"] = kc.get_user_groups(user_id=desired_user["id"], realm=realm)
        result["end_state"] = after_user

    result['changed'] = changed
    module.exit_json(**result)


if __name__ == '__main__':
    main()
