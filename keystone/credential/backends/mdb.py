
# Copyright 2015 OpenStack Foundation
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from keystone.common.mdb import *
from keystone import config
from keystone import exception
from keystone import credential

CONF = config.CONF

CREDENTIAL_TABLE = {
        'credential': {
          'hash_key': 'id',
        }
    }

CREDENTIAL_SCHEMA = {
        'id': 'S',
        'user_id': 'S',
        'project_id': 'S',
        'blob': 'S',
        'type': 'S',
        'extra': 'S',
}

MDB = Mdb().get_client()

class Credential(credential.Driver):

    # credential crud

    def create_credential(self, credential_id, credential):
        put_cred_json = build_create_req(credential, CREDENTIAL_SCHEMA)
        for table_name, keys in CREDENTIAL_TABLE.iteritems():
            put_cred_json = append_expected_for_attr(put_cred_json,\
                    keys['hash_key'], False)
            MDB.put_item(table_name, put_cred_json)
        return credential

    def list_credentials(self, hints):
        req = build_scan_req([], [], [], CREDENTIAL_SCHEMA)
        cred_refs = MDB.scan('credential', req)
        return [strip_types_unicode(x)\
                for x in cred_refs['items']]

    def list_credentials_for_user(self, user_id):
        req = build_scan_req(['user_id'], [user_id], ['EQ'],\
                CREDENTIAL_SCHEMA)
        cred_refs = MDB.scan('credential', req)
        return [strip_types_unicode(x)\
                for x in cred_refs['items']]

    def _get_credential(self, credential_id):
        table_to_query = CREDENTIAL_TABLE['credential']
        req = build_query_req([table_to_query['hash_key']], [credential_id], ['EQ'],\
                CREDENTIAL_SCHEMA)

        cred_ref = MDB.query('credential', req)
        if cred_ref['count'] == 0:
            raise exception.CredentialNotFound(credential_id=credential_id)
        elif cred_ref['count'] != 1:
            raise Exception("More than one credential with same id")
        else:
            cred_ref = strip_types_unicode(cred_ref['items'][0])
        return cred_ref

    def get_credential(self, credential_id):
        cred_ref = self._get_credential(credential_id)
        if type(cred_ref) is not dict:
            cred_ref = cred_ref.to_dict()
        return cred_ref

    def update_credential(self, credential_id, credential):
        old_cred = self._get_credential(credential_id)
        new_cred = credential

        req = build_update_req(CREDENTIAL_TABLE['credential'].values(),
                CREDENTIAL_SCHEMA, new_cred, old_cred)
        #req = append_return_values(req, 'ALL_NEW')
        res = MDB.update_item('credential', req)

        #return strip_types_unicode(res['attributes'])
        # magnetoDB bug #1423058 
        # update_item doesn't return the updated value
        ret_val = old_cred.copy()
        for key in new_cred:
            ret_val[key] = new_cred[key]
        return ret_val

    def delete_credential(self, credential_id):
        req = build_delete_req([CREDENTIAL_TABLE['credential']['hash_key']],
                [credential_id], CREDENTIAL_SCHEMA)
        MDB.delete_item('credential', req)

    def delete_credentials_for_project(self, project_id):
        req = build_scan_req(['project_id'], [project_id], ['EQ'],\
                CREDENTIAL_SCHEMA)
        cred_refs = MDB.scan('credential', req)
        for cred in cred_refs['items']:
            self.delete_credential(cred['id'].values()[0])

    def delete_credentials_for_user(self, user_id):
        req = build_scan_req(['user_id'], [user_id], ['EQ'],\
                CREDENTIAL_SCHEMA)
        cred_refs = MDB.scan('credential', req)
        for cred in cred_refs['items']:
            self.delete_credential(cred['id'].values()[0])
