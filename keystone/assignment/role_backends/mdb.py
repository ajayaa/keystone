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

from keystone import assignment
from keystone.common import sql
from keystone import exception
from keystone.common.mdb import *
from keystone.i18n import _

TABLES = {
    'role': {
        'hash_key': 'id',
        'range_key': 'name'
    },
    'role_name_index': {
        'hash_key': 'name'
    }
}

SCHEMA = {
    'role': {
        'id': 'S',
        'name': 'S',
        'extra': 'S'
    },
    'role_name_index': {
        'name': 'S'
    }
}

MDB = Mdb().get_client()


class Role(assignment.RoleDriver):

    def create_role(self, role_id, role):
        d = {'name': role['name']}
        req = build_create_req(d, SCHEMA['role_name_index'])
        req = append_if_not_exists(req, TABLES['role_name_index']['hash_key'])
        try:
            MDB.put_item('role_name_index', req)
        except Exception as e:
            raise exception.Conflict(type='role', details=_('Duplicate Entry'))
        put_role_json = build_create_req(role, SCHEMA['role'])
        put_role_json = append_if_not_exists(put_role_json,
                TABLES['role']['hash_key'])
        MDB.put_item('role', put_role_json)
        return role

    def list_roles(self, hints):
        filter_keys = []
        filter_values = []
        for filt in hints.filters:
            filter_keys.append(filt['name'])
            filter_values.append(filt['value'])

        ops = ['EQ'] * len(filter_keys)
        req = build_scan_req(filter_keys, filter_values, ops,
                SCHEMA['role'], limit=100000)
        role_refs = MDB.scan('role', req)
        roles = [strip_types_unicode(x) for x in role_refs['items']]
        return roles

    def list_roles_from_ids(self, ids):
        if not ids:
            return []
        else:
           roles = []
           for role_id in ids:
               roles.append(self._get_role(role_id))
           return roles

    def _get_role(self, role_id):
        req = build_query_req([TABLES['role']['hash_key']], [role_id], ['EQ'],
                    SCHEMA['role'])
        res = MDB.query('role', req)
        if res['count'] == 0:
            raise exception.RoleNotFound(role_id=role_id)
        elif res['count'] > 1:
            raise Exception('more than one role with same id')
        res = res['items'][0]
        res = strip_types_unicode(res)
        return res

    def get_role(self, role_id):
       return self._get_role(role_id)

    def update_role(self, role_id, role):
        if 'name' in role:
           role.pop('name')
        old_role = self._get_role(role_id)
        req = build_update_req(TABLES['role'].values(), SCHEMA['role'],
                role, old_role, action={})
        if req:
            res = MDB.update_item('role', req)
        old_role.update(role)
        return old_role

    def delete_role(self, role_id):
        role = self._get_role(role_id)
        req = build_delete_req(TABLES['role'].values(), [role['id'],\
                role['name']], SCHEMA['role'])
        res = MDB.delete_item('role', req)
        req = build_delete_req(TABLES['role_name_index'].values(),
                [role['name']], SCHEMA['role_name_index'])
        res = MDB.delete_item('role_name_index', req)
