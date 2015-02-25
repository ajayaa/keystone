# Copyright 2012 OpenStack Foundation
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
import json
from keystone.common.mdb import *
from keystone.common import utils
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone import identity

CONF = config.CONF

TABLES = {
    'user': {
        'hash_key': 'domain_id',
        'range_key': 'name'
    },
    'user_id_index': {
        'hash_key': 'id'
    },
    'group': {
        'hash_key': 'domain_id',
        'range_key': 'name'
    },
    'group_id_index': {
        'hash_key': 'id'
    },
    'user_group': {
        'hash_key': 'user_id',
        'range_key': 'group_id'
    },
    'group_user': {
        'hash_key': 'group_id',
        'range_key': 'user_id'
    }
}

SCHEMA = {
    'user': {
        'id': 'S',
        'name': 'S',
        'password': 'S',
        'extra': 'S',
        'enabled': 'N',
        'domain_id': 'S',
        'default_project_id': 'S'
    },
    'user_id_index': {
        'id': 'S',
        'name': 'S',
        'password': 'S',
        'extra': 'S',
        'enabled': 'N',
        'domain_id': 'S',
        'default_project_id': 'S'
    },

    'group': {
        'id': 'S',
        'name': 'S',
        'domain_id': 'S',
        'extra': 'S',
        'description': 'S'
    },
    'group_id_index': {
        'id': 'S',
        'name': 'S',
        'domain_id': 'S',
        'extra': 'S',
        'description': 'S'
    },
    'user_group': {
        'user_id': 'S',
        'group_id': 'S'
    },
    'group_user': {
        'group_id': 'S',
        'user_id': 'S'
    }
}

MDB = Mdb().get_client()

def to_db(user):
    if user.has_key('enabled'):
        user['enabled'] = int(user['enabled'])
    extra = {}
    if user.has_key('email'):
        extra['email'] = user['email']
        user.pop('email')
    if user.has_key('description'):
        extra['description'] = user['description']
        user.pop('description')
    if user.has_key('project_id'):
        extra['project_id'] = user['project_id']
        user.pop('project_id')
    user['extra'] = json.dumps(extra)
    for item in user.items():
        if user[item[0]] is None:
            user.pop(item[0])
    return user

def from_db(user):
    if user.has_key('enabled'):
        user['enabled'] = bool(user['enabled'])
    if user.has_key('extra'):
        user['extra'] = json.loads(user['extra'])
        user.update(user['extra'])
        user.pop('extra')
    return user


class Identity(identity.Driver):
    # NOTE(henry-nash): Override the __init__() method so as to take a
    # config parameter to enable sql to be used as a domain-specific driver.
    def __init__(self, conf=None):
        super(Identity, self).__init__()

    def default_assignment_driver(self):
        return "keystone.assignment.backends.sql.Assignment"

    def _check_password(self, password, user_ref):
        """Check the specified password against the data store.

        Note that we'll pass in the entire user_ref in case the subclass
        needs things like user_ref.get('name')
        For further justification, please see the follow up suggestion at
        https://blueprints.launchpad.net/keystone/+spec/sql-identiy-pam

        """
        return utils.check_password(password, user_ref['password'])

    # Identity interface
    def authenticate(self, user_id, password):
        user_ref = None
        try:
            user_ref = self._get_user(user_id)
        except exception.UserNotFound:
            raise AssertionError(_('Invalid user / password'))
        if not self._check_password(password, user_ref):
            raise AssertionError(_('Invalid user / password'))
        return identity.filter_user(user_ref)

    # user crud

    def create_user(self, user_id, user):
        user = utils.hash_user_password(user)
        user = to_db(user)
        put_user_json = build_create_req(user, SCHEMA['user'])
        tables = ['user', 'user_id_index']
        try:
            for table in tables:
                put_user_json = append_if_not_exists(put_user_json,\
                        TABLES[table]['hash_key'])
                MDB.put_item(table, put_user_json)
        except Exception as e:
           raise exception.Conflict(type='user', details=_('Duplicate Entry'))
        return identity.filter_user(from_db(user))

    def list_users(self, hints):
        domain = None
        filter_keys = []
        filter_values = []
        for filt in hints.filters:
            if filt['name'] == 'domain_id':
                domain = filt['value']
            elif filt['name'] == 'enabled':
                filter_keys.append(filt['name'])
                if filt['value'].lower() == 'false':
                    filter_values.append(0)
                else:
                    filter_values.append(1)
            else:
                filter_keys.append(filt['name'])
                filter_values.append(filt['value'])
        user_ref = None
        if domain is not None:
            table_to_query = TABLES['user']
            req = build_query_req([table_to_query['hash_key']], [domain], ['EQ'],\
                    SCHEMA['user'])
            user_refs = MDB.query('user', req)
        else:
            #work around because of bug #142358
            ops = ['EQ'] * len(filter_keys)
            req = build_scan_req(filter_keys, filter_values, ops,
                    SCHEMA['user'], limit=100000)
            user_refs = MDB.scan('user', req)
        users = [from_db(strip_types_unicode(x)) for x in user_refs['items']]
        return [identity.filter_user(x) for x in users]

    def _get_user(self, user_id):
        table_to_query = TABLES['user_id_index']
        req = build_query_req([table_to_query['hash_key']], [user_id], ['EQ'],\
                SCHEMA['user'])

        user_ref = MDB.query('user_id_index', req)
        if user_ref['count'] == 0:
            raise exception.UserNotFound(user_id=user_id)
        elif user_ref['count'] != 1:
            raise Exception("More than one user with same id")
        else:
            user_ref = strip_types_unicode(user_ref['items'][0])
        return from_db(user_ref)

    def get_user(self, user_id):
        user_ref = self._get_user(user_id)
        if type(user_ref) is not dict:
            user_ref = user_ref.to_dict()
        return identity.filter_user(user_ref)

    def get_user_by_name(self, user_name, domain_id):
        table_to_query = TABLES['user']
        req = build_get_req(table_to_query.values(), [domain_id, user_name],
                SCHEMA['user'])
        user_ref = MDB.get_item('user', req)
        if not user_ref:
            raise exception.UserNotFound(user_id=user_name)
        user_ref = strip_types_unicode(user_ref['item'])
        return identity.filter_user(from_db(user_ref))

    def update_user(self, user_id, user):
        if 'name' in user:
            user.pop('name')
        #    raise exception.ForbiddenAction()
        user = utils.hash_user_password(user)
        old_user = to_db(self._get_user(user_id))
        new_user = to_db(user)
        req = build_update_req(TABLES['user'].values(),
        SCHEMA['user'], new_user, old_user, action={})
        if req:
            res = MDB.update_item('user', req)

        req = build_update_req(TABLES['user_id_index'].values(),
                SCHEMA['user'], new_user, old_user, action={})
        if req:
            res = MDB.update_item('user_id_index', req)
        old_user.update(new_user)
        return identity.filter_user(from_db(old_user))

    def delete_user(self, user_id):
        ref = self._get_user(user_id)
        domain_id = ref['domain_id']
        name = ref['name']
        req = build_delete_req(TABLES['user'].values(), [domain_id,\
                name], SCHEMA['user'])
        MDB.delete_item('user', req)
        req = build_delete_req(TABLES['user_id_index'].values(),
                [user_id], SCHEMA['user'])
        MDB.delete_item('user_id_index', req)

    # group crud
    def add_user_to_group(self, user_id, group_id):
        d = {'user_id': user_id, 'group_id': group_id}
        put_req = build_create_req(d, SCHEMA['user_group'])
        tables = ['user_group', 'group_user']
        for table in tables:
            MDB.put_item(table, put_req)

    def check_user_in_group(self, user_id, group_id):
        d = {'user_id': user_id, 'group_id': group_id}
        req = build_get_req(TABLES['user_group'].values(),
                [user_id, group_id], SCHEMA['user_group'])
        res = MDB.get_item('user_group', req)
        if not res:
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})

    def remove_user_from_group(self, user_id, group_id):
        req = build_delete_req(TABLES['user_group'].values(),
                [user_id, group_id], SCHEMA['user_group'])
        try:
            res = MDB.delete_item('user_group', req)
        except e:
            raise exception.NotFound(_("User '%(user_id)s' not found in"
                                       " group '%(group_id)s'") %
                                     {'user_id': user_id,
                                      'group_id': group_id})
        req = build_delete_req(TABLES['group_user'].values(),
                [group_id, user_id], SCHEMA['group_user'])
        MDB.delete_item('group_user', req)

    def list_groups_for_user(self, user_id, hints):
        req = build_query_req([TABLES['user_group']['hash_key']],
                [user_id], ['EQ'], SCHEMA['user_group'],
                attr_to_get=['group_id'])
        group_refs = MDB.query('user_group', req)
        groups = [strip_types_unicode(x) for x in group_refs['items']]
        full_groups = []
        for group in groups:
            gr = self.get_group(group['group_id'])
            full_groups.append(gr)
        return full_groups

    def list_users_in_group(self, group_id, hints):
        req = build_query_req([TABLES['group_user']['hash_key']],
                [group_id], ['EQ'], SCHEMA['group_user'],
                attr_to_get=['user_id'])
        user_refs = MDB.query('group_user', req)
        users = [strip_types_unicode(x) for x in user_refs['items']]
        full_users = []
        for user in users:
            us = self._get_user(user['user_id'])
            full_users.append(us)
        return full_users


    def create_group(self, group_id, group):
        put_group_json = build_create_req(group, SCHEMA['group'])
        tables = ['group', 'group_id_index']
        for table in tables:
            put_group_json = append_if_not_exists(put_group_json,
                    TABLES[table]['hash_key'])
            MDB.put_item(table, put_group_json)
        group = dict((k, v) for k, v in group.iteritems() if v)
        return group

    def list_groups(self, hints):
        domain = None
        filter_keys = []
        filter_values = []
        for filt in hints.filters:
            if filt['name'] == 'domain_id':
                domain = filt['value']
            else:
                filter_keys.append(filt['name'])
                filter_values.append(filt['value'])
        group_ref = None
        if domain is not None:
            table_to_query = TABLES['group']
            req = build_query_req([TABLES['group']['hash_key']], [domain], ['EQ'],\
                    SCHEMA['group'])
            group_refs = MDB.query('group', req)
        else:
            #work around because of bug #142358
            ops = ['EQ'] * len(filter_keys)
            req = build_scan_req(filter_keys, filter_values, ops,
                    SCHEMA['group'], limit=100000)
            group_refs = MDB.scan('group', req)
        groups = [from_db(strip_types_unicode(x)) for x in group_refs['items']]
        return groups

    def get_group(self, group_id):
        table_to_query = TABLES['group_id_index']
        req = build_query_req([table_to_query['hash_key']], [group_id], ['EQ'],\
                SCHEMA['group_id_index'])

        group_ref = MDB.query('group_id_index', req)
        if group_ref['count'] == 0:
            raise exception.GroupNotFound(group_id=group_id)
        elif group_ref['count'] != 1:
            raise Exception("More than one group with same id")
        else:
            group_ref = strip_types_unicode(group_ref['items'][0])
        return group_ref

    def get_group_by_name(self, group_name, domain_id):
        table_to_query = TABLES['group']
        req = build_get_req(table_to_query.values(), [domain_id, group_name],
                SCHEMA['group'])
        group_ref = MDB.get_item('group', req)
        if not group_ref:
            raise exception.GroupNotFound(group_name=group_name)
        group_ref = strip_types_unicode(group_ref['item'])
        return group_ref

    def update_group(self, group_id, group):
        if 'name' in group:
            group.pop('name')
            #raise exception.ForbiddenAction()
        old_group = self.get_group(group_id)
        new_group = group
        req = build_update_req(TABLES['group'].values(),SCHEMA['group'],
                new_group, old_group, action={})
        if req:
            res = MDB.update_item('group', req)

        req = build_update_req(TABLES['group_id_index'].values(),
                SCHEMA['group_id_index'], new_group, old_group, action={})
        if req:
            res = MDB.update_item('group_id_index', req)
        old_group.update(new_group)
        return old_group

    def delete_group(self, group_id):
        ref = self.get_group(group_id)
        domain_id = ref['domain_id']
        name = ref['name']
        req = build_delete_req(TABLES['group'].values(), [domain_id,\
                name], SCHEMA['group'])
        MDB.delete_item('group', req)
        req = build_delete_req(TABLES['group_id_index'].values(),
                [group_id], SCHEMA['group_id_index'])
        MDB.delete_item('group_id_index', req)
