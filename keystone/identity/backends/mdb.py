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

USER_TABLE = {
        'user': {
          'hash_key': 'domain_id',
          'range_key': 'name'
        },
        'user_id_index': {
          'hash_key': 'id'
        }
    }

USER_SCHEMA = {
        'id': 'S',
        'name': 'S',
        'password': 'S',
        'extra': 'S',
        'enabled': 'N',
        'domain_id': 'S',
        'default_project_id': 'S'
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
        put_user_json = build_create_req(user, USER_SCHEMA)
        for table_name, keys in USER_TABLE.iteritems():
            put_user_json = append_if_not_exists(put_user_json,\
                    keys['hash_key'])
            MDB.put_item(table_name, put_user_json)
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
            table_to_query = USER_TABLE['user']
            req = build_query_req([table_to_query['hash_key']], [domain], ['EQ'],\
                    USER_SCHEMA)
            user_refs = MDB.query('user', req)
        else:
            #work around because of bug #142358
            ops = ['EQ'] * len(filter_keys)
            req = build_scan_req(filter_keys, filter_values, ops,
                    USER_SCHEMA, limit=100000)
            user_refs = MDB.scan('user', req)
        users = [from_db(strip_types_unicode(x)) for x in user_refs['items']]
        return [identity.filter_user(x) for x in users]

    def _get_user(self, user_id):
        table_to_query = USER_TABLE['user_id_index']
        req = build_query_req([table_to_query['hash_key']], [user_id], ['EQ'],\
                USER_SCHEMA)

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
        table_to_query = USER_TABLE['user']
        req = build_get_req(table_to_query.values(), [domain_id, user_name],
                USER_SCHEMA)
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
        req = build_update_req(USER_TABLE['user'].values(),
        USER_SCHEMA, new_user, old_user, action={})
        if req:
            res = MDB.update_item('user', req)

        req = build_update_req(USER_TABLE['user_id_index'].values(),
                USER_SCHEMA, new_user, old_user, action={})
        if req:
            res = MDB.update_item('user_id_index', req)
        old_user.update(new_user)
        return identity.filter_user(from_db(old_user))

    def delete_user(self, user_id):
        ref = self._get_user(user_id)
        domain_id = ref['domain_id']
        name = ref['name']
        req = build_delete_req(USER_TABLE['user'].values(), [domain_id,\
                name], USER_SCHEMA)
        MDB.delete_item('user', req)
        req = build_delete_req(USER_TABLE['user_id_index'].values(),
                [user_id], USER_SCHEMA)
        MDB.delete_item('user_id_index', req)

    # group crud
    def add_user_to_group(self, user_id, group_id):
        raise exception.ForbiddenAction()

    def check_user_in_group(self, user_id, group_id):
        raise exception.ForbiddenAction()

    def remove_user_from_group(self, user_id, group_id):
        raise exception.ForbiddenAction()

    def list_groups_for_user(self, user_id, hints):
        # When an user is authenticated his groups are also listed.
        # So this work-around.
        return {}

    def list_users_in_group(self, group_id, hints):
        raise exception.ForbiddenAction()

    def create_group(self, group_id, group):
        raise exception.ForbiddenAction()

    def list_groups(self, hints):
        return []

    def get_group(self, group_id):
        raise exception.ForbiddenAction()

    def get_group_by_name(self, group_name, domain_id):
        raise exception.ForbiddenAction()

    def update_group(self, group_id, group):
        raise exception.ForbiddenAction()

    def delete_group(self, group_id):
        raise exception.ForbiddenAction()
