# Copyright 2012-13 OpenStack Foundation
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

import six
import sqlalchemy
from sqlalchemy.sql.expression import false

from keystone.common.mdb import *
from keystone import assignment as keystone_assignment
from keystone.common import sql
from keystone import config
from keystone import exception
from keystone.i18n import _
from keystone.openstack.common import log


CONF = config.CONF
LOG = log.getLogger(__name__)

TABLES = {
        'assignment': {
            'hash_key': 'actor_id',
            'range_key': 'target_id'
        },
        'target_id_index': {
            'hash_key': 'target_id',
            'range_key': 'actor_id'
        },
        'role_id_index': {
            'hash_key': 'role_id',
            'range_key': 'actor_id'
        }
}

SCHEMA = {
        'assignment': {
            'actor_id': 'S',
            'target_id': 'S',
            'role_ids': 'SS',
            'type': 'S'
        },
        'target_id_index': {
            'target_id': 'S',
            'actor_id': 'S',
            'role_ids': 'SS'
        },
        'role_id_index': {
            'role_id': 'S',
            'actor_id': 'S',
            'target_ids': 'SS'
        }
}

MDB = Mdb().get_client()


class Assignment(keystone_assignment.Driver):

    def default_role_driver(self):
        return "keystone.assignment.role_backends.mdb.Role"

    def default_resource_driver(self):
        return 'keystone.resource.backends.sql.Resource'

    def list_user_ids_for_project(self, tenant_id):
        req = build_query_req([TABLES['target_id_index']['hash_key']],
                [tenant_id], ['EQ'], SCHEMA['target_id_index'])
        users = MDB.query('target_id_index', req)
        users = users['items']
        ret = []
        for u in users:
            if u.has_key('role_ids'):
                ret.append(u['actor_id'].values()[0].encode('ascii'))
        return ret

    def _get_metadata(self, user_id=None, tenant_id=None,
                      domain_id=None, group_id=None, session=None):
        metadata_ref = {}
        metadata_ref['roles'] = []
        actor_id = user_id or group_id
        target_id = tenant_id or domain_id
        req = build_get_req(TABLES['assignment'].values(), [actor_id,\
                target_id], SCHEMA['assignment'])
        res = MDB.get_item('assignment', req)
        if bool(res):
            if(res['item'].has_key('role_ids')):
                metadata_ref['roles'] =  res['item']['role_ids']['SS']
                return metadata_ref
        raise exception.MetadataNotFound()

    def create_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        target_id = None
        actor_id = None
        assignment_type = None
        if user_id:
            actor_id=user_id
            if project_id:
                target_id=project_id
                assignment_type='UserProject'
            if domain_id:
                target_id=domain_id
                assignment_type='UserDomain'
        if group_id:
            actor_id = group_id
            if project_id:
                target_id=project_id
                assignment_type='GroupProject'
            if domain_id:
                target_id=domain_id
                assignment_type='GroupDomain'

        # add to the the target_id_index table.
        d = {'role_ids': [role_id]}
        action = {'role_ids': 'ADD'}
        req = build_update_req(TABLES['target_id_index'].values(),
                SCHEMA['target_id_index'], d, {}, key_values=[target_id, actor_id],
                action=action)
        res = MDB.update_item('target_id_index', req)

        # add to the role_id_index table.
        d = {'target_ids': [target_id]}
        action = {'target_ids': 'ADD'}
        req = build_update_req(TABLES['role_id_index'].values(),
                SCHEMA['role_id_index'], d, {}, key_values=[role_id, actor_id],
                action=action)
        res = MDB.update_item('role_id_index', req)

        # add to the assignment table.
        d = {'role_ids': [role_id]}
        d['type'] = assignment_type
        action = {'role_ids': 'ADD'}
        req = build_update_req(TABLES['assignment'].values(),
                SCHEMA['assignment'], d, {}, key_values=[actor_id, target_id],
                action=action)
        res = MDB.update_item('assignment', req)

    def list_grant_role_ids(self, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        actor_id = user_id or group_id
        target_id = project_id or domain_id
        req = build_get_req(TABLES['assignment'].values(), [actor_id,\
                target_id], SCHEMA['assignment'])
        res = MDB.get_item('assignment', req)
        if bool(res):
            if(res['item'].has_key('role_ids')):
                return res['item']['role_ids']['SS']
        return []

    def check_grant_role_id(self, role_id, user_id=None, group_id=None,
                            domain_id=None, project_id=None,
                            inherited_to_projects=False):
        actor_id = user_id or group_id
        target_id = project_id or domain_id
        req = build_get_req(TABLES['assignment'].values(), [actor_id,\
                target_id], SCHEMA['assignment'])
        res = MDB.get_item('assignment', req)
        if bool(res):
            if(res['item'].has_key('role_ids')):
                return res['item']['role_ids']['SS'][0]
        raise exception.RoleNotFound(role_id=role_id)

    def delete_grant(self, role_id, user_id=None, group_id=None,
                     domain_id=None, project_id=None,
                     inherited_to_projects=False):
        actor_id = user_id or group_id
        target_id = project_id or domain_id
        req = build_get_req(TABLES['assignment'].values(), [actor_id,\
                target_id], SCHEMA['assignment'])
        res = MDB.get_item('assignment', req)
        if bool(res):
            role_ids = None
            if res['item'].has_key('role_ids'):
                role_ids = res['item']['role_ids']['SS']
            if role_ids and role_id in role_ids:
                #remove from target_id_index table.
                d = {'role_ids': [role_id]}
                action = {'role_ids': 'DELETE'}
                req = build_update_req(TABLES['target_id_index'].values(),
                        SCHEMA['target_id_index'], d, {}, key_values=[target_id, actor_id],
                        action=action)
                res = MDB.update_item('target_id_index', req)

                # remove from the role_id_index table.
                d = {'target_ids': [target_id]}
                action = {'target_ids': 'DELETE'}
                req = build_update_req(TABLES['role_id_index'].values(),
                        SCHEMA['role_id_index'], d, {}, key_values=[role_id, actor_id],
                        action=action)
                res = MDB.update_item('role_id_index', req)

                # add to the assignment table.
                d = {'role_ids': [role_id]}
                action = {'role_ids': 'DELETE'}
                req = build_update_req(TABLES['assignment'].values(),
                        SCHEMA['assignment'], d, {}, key_values=[actor_id, target_id],
                        action=action)
                res = MDB.update_item('assignment', req)
                return

        raise exception.RoleNotFound(role_id=role_id)


    def _list_project_ids_for_actor(self, actors, hints, inherited,
                                    group_only=False):

        # query the assignment table.
        projects = []
        for actor in actors:
            req = build_query_req(['actor_id'], [actor], ['EQ'],
                    SCHEMA['assignment'])
            res = MDB.query('assignment', req)
            for item in res['items']:
                if item.has_key('role_ids'):
                    if item['type']['S'] == 'UserProject':
                        projects.append(item['target_id']['S'].encode('ascii'))
        return projects

    def list_project_ids_for_user(self, user_id, group_ids, hints,
                                  inherited=False):
        actor_list = [user_id]
        if group_ids:
            actor_list = actor_list + group_ids

        return self._list_project_ids_for_actor(actor_list, hints, inherited)

    def list_domain_ids_for_user(self, user_id, group_ids, hints,
                                 inherited=False):
        actors = group_ids.append(user_id)
        # query the assignment table.
        domains = []
        for actor in actors:
            req = build_query_req(['actor_id'], [actor], ['EQ'],
                    SCHEMA['assignment'])
            res = MDB.query('assignment', req)
            for item in res['items']:
                if item.has_key('role_ids'):
                    if item['type']['S'] == 'UserDomain':
                        domains.append(item['target_id']['S'].encode('ascii'))
        return domains

    def list_role_ids_for_groups_on_domain(self, group_ids, domain_id):
        if not group_ids:
            # If there's no groups then there will be no domain roles.
            return []
        roles = []
        for actor in groups:
            req = build_get_req(TABLES['asssignment'].values(), [actor,\
                    domain_id], SCHEMA['assignment'])
            res = MDB.get_item('assignment', req)
            if bool(res):
                if res.has_key('role_ids'):
                    if res['type']['S'] == 'GroupDomain':
                        roles.extend(item['role_ids']['SS'])
        return roles

    def list_role_ids_for_groups_on_project(
            self, group_ids, project_id, project_domain_id, project_parents):

        if not group_ids:
            # If there's no groups then there will be no project roles.
            return []

        roles = []
        for actor in group_ids:
            req = build_get_req(TABLES['assignment'].values(), [actor,\
                    project_id], SCHEMA['assignment'])
            res = MDB.get_item('assignment', req)
            if bool(res):
                if res['item'].has_key('role_ids'):
                    if res['item']['type']['S'] == 'GroupProject':
                        roles.extend(res['item']['role_ids']['SS'])
        return roles

    def list_project_ids_for_groups(self, group_ids, hints,
                                    inherited=False):
        return self._list_project_ids_for_actor(
            group_ids, hints, inherited, group_only=True)

    def list_domain_ids_for_groups(self, group_ids, inherited=False):
        # query the assignment table.
        domains = []
        for actor in groups:
            req = build_query_req(['actor_id'], [actor], ['EQ'],
                    SCHEMA['assignment'])
            res = MDB.query('assignment', req)
            for item in res['items']:
                if item.has_key('role_ids'):
                    if item['type']['S'] == 'GroupDomain':
                        domains.append(item['target_id']['S'].encode('ascii'))
        return domains

    def add_role_to_user_and_project(self, user_id, tenant_id, role_id):
        # add to the the target_id_index table.
        d = {'role_ids': [role_id]}
        action = {'role_ids': 'ADD'}
        req = build_update_req(TABLES['target_id_index'].values(),
                SCHEMA['target_id_index'], d, {}, key_values=[tenant_id, user_id],
                action=action)
        res = MDB.update_item('target_id_index', req)

        # add to the role_id_index table.
        d = {'target_ids': [tenant_id]}
        action = {'target_ids': 'ADD'}
        req = build_update_req(TABLES['role_id_index'].values(),
                SCHEMA['role_id_index'], d, {}, key_values=[role_id, user_id],
                action=action)
        res = MDB.update_item('role_id_index', req)

        # add to the assignment table.
        d = {'role_ids': [role_id]}
        d['type'] = 'UserProject'
        action = {'role_ids': 'ADD'}
        req = build_update_req(TABLES['assignment'].values(),
                SCHEMA['assignment'], d, {}, key_values=[user_id, tenant_id],
                action=action)
        res = MDB.update_item('assignment', req)

    def remove_role_from_user_and_project(self, user_id, tenant_id, role_id):
        #remove from target_id_index table.
        d = {'role_ids': [role_id]}
        action = {'role_ids': 'DELETE'}
        req = build_update_req(TABLES['target_id_index'].values(),
                SCHEMA['target_id_index'], d, {}, key_values=[tenant_id, user_id],
                action=action)
        res = MDB.update_item('target_id_index', req)

        # remove from the role_id_index table.
        d = {'target_ids': [tenant_id]}
        action = {'target_ids': 'DELETE'}
        req = build_update_req(TABLES['role_id_index'].values(),
                SCHEMA['role_id_index'], d, {}, key_values=[role_id, user_id],
                action=action)
        res = MDB.update_item('role_id_index', req)

        # add to the assignment table.
        d = {'role_ids': [role_id]}
        action = {'role_ids': 'DELETE'}
        req = build_update_req(TABLES['assignment'].values(),
                SCHEMA['assignment'], d, {}, key_values=[user_id, tenant_id],
                action=action)
        res = MDB.update_item('assignment', req)


    def list_role_assignments(self):

        def denormalize(ref):
            assignment = {}
            ret = []
            if ref['type']['S'] == 'UserProject':
                assignment['user_id'] = ref['actor_id']['S']
                assignment['project_id'] = ref['target_id']['S']
            elif ref['type']['S'] == 'UserDomain':
                assignment['user_id'] = ref['actor_id']['S']
                assignment['domain_id'] = ref['target_id']['S']
            elif ref['type']['S'] == 'GroupProject':
                assignment['group_id'] = ref['actor_id']['S']
                assignment['project_id'] = ref['target_id']['S']
            elif ref['type']['S'] == 'GroupDomain':
                assignment['group_id'] = ref['actor_id']['S']
                assignment['domain_id'] = ref['target_id']['S']
            else:
                raise exception.Error(message=_(
                    'Unexpected assignment type encountered, %s') %
                    ref.type)
            if ref.has_key('role_ids'):
                for role in ref['role_ids']['SS']:
                    assignment_copy = assignment.copy()
                    assignment_copy['role_id'] = role
                    ret.append(assignment_copy)
            return ret
        # work around because of bug #1423858
        types = ['UserProject', 'UserDomain', 'GroupProject', 'GroupDomain']
        return_value = []
        for typ in types:
            req = build_scan_req(['type'], [typ], ['EQ'], SCHEMA['assignment'])
            res = MDB.scan('assignment', req)
            for item in res['items']:
                return_value.extend(denormalize(item))
        return return_value

    # don't delete any row, just updates to the row.
    def delete_project_assignments(self, project_id):
        #remove from target_id_index table.
        req = build_query_req(['target_id'], [project_id], ['EQ'],
                SCHEMA['target_id_index'])
        # use this to delete values from three tables
        result = MDB.query('target_id_index', req)

        for item in result['items']:
            if item.has_key('role_ids'):
                d = {'role_ids': item['role_ids']['SS']}
                action = {'role_ids': 'DELETE'}
                #update the target_id_index table
                req = build_update_req(TABLES['target_id_index'].values(),
                        SCHEMA['target_id_index'], d, {},
                        key_values=[item['target_id']['S'], item['actor_id']['S']],
                        action=action)
                res = MDB.update_item('target_id_index', req)
                #update the assignment table
                req = build_update_req(TABLES['assignment'].values(),
                        SCHEMA['assignment'], d, {},
                        key_values=[item['actor_id']['S'], item['target_id']['S']],
                        action=action)
                res = MDB.update_item('assignment', req)
                #update the role_id_index table
                roles = item['role_ids']['SS']
                actor_id = item['actor_id']['S']
                d = {'target_ids': [item['target_id']['S']]}
                action = {'target_ids': 'DELETE'}
                for role in roles:
                    req = build_update_req(TABLES['role_id_index'].values(),
                        SCHEMA['role_id_index'], d, {},
                        key_values=[role, actor_id], action=action)
                    res = MDB.update_item('role_id_index', req)


    def delete_role_assignments(self, role_id):
        req = build_query_req(['role_id'], [role_id], ['EQ'],
                SCHEMA['role_id_index'])
        result = MDB.query('role_id_index', req)
        for item in result['items']:
            if item.has_key('target_ids'):
                d = {'role_ids': [item['role_id']['S']]}
                action = {'role_ids': 'DELETE'}
                for target_id in item['target_ids']['SS']:
                    #update the assignment table
                    req = build_update_req(TABLES['assignment'].values(),
                            SCHEMA['assignment'], d, {},
                            key_values=[item['actor_id']['S'], target_id],
                            action=action)
                    res = MDB.update_item('assignment', req)
                    #update the target_id_index table
                    req = build_update_req(TABLES['target_id_index'].values(),
                            SCHEMA['target_id_index'], d, {},
                            key_values=[target_id, item['actor_id']['S']],
                            action=action)
                    res = MDB.update_item('target_id_index', req)
                #update the role_id_index table
                d = {'target_ids': item['target_ids']['SS']}
                action = {'target_ids': 'DELETE'}
                req = build_update_req(TABLES['role_id_index'].values(),
                        SCHEMA['role_id_index'], d, {},
                        key_values=[role_id, item['actor_id']['S']],
                        action=action)
                res = MDB.update_item('role_id_index', req)

    def delete_user(self, user_id):
       req = build_query_req(['actor_id'], [user_id], ['EQ'],
               SCHEMA['assignment'])
       result = MDB.query('assignment', req)
       for item in result['items']:
           if item.has_key('role_ids'):
               d = {'role_ids': item['role_ids']['SS']}
               action = {'role_ids': 'DELETE'}
               #update the assignment table
               req = build_update_req(TABLES['assignment'].values(),
                       SCHEMA['assignment'], d, {},
                       key_values=[user_id, item['target_id']['S']],
                       action=action)
               res = MDB.update_item('assignment', req)
               #update the target_id_index table
               req = build_update_req(TABLES['target_id_index'].values(),
                       SCHEMA['target_id_index'], d, {},
                       key_values=[item['target_id']['S'], user_id],
                       action=action)
               res = MDB.update_item('target_id_index', req)
               for role in item['role_ids']['SS']:
                   d = {'target_ids': [item['target_id']['S']]}
                   action = {'target_ids': 'DELETE'}
                   #update the role_id_index table
                   req = build_update_req(TABLES['role_id_index'].values(),
                           SCHEMA['role_id_index'], d, {},
                           key_values=[role, item['actor_id']['S']],
                           action=action)
                   res = MDB.update_item('role_id_index', req)

    def delete_group(self, group_id):
       self.delete_user(group_id)
