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
from keystone import clean
from keystone.common import sql
from keystone import config
from keystone import exception
from keystone.i18n import _LE
from keystone.openstack.common import log
from keystone import resource as keystone_resource
from keystone.common.mdb import *
from keystone.i18n import _

CONF = config.CONF
LOG = log.getLogger(__name__)

TABLES = {
    'project': {
        'hash_key': 'domain_id',
        'range_key': 'name'
    },
    'project_id_index': {
        'hash_key': 'id'
    },
    'domain': {
        'hash_key': 'id',
    },
    'domain_name_index': {
        'hash_key': 'name'
    }

}

SCHEMA = {
    'project': {
        'id': 'S',
        'name': 'S',
        'description': 'S',
        'extra': 'S',
        'enabled': 'N',
        'domain_id': 'S',
    },
    'project_id_index': {
        'id': 'S',
        'name': 'S',
        'description': 'S',
        'extra': 'S',
        'enabled': 'N',
        'domain_id': 'S',
    },
    'domain': {
        'id': 'S',
        'enabled': 'S',
        'name': 'S',
        'extra': 'S'
    },
    'domain_name_index': {
        'name': 'S',
        'enabled': 'S',
        'id': 'S',
        'extra': 'S'
    }
}

MDB = Mdb().get_client()

def to_db(d, typ):
    d = dict((k, v) for k, v in d.iteritems() if v is not None)
    if typ == 'project':
        if d.has_key('enabled'):
            d['enabled'] = int(d['enabled'])
        return d
    elif typ == 'domain':
        if d.has_key('enabled'):
            d['enabled'] = str(int(d['enabled']))
        extra = {}
        if d.has_key('description'):
            extra['description'] = d['description']
            d.pop('description')
        d['extra'] = json.dumps(extra)
        return d

def from_db(d, typ):
    if typ == 'project':
        if d.has_key('enabled'):
            d['enabled'] = bool(d['enabled'])
        for col in SCHEMA['project'].keys():
            if col != 'extra':
                if not d.has_key(col):
                    d[col] = None
        return d
    elif typ == 'domain':
         if d.has_key('enabled'):
            d['enabled'] = bool(int(d['enabled']))
         if d.has_key('extra'):
            d['extra'] = json.loads(d['extra'])
            d.update(d['extra'])
            d.pop('extra')
         if not d.has_key('description'):
             d['description'] = None
         return d


class Resource(keystone_resource.Driver):

    def default_assignment_driver(self):
        return 'keystone.assignment.backends.sql.Assignment'

    def _get_project(self, project_id):
        table_to_query = TABLES['project_id_index']
        req = build_query_req([table_to_query['hash_key']], [project_id], ['EQ'],\
                SCHEMA['project_id_index'])

        project_ref = MDB.query('project_id_index', req)
        if project_ref['count'] == 0:
            raise exception.ProjectNotFound(project_id=project_id)
        elif project_ref['count'] != 1:
            raise Exception("More than one project with same id")
        else:
            project_ref = strip_types_unicode(project_ref['items'][0])
        return from_db(project_ref, 'project')

    def get_project(self, tenant_id):
        return self._get_project(tenant_id)

    def get_project_by_name(self, tenant_name, domain_id):
        table_to_query = TABLES['project']
        req = build_get_req(table_to_query.values(), [domain_id, tenant_name],
                SCHEMA['project'])
        project_ref = MDB.get_item('project', req)
        if not project_ref:
            raise exception.ProjectNotFound(project_name=project_name)
        project_ref = strip_types_unicode(project_ref['item'])
        return from_db(project_ref, 'project')

    @sql.truncated
    def list_projects(self, hints):
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
        project_ref = None
        if domain is not None:
            table_to_query = TABLES['project']
            req = build_query_req([table_to_query['hash_key']], [domain], ['EQ'],\
                    SCHEMA['project'])
            project_refs = MDB.query('project', req)
        else:
            #work around because of bug #142358
            ops = ['EQ'] * len(filter_keys)
            req = build_scan_req(filter_keys, filter_values, ops,
                    SCHEMA['project'], limit=100000)
            project_refs = MDB.scan('project', req)
        projects = [from_db(strip_types_unicode(x), 'project') for x in project_refs['items']]
        return projects

    def list_projects_from_ids(self, ids):
        if not ids:
            return []
        projects = []
        for project_id in ids:
            project = self._get_project(project_id)
            projects.append(project)
        return projects

    def list_project_ids_from_domain_ids(self, domain_ids):
        if not domain_ids:
            return []
        projects = []
        for domain_id in domain_ids:
            projects.extend(self.list_projects_in_domain(domain_id))
        return projects

    def list_projects_in_domain(self, domain_id):
        table_to_query = TABLES['project']
        req = build_query_req([table_to_query['hash_key']], [domain_id], ['EQ'],\
                SCHEMA['project'])
        project_refs = MDB.query('project', req)
        projects = [from_db(strip_types_unicode(x), 'project') for x in project_refs['items']]
        return projects

    def list_projects_in_subtree(self, project_id):
       return []

    def list_project_parents(self, project_id):
        return []

    def is_leaf_project(self, project_id):
        return True

    # CRUD
    def create_project(self, tenant_id, tenant):
        project = to_db(tenant, 'project')
        put_project_json = build_create_req(tenant, SCHEMA['project'])
        tables = ['project', 'project_id_index']
        try:
            for table in tables:
                put_project_json = append_if_not_exists(put_project_json,\
                        TABLES[table]['hash_key'])
                MDB.put_item(table, put_project_json)
        except Exception as e:
           raise exception.Conflict(type='project', details=_('Duplicate Entry'))
        return from_db(tenant, 'project')

    def update_project(self, tenant_id, tenant):
        if 'name' in tenant:
            tenant.pop('name')
        #    raise exception.ForbiddenAction()
        old_project = to_db(self._get_project(tenant_id), 'project')
        new_project = to_db(tenant, 'project')
        req = build_update_req(TABLES['project'].values(),
        SCHEMA['project'], new_project, old_project, action={})
        if req:
            res = MDB.update_item('project', req)

        req = build_update_req(TABLES['project_id_index'].values(),
                SCHEMA['project'], new_project, old_project, action={})
        if req:
            res = MDB.update_item('project_id_index', req)
        old_project.update(new_project)
        return from_db(old_project, 'project')


    def delete_project(self, tenant_id):
        ref = self._get_project(tenant_id)
        domain_id = ref['domain_id']
        name = ref['name']
        req = build_delete_req(TABLES['project'].values(), [domain_id,\
                name], SCHEMA['project'])
        MDB.delete_item('project', req)
        req = build_delete_req(TABLES['project_id_index'].values(),
                [tenant_id], SCHEMA['project'])
        MDB.delete_item('project_id_index', req)

    # domain crud

    def create_domain(self, domain_id, domain):
        domain = to_db(domain, 'domain')
        req = build_create_req(domain, SCHEMA['domain_name_index'])
        req = append_if_not_exists(req, TABLES['domain_name_index']['hash_key'])
        try:
            MDB.put_item('domain_name_index', req)
        except Exception as e:
            raise exception.Conflict(type='domain', details=_('Duplicate Entry'))
        put_domain_json = build_create_req(domain, SCHEMA['domain'])
        put_domain_json = append_if_not_exists(put_domain_json,
                TABLES['domain']['hash_key'])
        MDB.put_item('domain', put_domain_json)
        return from_db(domain, 'domain')

    def list_domains(self, hints):
        filter_keys = []
        filter_values = []
        for filt in hints.filters:
            filter_keys.append(filt['name'])
            filter_values.append(filt['value'])

        ops = ['EQ'] * len(filter_keys)
        req = build_scan_req(filter_keys, filter_values, ops,
                SCHEMA['domain'], limit=100000)
        domain_refs = MDB.scan('domain', req)
        domains = [from_db(strip_types_unicode(x), 'domain') for x in 
                domain_refs['items']]
        return domains

    def list_domains_from_ids(self, ids):
        if not ids:
            return []
        else:
            domains = []
            for domain_id in ids:
                domains.append(self._get_domain(domain_id))
            return domains

    def _get_domain(self, domain_id):
        req = build_query_req([TABLES['domain']['hash_key']], [domain_id], ['EQ'],
                    SCHEMA['domain'])
        res = MDB.query('domain', req)
        if res['count'] == 0:
            raise exception.DomainNotFound(domain_id=domain_id)
        elif res['count'] > 1:
            raise Exception('more than one domain with same id')
        res = res['items'][0]
        res = strip_types_unicode(res)
        return from_db(res, 'domain')

    def get_domain(self, domain_id):
        return self._get_domain(domain_id)

    def get_domain_by_name(self, domain_name):
        req = build_query_req([TABLES['domain_name_index']['hash_key']],
                [domain_name], ['EQ'], SCHEMA['domain_name_index'])
        res = MDB.query('domain_name_index', req)
        if res['count'] == 0:
            raise exception.DomainNotFound(domain_id=domain_id)
        elif res['count'] > 1:
            raise Exception('more than one domain with same id')
        res = res['items'][0]
        res = strip_types_unicode(res)
        return from_db(res, 'domain')

    def update_domain(self, domain_id, domain):
        if 'name' in domain:
           domain.pop('name')
        domain = to_db(domain, 'domain')
        old_domain = self._get_domain(domain_id)
        old_domain = to_db(old_domain, 'domain')
        req = build_update_req(TABLES['domain'].values(), SCHEMA['domain'],
                domain, old_domain, action={})
        if req:
            res = MDB.update_item('domain', req)
        req = build_update_req(TABLES['domain_name_index'].values(),
                SCHEMA['domain_name_index'], domain, old_domain, action={})
        if res:
            res = MDB.update_item('domain_name_index', req)
        old_domain.update(domain)
        return from_db(old_domain, 'domain')

    def delete_domain(self, domain_id):
        domain = self._get_domain(domain_id)
        domain = to_db(domain, 'domain')
        req = build_delete_req(TABLES['domain'].values(), [domain['id']],
                SCHEMA['domain'])
        res = MDB.delete_item('domain', req)
        req = build_delete_req(TABLES['domain_name_index'].values(),
                [domain['name']], SCHEMA['domain_name_index'])
        res = MDB.delete_item('domain_name_index', req)
