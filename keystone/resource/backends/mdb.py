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
        'enabled': 'N',
        'name': 'S',
        'extra': 'S'
    },
    'domain_name_index': {
        'name': 'S',
        'enabled': 'N',
        'id': 'S',
        'extra': 'S'
    }
}

MDB = Mdb().get_client()

def to_db(d, typ):
    d = dict((k, v) for k, v in d.iteritems() if v)
    if d.has_key('enabled'):
        d['enabled'] = int(d['enabled'])
    if typ == 'project':
        return d
    elif typ == 'domain':
        return d

def from_db(d, typ):
    if d.has_key('enabled'):
        d['enabled'] = bool(d['enabled'])
    if typ == 'project':
        for col in SCHEMA['project'].keys():
            if col != 'extra':
                if not d.has_key(col):
                    d[col] = None
        return d
    elif typ=='domain':
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
    @sql.handle_conflicts(conflict_type='domain')
    def create_domain(self, domain_id, domain):
        with sql.transaction() as session:
            ref = Domain.from_dict(domain)
            session.add(ref)
        return ref.to_dict()

    @sql.truncated
    def list_domains(self, hints):
        with sql.transaction() as session:
            query = session.query(Domain)
            refs = sql.filter_limit_query(Domain, query, hints)
            return [ref.to_dict() for ref in refs]

    def list_domains_from_ids(self, ids):
        if not ids:
            return []
        else:
            with sql.transaction() as session:
                query = session.query(Domain)
                query = query.filter(Domain.id.in_(ids))
                domain_refs = query.all()
                return [domain_ref.to_dict() for domain_ref in domain_refs]

    def _get_domain(self, session, domain_id):
        ref = session.query(Domain).get(domain_id)
        if ref is None:
            raise exception.DomainNotFound(domain_id=domain_id)
        return ref

    def get_domain(self, domain_id):
        with sql.transaction() as session:
            return self._get_domain(session, domain_id).to_dict()

    def get_domain_by_name(self, domain_name):
        with sql.transaction() as session:
            try:
                ref = (session.query(Domain).
                       filter_by(name=domain_name).one())
            except sql.NotFound:
                raise exception.DomainNotFound(domain_id=domain_name)
            return ref.to_dict()

    @sql.handle_conflicts(conflict_type='domain')
    def update_domain(self, domain_id, domain):
        with sql.transaction() as session:
            ref = self._get_domain(session, domain_id)
            old_dict = ref.to_dict()
            for k in domain:
                old_dict[k] = domain[k]
            new_domain = Domain.from_dict(old_dict)
            for attr in Domain.attributes:
                if attr != 'id':
                    setattr(ref, attr, getattr(new_domain, attr))
            ref.extra = new_domain.extra
            return ref.to_dict()

    def delete_domain(self, domain_id):
        with sql.transaction() as session:
            ref = self._get_domain(session, domain_id)
            session.delete(ref)


class Domain(sql.ModelBase, sql.DictBase):
    __tablename__ = 'domain'
    attributes = ['id', 'name', 'enabled']
    id = sql.Column(sql.String(64), primary_key=True)
    name = sql.Column(sql.String(64), nullable=False)
    enabled = sql.Column(sql.Boolean, default=True, nullable=False)
    extra = sql.Column(sql.JsonBlob())
    __table_args__ = (sql.UniqueConstraint('name'), {})


