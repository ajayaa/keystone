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


import time

from oslo.utils import timeutils

from keystone.common.mdb import *
from keystone import config
from keystone import exception
from keystone.openstack.common import log
from keystone import trust
from datetime import datetime

EPOCH = datetime(1970, 1, 1)

LOG = log.getLogger(__name__)
# The maximum number of iterations that will be attempted for optimistic
# locking on consuming a limited-use trust.
MAXIMUM_CONSUME_ATTEMPTS = 10

CONF = config.CONF

TABLES = {
        'trust': {
          'hash_key': 'id',
        }
    }

SCHEMA = {
        'trust': {
          'id': 'S',
          'trustor_user_id': 'S',
          'trustee_user_id': 'S',
          'project_id': 'S',
          'impersonation': 'BL',
          'deleted_at': 'D',
          'expires_at': 'D',
          'remaining_uses': 'N',
          'extra': 'S',
          'roles': 'SS'
        }
}

MDB = Mdb().get_client()

class Trust(trust.Driver):
    #@sql.handle_conflicts(conflict_type='trust')
    def create_trust(self, trust_id, trust, roles):
        trust['id'] = trust_id
        if trust.get('expires_at') and trust['expires_at'].tzinfo is not None:
            trust['expires_at'] = timeutils.normalize_time(trust['expires_at'])
        role_set = set([])
        for role in roles:
            role_set.add(role['id'])
        trust['roles'] = role_set
        table = TABLES['trust']
        json = build_create_req(trust, SCHEMA['trust'])
        json = append_expected_for_attr(json, table['hash_key'], False)
        MDB.put_item('trust', json)
        trust['roles'] = roles
        return trust

    #@sql.handle_conflicts(conflict_type='trust')
    def consume_use(self, trust_id):

        for attempt in range(MAXIMUM_CONSUME_ATTEMPTS):
            trust = self.get_trust(trust_id)
            remaining_uses = trust.get('remaining_uses')
            if remaining_uses is None:
                # unlimited uses, do nothing
                break
            elif remaining_uses > 0:
                # NOTE(morganfainberg): use an optimistic locking method
                # to ensure we only ever update a trust that has the
                # expected number of remaining uses.
                new_trust = {"remaining_uses": int(remaining_uses) - 1}
                req = build_update_req(TABLES['trust'].values(),
                        SCHEMA['trust'], new_trust, trust)
                req = append_expected_for_attr(req, 'id', value=trust_id,
                        table_schema=SCHEMA['trust'])
                req = append_expected_for_attr(req, 'deleted_at', False)
                req = append_expected_for_attr(req, 'remaining_uses',
                        value=remaining_uses, table_schema=SCHEMA['trust'])
                MDB.update_item('trust', req)
                # Successfully consumed a single limited-use trust.
                # Since trust_id is the PK on the Trust table, there is
                # no case we should match more than 1 row in the
                # update. We either update 1 row or 0 rows.
                break
            else:
                raise exception.TrustUseLimitReached(trust_id=trust_id)
            # NOTE(morganfainberg): Ensure we have a yield point for eventlet
            # here. This should cost us nothing otherwise. This can be removed
            # if/when oslo.db cleanly handles yields on db calls.
            time.sleep(0)
        else:
            # NOTE(morganfainberg): In the case the for loop is not prematurely
            # broken out of, this else block is executed. This means the trust
            # was not unlimited nor was it consumed (we hit the maximum
            # iteration limit). This is just an indicator that we were unable
            # to get the optimistic lock rather than silently failing or
            # incorrectly indicating a trust was consumed.
            raise exception.TrustConsumeMaximumAttempt(trust_id=trust_id)

    def get_trust(self, trust_id, deleted=False):
        ref = None
        table_to_query = TABLES['trust']
        req = build_query_req([table_to_query['hash_key']], [trust_id], ['EQ'],\
                SCHEMA['trust'])
        ref = MDB.query('trust', req)
        if ref['count'] == 0:
            raise exception.TrustNotFound(trust_id=trust_id)
        elif ref['count'] != 1:
            raise Exception("More than one trust with same id")
        trust = strip_types_unicode(ref['items'][0], SCHEMA['trust'])
        if trust is None:
            return None
        if not deleted and trust.get('deleted_at') is not None:
            return None
        if trust.get('expires_at') is not None and not deleted:
            now = timeutils.utcnow()
            if now > trust['expires_at']:
                return None
        # Do not return trusts that can't be used anymore
        if trust.get('remaining_uses') is not None and not deleted:
            if trust['remaining_uses'] <= 0:
                return None
        roles = []
        for role in trust['roles']:
            roles.append({'id' : role})
        trust['roles'] = roles
        return trust

    #@sql.handle_conflicts(conflict_type='trust')
    def list_trusts(self):
        req = build_scan_req([], [], [], SCHEMA['trust'])
        trust_refs = MDB.scan('trust', req)
        return [strip_types_unicode(x, SCHEMA['trust'])\
          for x in trust_refs['items'] if x.get('deleted_at') is None]

    #@sql.handle_conflicts(conflict_type='trust')
    def list_trusts_for_trustee(self, trustee_user_id):
        req = build_scan_req(['trustee_user_id'],\
                [trustee_user_id], ['EQ'], SCHEMA['trust'])
        trust_refs = MDB.scan('trust', req)
        return [strip_types_unicode(x, SCHEMA['trust'])\
           for x in trust_refs['items'] if x.get('deleted_at') is None]

    #@sql.handle_conflicts(conflict_type='trust')
    def list_trusts_for_trustor(self, trustor_user_id):
        req = build_scan_req(['trustor_user_id'],\
                [trustor_user_id], ['EQ'], SCHEMA['trust'])
        trust_refs = MDB.scan('trust', req)
        return [strip_types_unicode(x, SCHEMA['trust'])\
           for x in trust_refs['items'] if x.get('deleted_at') is None]

    #@sql.handle_conflicts(conflict_type='trust')
    def delete_trust(self, trust_id):
        old_trust = self.get_trust(trust_id)
        if not old_trust:
            raise exception.TrustNotFound(trust_id=trust_id)
        new_trust = {}
        new_trust['deleted_at'] = timeutils.utcnow()

        req = build_update_req(TABLES['trust'].values(),
                SCHEMA['trust'], new_trust, old_trust)
        MDB.update_item('trust', req)

