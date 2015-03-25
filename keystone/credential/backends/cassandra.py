# Copyright 2015 Reliance Jio Infocom
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

from keystone.common import cassandra
from keystone import credential
from keystone import exception

from cqlengine import columns
from cqlengine import connection
from cqlengine import BatchQuery
from cqlengine.management import sync_table
from cqlengine.query import BatchType

class CredentialModel(cassandra.ExtrasModel):
    id = columns.Text(primary_key=True, max_length=64)
    user_id = columns.Text(max_length=64, index=True)
    project_id = columns.Text(max_length=64, index=True)
    blob = columns.Text()
    type = columns.Text(max_length=255)
    extra = columns.Text(default='')

connection.setup(cassandra.ips, cassandra.keyspace)

sync_table(CredentialModel)


class Credential(credential.Driver):

    # credential crud

    def create_credential(self, credential_id, credential):
        create_dict = CredentialModel.get_model_dict(credential)
        ref = CredentialModel.create(**create_dict)
        return ref.to_dict()

    @cassandra.truncated
    def list_credentials(self, hints):
        refs = CredentialModel.objects()
        return [cassandra.to_dict(ref) for ref in refs]

    def list_credentials_for_user(self, user_id):
        refs = CredentialModel.objects.filter(user_id=user_id)
        return [cassandra.to_dict(ref) for ref in refs]

    def _get_credential(self, credential_id):
        refs = CredentialModel.objects.filter(id=credential_id)
        if len(refs) is None:
            raise exception.CredentialNotFound(credential_id=credential_id)
        return refs[0]

    def get_credential(self, credential_id):
        return cassandra.to_dict(self._get_credential(credential_id))

    def update_credential(self, credential_id, credential):
        ref = self._get_credential(credential_id)
        ref_dict = cassandra.to_dict(ref)
        for key in credential:
            ref_dict[key] = credential[key]
        ref_id = ref_dict.pop(id)
        ref.objects(id=ref_id).update(ref_dict)
        return ref

    def delete_credential(self, credential_id):
        ref = self._get_credential(credential_id).delete()

    def delete_credentials_for_project(self, project_id):
        refs = CredentialModel.objects(project_id=project_id)
        with BatchQuery(batch_type=BatchType.Unlogged) as b:
            for ref in refs:
                CredentialModel.objects(id=ref.id).batch(b).delete()

    def delete_credentials_for_user(self, user_id):
        refs = CredentialModel.objects(user_id=user_id)
        with BatchQuery(batch_type=BatchType.Unlogged) as b:
            for ref in refs:
                CredentialModel.objects(id=ref.id).batch(b).delete()
