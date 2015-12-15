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

import uuid

from keystone.common import controller
from keystone.common import dependency
from keystone.common import validation
from keystone import notifications


@dependency.requires('cubeit_api')
class Cubeit(controller.V3Controller):
    collection_name = 'cubeit'
    member_name = 'cubeit'

    def register_user(self, context, **kwargs):
        return self.cubeit_api.register_user(**kwargs)

    def create_cube(self, context, user_id, **kwargs):
        return self.cubeit_api.create_cube(user_id, **kwargs)

    def delete_cube(self, context, user_id, cube_id):
        return self.cubeit_api.delete_cube(user_id, cube_id)

    def create_content(self, context, user_id, **kwargs):
         return self.cubeit_api.create_content(user_id, **kwargs)

    def attach_content_with_cube(self, context, user_id, cube_id, **kwargs):
        return self.cubeit_api.attach_content_with_cube(user_id, cube_id, **kwargs)

    def detach_content_from_cube(self, context, user_id, cube_id, content_id):
        return self.cubeit_api.detach_content_from_cube(user_id, cube_id, content_id)

    # The parameter here is u_id instead of user_id. Framework problem.
    def share_content_with_user(self, context, u_id, content_id, **kwargs):
        return self.cubeit_api.share_content_with_user(u_id, content_id, **kwargs)

    def share_cube_with_user(self, context, u_id, cube_id, **kwargs):
        return self.cubeit_api.share_cube_with_user(u_id, cube_id, **kwargs)

    def list_cubes_for_user(self, context, user_id):
        return self.cubeit_api.list_cubes_for_user(user_id)

    def list_contents_for_user(self, context, user_id):
        return self.cubeit_api.list_contents_for_user(user_id)
