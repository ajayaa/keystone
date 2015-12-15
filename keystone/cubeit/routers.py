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
from keystone.common import router
from keystone.common import wsgi
from keystone.common import json_home
from keystone.cubeit import controllers

class Routers(wsgi.RoutersBase):

    def append_v3_routers(self, mapper, routers):
        cube_controller = controllers.Cubeit()

        self._add_resource(
            mapper, cube_controller,
            path='/user',
            post_action='register_user',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/cube',
            post_action='create_cube',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/cube/{cube_id}',
            delete_action='delete_cube',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/content',
            post_action='create_content',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/cube/{cube_id}/content',
            post_action='attach_content_with_cube',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/cube/{cube_id}/content/{content_id}',
            delete_action='detach_content_from_cube',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{u_id}/content/{content_id}/share',
            post_action='share_content_with_user',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{u_id}/cube/{cube_id}/share',
            post_action='share_cube_with_user',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/cube',
            get_action='list_cubes_for_user',
            rel=json_home.build_v3_resource_relation('user'),
            )
        self._add_resource(
            mapper, cube_controller,
            path='/user/{user_id}/content',
            get_action='list_contents_for_user',
            rel=json_home.build_v3_resource_relation('user'),
            )
