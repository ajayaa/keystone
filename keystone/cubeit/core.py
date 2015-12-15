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

import abc

from oslo_config import cfg
import six

from keystone.common import dependency
from keystone.common import manager
from keystone import exception
from keystone import notifications


CONF = cfg.CONF


@dependency.provider('cubeit_api')
class Manager(manager.Manager):
    """Default pivot point for the Policy backend.

    See :mod:`keystone.common.manager.Manager` for more details on how this
    dynamically calls the backend.

    """

    def __init__(self):
        super(Manager, self).__init__(CONF.cubeit.driver)

    def register_user(self, **kwargs):
        return self.driver.register_user(**kwargs)

    def create_cube(self, user_id, **kwargs):
        return self.driver.create_cube(user_id, **kwargs)

    def delete_cube(self, user_id, cube_id):
        return self.driver.delete_cube(user_id, cube_id)

    def create_content(self, user_id, **kwargs):
        return self.driver.create_content(user_id, **kwargs)

    def attach_content_with_cube(self, user_id, cube_id, **kwargs):
        return self.driver.attach_content_with_cube(user_id, cube_id, **kwargs)

    def detach_content_from_cube(self, user_id, cube_id, content_id):
        return self.driver.detach_content_from_cube(user_id, cube_id, content_id)

    def share_content_with_user(self, u_id, content_id, **kwargs):
        return self.driver.share_content_with_user(u_id, content_id, **kwargs)

    def list_cubes_for_user(self, user_id):
        return self.driver.list_cubes_for_user(user_id)

    def list_contents_for_user(self, user_id):
        return self.driver.list_contents_for_user(user_id)


@six.add_metaclass(abc.ABCMeta)
class Driver(object):

    @abc.abstractmethod
    def register_user(self, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_cube(self, user_id, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def delete_cube(self, user_id, cube_id):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def create_content(self, user_id, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def attach_content_with_cube(self, user_id, cube_id, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def detach_content_from_cube(self, user_id, cube_id, content_id):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def share_content_with_user(self, u_id, content_id, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def share_cube_with_user(self, u_id, cube_id, **kwargs):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_cubes_for_user(self, user_id):
        raise exception.NotImplemented()

    @abc.abstractmethod
    def list_contents_for_user(self, user_id):
        raise exception.NotImplemented()
