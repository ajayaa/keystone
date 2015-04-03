# Copyright 2015 Reliance Jio Infocomm
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

"""Cassandra!

To create keyspace by name keystone:

    from cqlengine.management import create_keyspace
    create_keyspace("keystone", "SimpleStrategy", 1)
"""
from cqlengine.models import Model, ModelMetaClass

import functools
import json

from keystone import exception

ips=['127.0.0.1']
keyspace='keystone'

import six

@six.add_metaclass(ModelMetaClass)
class ExtrasModel(Model):
    __abstract__ = True

    @classmethod
    def get_model_dict(cls, d, extras_table=True):
        # 'extras_table' is for working with tables which doesn't have extras
        # magic. For such tables, just pass extras_table=False
        new_dict = d.copy()

        if not extras_table:
            for k in new_dict.keys():
                if k not in cls._columns:
                    new_dict.pop(k)
            return new_dict

        new_dict['extra'] = json.dumps(dict((k, new_dict.pop(k)) for k in six.iterkeys(d)
                                if k not in cls._columns and k != 'extra'))
        return new_dict

    def to_dict(self):
        model_dict = {}
        for k, v in zip(self.keys(), self.values()):
            model_dict[k] = v

        if self.__class__.__name__ = 'RoleAssignment':
            return model_dict

        if 'extra' in model_dict.keys():
            model_dict['extra'] = json.loads(model_dict['extra'])

        for k, v in model_dict['extra'].items():
            model_dict[k] = v

        if self.__class__.__name__ == 'User':
            if 'default_project_id' in model_dict and model_dict['default_project_id'] is None:
                del model_dict['default_project_id']
        return model_dict


def truncated(f):
    """Ensure list truncation is detected in Driver list entity methods.

    This is designed to wrap and sql Driver list_{entity} methods in order to
    calculate if the resultant list has been truncated. Provided a limit dict
    is found in the hints list, we increment the limit by one so as to ask the
    wrapped function for one more entity than the limit, and then once the list
    has been generated, we check to see if the original limit has been
    exceeded, in which case we truncate back to that limit and set the
    'truncated' boolean to 'true' in the hints limit dict.

    """
    @functools.wraps(f)
    def wrapper(self, hints, *args, **kwargs):
        if not hasattr(hints, 'limit'):
            raise exception.UnexpectedError(
                _('Cannot truncate a driver call without hints list as '
                  'first parameter after self '))

        if hints.limit is None:
            return f(self, hints, *args, **kwargs)

        # A limit is set, so ask for one more entry than we need
        list_limit = hints.limit['limit']
        hints.set_limit(list_limit + 1)
        ref_list = f(self, hints, *args, **kwargs)

        # If we got more than the original limit then trim back the list and
        # mark it truncated.  In both cases, make sure we set the limit back
        # to its original value.
        if len(ref_list) > list_limit:
            hints.set_limit(list_limit, truncated=True)
            return ref_list[:list_limit]
        else:
            hints.set_limit(list_limit)
            return ref_list
    return wrapper


