from magnetodbclient.v1 import client
from keystone import exception
from datetime import datetime

EPOCH = datetime(1970, 1, 1)

class Mdb(object):
    def __init__(self):
        self.mdb_client = None
    def get_client(self):
        if self.mdb_client is None:
            self.mdb_client =  client.Client(endpoint_url='http://127.0.0.1:8480/v1/data/default_tenant',
                                             auth_strategy='noauth')
        return self.mdb_client

def strip_types_unicode(us, table_schema=None):
    dict = {}
    for k, v in us.iteritems():
        val = v.values()[0]
        if type(val) is list:
            dict[k] = [i.encode('ascii') for i in val]
        else:
            val = val.encode('ascii')
            if table_schema:
                if table_schema[k] == "D":
                    val = datetime.utcfromtimestamp(float(val))
                if table_schema[k] == "BL":
                    val = True if val == 'true' else False
            dict[k] = val
    if table_schema:
        # populate missing attributes as None
        for k in table_schema:
            if dict.get(k) is None:
                dict[k] = None
    return dict

def handle_custom_types(k, v):
    if k == "D":
        v = convert_datetime_to_seconds(v)
        # magnetoDB bug #1430775 so store as string
        v = str(v)
        k = "N"
    elif k == "BL":
        v = convert_boolean_to_string(v)
        k = "S"
    return k, v

def convert_datetime_to_seconds(d):
    return (d - EPOCH).total_seconds()

def convert_boolean_to_string(b):
    return 'true' if b else 'false'

def build_query_req(key, value, operators, table_schema, attr_to_get=None):
    body = {}
    body['consistent_read'] = True
    body['key_conditions'] = {}
    for key, value, op in  zip(key, value, operators):
        body['key_conditions'][key] = {}
        k, v = handle_custom_types(table_schema[key], value)
        val_json = {k : v}
        body['key_conditions'][key]['attribute_value_list'] = [val_json]
        body['key_conditions'][key]['comparison_operator'] = op
    if attr_to_get is not None:
        body['attributes_to_get'] = attr_to_get
    return body

def build_scan_req(keys, values, operators, table_schema, limit=None):
    body = {}
    body['scan_filter'] = {}
    if len(keys) == len(values) == len(operators):
        for key, value, op in  zip(keys, values, operators):
            body['scan_filter'][key] = {}
            k, v = handle_custom_types(table_schema[key], value)
            val_json = {k : v}
            body['scan_filter'][key]['attribute_value_list'] = [val_json]
            body['scan_filter'][key]['comparison_operator'] = op
    if limit is not None:
        body['limit'] = limit
    return body

def build_get_req(keys, values, table_schema):
    body = {}
    body['consistent_read'] = True
    body['key'] = {}
    if len(keys) < 1 or len(keys) != len(values):
        raise Exception("Invalid key schema")
    for key, value in zip(keys, values):
        body['key'][key] = {}
        body['key'][key][table_schema[key]] = value
    return body

def append_expected_for_attr(req, key, exists=None, value=None,
        table_schema=None):
    if key:
        if not req.get('expected'):
            req['expected'] = {}
        req['expected'][key] = {}
        if exists is not None:
            req['expected'][key]['exists'] = exists
        else:
            if value is not None and table_schema is not None:
                req['expected'][key]['value'] = {table_schema[key]: value}
            else:
                raise Exception("Not enough parameters to build request")
    return req

# This function is deprecated. Don't use it going forward. Use
# append_expected_for_attr instead. This is here because it is
# in some places and we plan to move to the above function while
# refactoring.
def append_if_not_exists(req, hash_key):
    if hash_key:
        req['expected'] = {}
        req['expected'][hash_key] = {}
        req['expected'][hash_key]['exists'] = False
    return req

def append_return_values(req, ret_val):
    req['return_values'] = ret_val
    return req

def build_create_req(req_dict, table_schema):
    body = {}
    body['item'] = {}
    for key, value in table_schema.iteritems():
        try:
            if req_dict[key] is None:
                # if a value is None, its stored as NULL in SQL
                # In magnetoDB, we will not store that attribute
                # because attribute values cannot be null;
                continue
            if value == "S":
                attr_val = { "S": req_dict[key] }
            elif value == "SS":
                # empty set check:
                # below check doesn't ensure that its not None
                # but that's ok as we've already ensured it at start
                if not req_dict[key]:
                    raise exception.Error(
                            message='empty sets are not supported')
                attr_val = { "SS": list(req_dict[key]) }
            elif value == "N":
                # magnetoDB bug #1430775 so store as string
                if type(req_dict[key]) is float:
                    val = str(req_dict[key])
                else:
                    val = int(req_dict[key])
                attr_val = { "N": val }
            elif value == "D":
                val = convert_datetime_to_seconds(req_dict[key])
                # magnetoDB bug #1430775 so store as string
                val = str(val)
                attr_val = { "N": val }
            elif value == "BL":
                val = convert_boolean_to_string(req_dict[key])
                attr_val = { "S": val }
            else:
                raise exception.Error(message='attribute type not supported')
        except KeyError:
            continue
        if req_dict[key] is not None:
            body['item'][key] = attr_val
    return body

def diff_dicts(new_dict, old_dict):
    diff = {}
    for key in new_dict:
        if key in old_dict and old_dict[key] == new_dict[key]:
            continue
        else:
            diff[key] = new_dict[key]
    return diff

def union_dicts(old_dict, new_dict):
    union = new_dict.copy()
    for key in old_dict:
        if key in new_dict and new_dict[key] == old_dict[key]:
            continue
        else:
            union[key] = old_dict[key]

def build_update_req(keys, table_schema, new_dict, old_dict, key_values=None,
        action={}, return_values=None):
    body = {}
    body['key'] = {}
    if key_values is None:
        for key in keys:
            body['key'][key] = {table_schema[key] : old_dict[key]}
    else:
        for k, v in zip(keys, key_values):
            body['key'][k] = {table_schema[k]: v}
    changed_attrs = diff_dicts(new_dict, old_dict)
    if not changed_attrs:
        return {}
    body['attribute_updates'] = {}
    for key, value in changed_attrs.iteritems():
        k, v = handle_custom_types(table_schema[key], value)
        body['attribute_updates'][key] = {'value': {k : v}}
        body['attribute_updates'][key]['action'] = action.get(key, 'PUT')
    if return_values:
        body['return_values'] = return_values
    return body

def build_delete_req(keys, values, table_schema):
    body = {}
    body['key'] = {}
    for key, value in zip(keys, values):
        k, v = handle_custom_types(table_schema[key], value)
        body['key'][key] = {k : v}
    return body
