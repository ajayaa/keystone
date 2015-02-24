from magnetodbclient.v1 import client
from keystone import exception

class Mdb(object):
    def __init__(self):
        self.mdb_client = None
    def get_client(self):
        if self.mdb_client is None:
            self.mdb_client =  client.Client(endpoint_url='http://127.0.0.1:8480/v1/data/default_tenant',
                                             auth_strategy='noauth')
        return self.mdb_client

def strip_types_unicode(us):
    dict = {}
    for k, v in us.iteritems():
        dict[k] = v.values()[0].encode('ascii')
    return dict

def build_query_req(key, value, operators, table_schema):
    body = {}
    body['consistent_read'] = True
    body['key_conditions'] = {}
    for key, value, op in  zip(key, value, operators):
        body['key_conditions'][key] = {}
        val_json = {table_schema[key]: value}
        body['key_conditions'][key]['attribute_value_list'] = [val_json]
        body['key_conditions'][key]['comparison_operator'] = op
    return body

def build_scan_req(keys, values, operators, table_schema, limit=None):
    body = {}
    if len(keys) == len(values) == len(operators):
        body['scan_filter'] = {}
        for key, value, op in  zip(keys, values, operators):
            body['scan_filter'][key] = {}
            val_json = {table_schema[key]: value}
            body['scan_filter'][key]['attribute_value_list'] = [val_json]
            body['scan_filter'][key]['comparison_operator'] = op
    if limit is not None:
        body['limit'] = limit
    return body

def build_get_req(keys, values, table_schema):
    body = {}
    body['consistent_read'] = True
    body['key'] = {}
    for key, value in zip(keys, values):
        body['key'][key] = {}
        body['key'][key][table_schema[key]] = value
    return body

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
            if value == "S":
                attr_val = { "S": req_dict[key] }
            elif value == "N":
                attr_val = { "N": int(req_dict[key]) }
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
        action=None, return_values=None):
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
        body['attribute_updates'][key] = {'value': {table_schema[key]: value}}
        if action is None:
            body['attribute_updates'][key]['action'] = action.get(key, 'PUT')
        else:
            body['attribute_updates'][key]['action'] = 'PUT'
    if return_values:
        body['return_values'] = return_values
    return body

def build_delete_req(keys, values, table_schema):
    body = {}
    body['key'] = {}
    for key, value in zip(keys, values):
        body['key'][key] = {table_schema[key]: value}
    return body
