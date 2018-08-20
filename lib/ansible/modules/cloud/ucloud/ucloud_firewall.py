#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_firewall

short_description: create, delete, describe, update, grant, describe_resource ucloud firewall

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task

options:
  action:
    description:
      - action of firewall, (create, describe, update, grant, delete, describe_source)
    required: true

  public_key:
    description:
      - ucloud pubic key for api
    required: true
    
  private_key:
    description:
      - ucloud private key for api
    required: true
  
  region:
    description:
      - "the region of ucloud, see https://docs.ucloud.cn/api/summary/regionlist.html"
    required: true 
    
  projectid:
    description:
      - the projectid
    default: org-a41n54
 
  name:
    description:
      - firewall name
      
  rules:
    description:
      - firewall rules, if action is update or create, it required
    type: list
    
  tag:
    description:
      - tag name
      
  remark:
    description:
      - remark name
      
  fwid:
    description:
      - friewall id, if action is update, delete, describe_resource or grant. it required

  resoucetype:
    description:
      - type of resource, example is UHost, used for  grant action
      
  resourceid:
    description:
      - id of resource, used for grant action

'''

EXAMPLES = '''

# create firewall
- name: create firewall
  ucloud_firewall:
    action: create
    public_key:
    private_key:
    region: cn-sh2
    rules:
      - UDP|53|0.0.0.0/0|ACCEPT|HIGH
      - TCP|0-56636|0.0.0.0/0|ACCEPT|HIGH
      - TCP|3306|0.0.0.0/0|DROP|HIGH
    name: test-firewall

# delete firewall, it only be delete successfully when no resource is bind
- name: delete firewall
  ucloud_firewall:
    action: delete
    public_key:
    private_key:
    region: cn-sh2
    fwid: firewall-uhzual
    
# update firewall
- name: update firewall
  ucloud_firewall:
    action: update
    public_key:
    private_key:
    region: cn-sh2
    fwid: firewall-uhzual
    rules:
      - UDP|53|0.0.0.0/0|ACCEPT|HIGH
      - TCP|0-56636|0.0.0.0/0|ACCEPT|HIGH
      - TCP|3306|0.0.0.0/0|DROP|HIGH

# describe firewall
- name: describe firewall
  ucloud_firewall:
    action: describe
    public_key:
    private_key:
    region: cn-sh2
 
# describe_resource of sepical firewall
- name:  describe_resource of sepical firewall
  ucloud_firewall:
    action: describe_resource
    public_key:
    private_key:
    region: cn-sh2
    fwid: firewall-uhzalz
    
# grant firewall to one resource
- name: grant firewall
  ucloud_firewall:
    action: grant
    public_key:
    private_key:
    region: cn-sh2
    fwid: firewall-uzjah1
    resourcetype: UHost
    resourceid: uhost-2o1bls 

'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, CORE_PARAMS, CREATEFIREWALL_PARAMS, DESCRIBEFIREWALL_PARAMS, \
    DELETEFIREWALL_PARAMS, UPDATEFIREWALL_PARAMS, DESCRIBERESOURCEFIREALL_PARAMS, GRANTFIREWALL_PARAMS


def create(module, **kwargs):
    ur = UhttpRequests('CreateFirewall', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeFirewall', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update(module, **kwargs):
    ur = UhttpRequests('UpdateFirewall', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def delete(module, **kwargs):
    ur = UhttpRequests('DeleteFirewall', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def grant(module, **kwargs):
    ur = UhttpRequests('GrantFirewall', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe_resource(module, **kwargs):
    ur = UhttpRequests('DescribeFirewallResource', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update_kwargs_by_name(module, name, **kwargs):
    describe_firewall_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    firewalls = _list_firewall(module, **describe_firewall_params)

    if firewalls and name in [i['Name'] for i in firewalls]:
        fwid = find_fwid_by_name(module, name, firewalls)
        kwargs['FWId'] = fwid
    else:
        module.fail_json(msg='Can not Found Firewall Named {0} in list'.format(name))
    return kwargs


def find_fwid_by_name(module, name, result, flag='FWId'):
    fwinfo = find_fwinfo_by_name(module, name, result)
    return fwinfo[flag]


def find_fwinfo_by_name(module, name, result):
    match_fw = list(filter(lambda x: x['Name'] == name, result))
    if len(match_fw) > 1:
        module.fail_json(msg="Firewall Named {0} is more than 1".format(name))
    else:
        return match_fw[0]


def _list_uhosts(module, **kwargs):
    ui = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['UHostSet'] if 'UHostSet' in resp else None
    else:
        module.fail_json(msg=resp)

def find_uhostid_by_name(module, name, result):
    if name in [i['Name'] for i in result]:
        uhostinfo = list(filter(lambda x: x['Name'] == name, result))
        if len(uhostinfo) > 1:
            module.fail_json(msg='UHost Named {0} is more than 1'.format(name))
        else:
            return uhostinfo[0]['UHostId']
    else:
        module.fail_json(msg='Can not found Uhost Named {0}'.format(name))


def _list_firewall(module, **kwargs):
    ur = UhttpRequests('DescribeFirewall', **kwargs)
    resp = ur.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)

def is_create_firewall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATEFIREWALL_PARAMS + CORE_PARAMS else False


def is_describe_firewall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEFIREWALL_PARAMS + CORE_PARAMS else False


def is_delete_firewall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DELETEFIREWALL_PARAMS + CORE_PARAMS else False


def is_update_firewall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in UPDATEFIREWALL_PARAMS + CORE_PARAMS else False


def is_describesource_fireall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBERESOURCEFIREALL_PARAMS + CORE_PARAMS else False


def is_grant_firewall_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in GRANTFIREWALL_PARAMS + CORE_PARAMS else False


def main():

    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'update', 'delete', 'describe', 'grant', 'describe_resource']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        rules=dict(type='list'),
        projectid=dict(type='str', default='org-a41n54'),
        name=dict(type='str'),
        tag=dict(type='str'),
        remark=dict(type='str'),
        fwid=dict(type='str'),
        resourcetype=dict(type='str', default='UHost'),
        resourceid=dict(type='str'),
        uhostname=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    action = module.params.get('action')
    public_key = module.params.get('public_key')
    private_key = module.params.get('private_key')
    region = module.params.get('region')
    projectid = module.params.get('projectid')
    rules = module.params.get('rules')
    name = module.params.get('name')
    tag = module.params.get('tag')
    remark = module.params.get('remark')
    fwid = module.params.get('fwid')
    resourcetype = module.params.get('resourcetype')
    resourceid = module.params.get('resourceid')
    uhostname = module.params.get('uhostname')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        ProjectId=projectid,
        Name=name,
        Tag=tag,
        Remark=remark,
        FWId=fwid,
        ResourceType=resourcetype,
        ResourceId=resourceid,
        Limit=1000
        # Ucloud 的describe (tag)逻辑问题, 目前这边都用1000 来保证取得全部符合条件的Uhost, subnet, natgw, firewall, eip
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'create':
        kwargs = dict(filter(is_create_firewall_params, kwargs.items()))

        if rules:
            for index, value in enumerate(rules):
                _key = "{0}.{1}".format("Rule", index)
                kwargs[_key] = value

        # 检测是否存在同名
        describe_firewall_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
            )
        firewalls = _list_firewall(module, **describe_firewall_params)

        if firewalls and kwargs['Name'] in [i['Name'] for i in firewalls]:
            module.warn('Firewall Named {0} is already exists!'.format(kwargs['Name']))
            fw_info = find_fwinfo_by_name(module, kwargs['Name'], firewalls)
            module.exit_json(**fw_info)

        create(module, **kwargs)

    if action == 'delete':
        kwargs = dict(filter(is_delete_firewall_params, kwargs.items()))
        if name and not fwid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)
        delete(module, **kwargs)

    if action == 'update':
        kwargs = dict(filter(is_update_firewall_params, kwargs.items()))
        if name and not fwid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        if rules:
            for index, value in enumerate(rules):
                _key = "{0}.{1}".format("Rule", index)
                kwargs[_key] = value
        update(module, **kwargs)

    if action == 'grant':
        kwargs = dict(filter(is_grant_firewall_params, kwargs.items()))
        if name and not fwid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        if uhostname and not resourceid:
            describe_uhost_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            uhosts = _list_uhosts(module, **describe_uhost_params)
            if not uhosts:
                 module.fail_json(msg='There is no Uhosts')
            uhostid = find_uhostid_by_name(module, uhostname, uhosts)
            kwargs['ResourceId'] = uhostid

        grant(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_firewall_params, kwargs.items()))

        if name and not fwid:
            firewalls = _list_firewall(module, **kwargs)
            if firewalls and name in [i["Name"] for i in firewalls]:
                fw_info = find_fwinfo_by_name(module, name, firewalls)
                module.exit_json(**fw_info)
            else:
                module.fail_json(msg="Can not Found firewall Named {0}".format(name))

        describe(module, **kwargs)

    if action == 'describe_resource':
        kwargs = dict(filter(is_describesource_fireall_params, kwargs.items()))
        if name and not fwid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)
        describe_resource(module, **kwargs)


if __name__ == "__main__":
    main()
