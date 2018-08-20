#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_vpc

short_description: create, delete, describe ucloud vpc

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
 
options:
  action:
    description:
      - action of vpc, (create, delete, describe)
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
    default: cn-sh2
  
  projectid:
    description:
      - the projectid , if action is create or describe it required
    default: org-a41n54
  
  name:
    description:
      - Name of vpc, if action is create it required
    default: auto_vpc
    
  network:
    description:
      - the list of network, example is 10.1.0.0/16, if action is create it requried
    
  tag:
    description:
      - tag name

  remark:
    description:
      - remark name
      
  businessid:
    description:
      - business name

  vpcids:
    description:
      - list of vpcid, it used for describe action
  
  names:
    description:
      - name of vpc
    type: list
      
  vpcid:
    description:
      - vpc id, if action is delete it required

notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"
  
author:
  - fu-l@klab.com
  
'''

EXAMPLES = """

# create vpc
- name: create vpc
  ucloud_vpc:
    action: create
    public_key:
    private_key:
    region: cn-sh2
    projectid: org-a41n54
    network:
      - 10.1.0.0/16
      - 10.2.0.0/16
      - 10.3.0.0/16
    name: generate_from_ansible
    
# describe vpc    
- name:  describe vpc
  ucloud_vpc:
    action: describe
    public_key:
    private_key:
    projectid: org-a41n54
    region: cn-sh2
    vpcids:
      - uvnet-deudx0
      - uvnet-pbd515
      - uvnet-klolvt
      - uvnet-vwrsos
    
# delete vpc
- name: delete vpc
  ucloud_vpc:
    action: delete
    public_key:
    private_key:
    region: cn-sh2
    vpcid: uvnet-xxx
    

# add network in vpc
- name: add network
  ucloud_vpc:
    action: add_network
    public_key:
    private_key:
    region: cn-sh2
    vpcid: uvnet-deudx0
    network:
      - 10.10.0.0/16
      - 10.11.0.0/16
"""


from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, CORE_PARAMS, CREATEVPC_PARAMS, DELETEVPC_PARAMS, DESCRIBEVPC_PARAMS, \
    ADDNETWORKVPC_PARAMS


def create(module, **kwargs):
    ur = UhttpRequests('CreateVPC', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def delete(module, **kwargs):
    ur = UhttpRequests('DeleteVPC', **kwargs)
    resp = ur.urequest('GET', retry=5)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeVPC', **kwargs)
    resp = ur.urequest('GET', retry=5)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.exit_json(msg=resp)


def add_network(module, **kwargs):
    ur = UhttpRequests('AddVPCNetwork', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update_kwargs_by_vpcname(module, vpc, **kwargs):
    describe_vpc_params=dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    vpcs = _list_vpcs(module, **describe_vpc_params)

    if vpcs and vpc in [i['Name']for i in vpcs]:
        vpcid = find_vpcid_by_name(module, vpc, vpcs)
        kwargs['VPCId'] = vpcid
    else:
        module.fail_json(msg='Can not Found VPC Named {0} in list'.format(vpc))
    return kwargs


def find_vpcid_by_name(module, name, result, flag='VPCId'):
    vpc_info = find_vpcinfo_by_name(module, name, result)
    return vpc_info['flag']


def find_vpcinfo_by_name(module, name, result):
    match_vpc = list(filter(lambda x: x['Name'] == name, result))
    if len(match_vpc) > 1:
        module.fail_json(msg='vpc Named {0} is more than 1'.format(name))
    else:
        return match_vpc[0]


def is_create_vpc_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATEVPC_PARAMS + CORE_PARAMS else False


def is_delete_vpc_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DELETEVPC_PARAMS + CORE_PARAMS else False


def is_describe_vpc_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEVPC_PARAMS + CORE_PARAMS else False


def is_addnetwork_vpc_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in ADDNETWORKVPC_PARAMS + CORE_PARAMS else False


def _list_vpcs(module, **kwargs):
    ur = UhttpRequests('DescribeVPC', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def main():
    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'delete', 'describe', 'add_network']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        name=dict(type='str'),
        names=dict(type='list'),
        projectid=dict(type='str', default='org-a41n54'),
        network=dict(type='list'),
        tag=dict(type='str'),
        remark=dict(type='str'),
        businessid=dict(type='str'),
        vpcids=dict(type='list'),
        vpcid=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    action = module.params.get('action')
    public_key = module.params.get('public_key')
    private_key = module.params.get('private_key')
    region = module.params.get('region')
    name = module.params.get('name')
    names = module.params.get('names')
    projectid = module.params.get('projectid')
    network = module.params.get('network')  # list
    tag = module.params.get('tag')
    remark = module.params.get('remark')
    businessid = module.params.get('businessid')
    vpcids = module.params.get('vpcids')  # list
    vpcid = module.params.get('vpcid')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        Name=name,
        ProjectId=projectid,
        Tag=tag,
        Remark=remark,
        BusinessId=businessid,
        VPCId=vpcid,
        Limit=1000
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'create':
        kwargs = dict(filter(is_create_vpc_params, kwargs.items()))
        if network:
            for index, value in enumerate(network):
                _key = "{0}.{1}".format("Network", index)
                kwargs[_key] = value

        # 检测是否存在同名
        describe_vpc_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )
        vpcs = _list_vpcs(module, **describe_vpc_params)

        if vpcs and kwargs["Name"] in [i['Name'] for i in vpcs]:
            module.warn("VPC Named {0} is already exists!".format(kwargs['Name']))
            vpc_info = find_vpcinfo_by_name(module, kwargs['Name'], vpcs)
            module.exit_json(**vpc_info)

        create(module, **kwargs)

    if action == 'delete':
        kwargs = dict(filter(is_delete_vpc_params, kwargs.items()))
        if name and not vpcid:
            kwargs = update_kwargs_by_vpcname(module, name, **kwargs)
        delete(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_vpc_params, kwargs.items()))

        if names and not vpcids:
            result = defaultdict(list)
            vpcs = _list_vpcs(module, **kwargs)

            if not vpcs:
                module.exit_json(msg='There is No VPC in {} project'.format(kwargs['ProjectId']))

            for name in names:
                if name in [i['Name'] for i in vpcs]:
                    vpc_info = find_vpcinfo_by_name(module, name, vpcs)
                    result['DataSet'].append(vpc_info)
            module.exit_json(**result)

        if vpcids:
            for index, value in enumerate(vpcids):
                _key = '{0}.{1}'.format("VPCIds", index)
                kwargs[_key] = value

        describe(module, **kwargs)

    if action == 'add_network':
        kwargs = dict(filter(is_addnetwork_vpc_params, kwargs.items()))
        if network:
            for index, value in enumerate(network):
                _key = "{0}.{1}".format("Network", index)
                kwargs[_key] = value

        if name and not vpcid:
            kwargs = update_kwargs_by_vpcname(module, name, **kwargs)
        add_network(module, **kwargs)


if __name__ == "__main__":
    main()

