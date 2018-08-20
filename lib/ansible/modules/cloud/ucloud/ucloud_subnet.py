#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_subnet

short_description: create, delete, describe ucloud subnet

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
  
options:
  action:
    description:
      - action of subnet, (create, delete, describe, update)
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
      - the region of ucloud, see "https://docs.ucloud.cn/api/summary/regionlist.html"
    required: true
    
  projectid:
    description:
      - the projectid
    required: true
    
  vpcid:
    description:
      - vpc id, if action is create it required
    
  subnet:
    description:
      - subnet, example:192.168.0.0 if action is create it required

  netmask:
    description:
      - int value like 24
      
  subnetname:
    description:
      - name of subnet

  tag:
    description:
      - tag name
      
  remark:
    description:
      - remark name
      
  businessid:
    description:
      - business id
      
  subnetids:
    description:
      - list, it only used for describe action when need to list many subnetids
      
  subnetid:
    description:
      - str, used for describe, delete, update action
      
'''

EXAMPLES = '''
# create subnet
- name: create subnet
  ucloud_subnet:
    action: create
    public_key:
    private_key:
    region: cn-sh2
    projectid: org-a41n54
    vpcid: uvnet-deudx0
    subnet: 192.168.0.0
    netmask: 24
    subnetname:  private subnet-1
    
    
# delete subnet
- name: delete subnet
  ucloud_subnet:
    action: delete
    public_key:
    private_key:
    region: cn-sh2
    projectid: org-a41n54
    subnetid: xxxx
    
# describe subnet
- name: describe subnet
  ucloud_subnet:
    action: describe
    public_key:
    private_key:
    region: cn-sh2
    projectid: org-a41n54
    subnetids:
      - xxxx
      - xxxx
      - xxxx
    vpcid: xxx
    
- name: update subnet
  ucloud_subnet:
    action: update
    public_key:
    private_key:
    region: cn-sh2
    subnetid: subnet-y2hlpe

'''

from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, CORE_PARAMS, CREATESUBNET_PARAMS, DELETESUBNET_PARAMS, \
    DESCRIBESUBNET_PARAMS, UPDATESUBNET_PARAMS


def create(module, **kwargs):
    ur = UhttpRequests('CreateSubnet', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def delete(module, **kwargs):
    ur = UhttpRequests('DeleteSubnet', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeSubnet', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update(module, **kwargs):
    ur = UhttpRequests('UpdateSubnetAttribute', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update_kwargs_by_subnetname(module, subnetname, **kwargs):
    describe_subnet_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    subnet = _list_subnet(module, **describe_subnet_params)

    if subnet and subnetname in [i['SubnetName'] for i in subnet]:
        subnetid = find_subnetid_by_name(module,subnetname, subnet)
        kwargs['SubnetId'] = subnetid
    else:
        module.fail_json(msg='Can Not Found Subnet Named {0} in list'.format(subnetname))
    return kwargs


def find_subnetid_by_name(module, subnetname, result, flag='SubnetId'):
    subnet_info = find_subnetinfo_by_name(module, subnetname, result)
    return subnet_info[flag]


def find_subnetinfo_by_name(module, subnetname, result):
    match_subnet = list(filter(lambda x: x['SubnetName'] == subnetname, result))
    if len(match_subnet) > 1:
        module.fail_json(msg="Subnet Named {0} is more than 1".format(subnetname))
    else:
        return match_subnet[0]


def _list_vpcs(module, **kwargs):
    ui = UhttpRequests('DescribeVPC', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def find_vpcid_by_name(module, name, result):
    if name in [i['Name']for i in result]:
        match_vpc = list(filter(lambda x: x['Name'] == name, result))
        if len(match_vpc) > 1:
            module.fail_json(msg='VPC Named {0} is more than 1'.format(name))
        else:
            vpc_info = match_vpc[0]
            return vpc_info['VPCId']
    else:
        module.fail_json(msg='Can not find {0} in Vpc list'.format(name))


def is_create_subnet_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATESUBNET_PARAMS + CORE_PARAMS else False


def is_delete_subnet_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DELETESUBNET_PARAMS + CORE_PARAMS else False


def is_describe_subnet_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBESUBNET_PARAMS + CORE_PARAMS else False


def is_update_subnet_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in UPDATESUBNET_PARAMS + CORE_PARAMS else False


def _list_subnet(module, **kwargs):
    ur = UhttpRequests('DescribeSubnet', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def main():
    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'delete', 'update', 'describe']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        projectid=dict(type='str', default='org-a41n54'),
        vpcid=dict(type='str'),
        subnet=dict(type='str', default='192.168.0.0'),
        netmask=dict(type='int', default=24),
        subnetname=dict(type='str'),
        tag=dict(type='str'),
        remark=dict(type='str'),
        businessid=dict(type='str'),
        subnetids=dict(type='list'),
        subnetid=dict(type='str'),
        subnetnames=dict(type='list'),
        vpc=dict(type='str'),
        new_subnetname=dict(type='str')
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
    vpcid = module.params.get('vpcid')
    subnet = module.params.get('subnet')
    netmask = module.params.get('netmask')
    subnetname = module.params.get('subnetname')
    tag = module.params.get('tag')
    remark = module.params.get('remark')
    businessid = module.params.get('businessid')
    subnetids = module.params.get('subnetids')
    subnetid = module.params.get('subnetid')
    subnetnames = module.params.get('subnetnames')
    vpc = module.params.get('vpc')
    new_subnetname = module.params.get('new_subnetname')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        ProjectId=projectid,
        VPCId=vpcid,
        Subnet=subnet,
        Netmask=int(netmask),
        SubnetName=subnetname,
        Tag=tag,
        Remark=remark,
        BuinessId=businessid,
        SubnetId=subnetid,
        Limit=1000
        # Ucloud 的describe (tag)逻辑问题, 目前这边都用1000 来保证取得全部符合条件的Uhost, subnet, natgw, firewall, eip
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'create':
        kwargs = dict(filter(is_create_subnet_params, kwargs.items()))

        # 指定vpc name, 获取vpcid
        if vpc and 'VPCId' not in kwargs:
            describe_vpc_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
                )

            vpcs = _list_vpcs(module, **describe_vpc_params)
            if not vpcs:
                module.exit_json(msg='There is no VPC')

            if vpc in [i['Name'] for i in vpcs]:
                kwargs['VPCId'] = find_vpcid_by_name(module, vpc, vpcs)

        # 检测是否存在同名
        describe_subnet_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )

        subnets = _list_subnet(module, **describe_subnet_params)

        if subnets and kwargs['SubnetName'] in [i['SubnetName']for i in subnets]:
            module.warn("Subnet Named {0} is already exists!".format(kwargs['SubnetName']))
            subnet_info = find_subnetinfo_by_name(module, kwargs['SubnetName'], subnets)
            module.exit_json(**subnet_info)

        create(module, **kwargs)

    if action == 'delete':
        kwargs = dict(filter(is_delete_subnet_params, kwargs.items()))
        if subnetname and not subnetid:
            kwargs = update_kwargs_by_subnetname(module, subnetname, **kwargs)
        delete(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_subnet_params, kwargs.items()))

        if subnetnames and not subnetids:
            result = defaultdict(list)
            subnets = _list_subnet(module, **kwargs)

            if not subnets:
                module.exit_json(msg="There is No subnet")

            for name in subnetnames:
                if name in [i['SubnetName'] for i in subnets]:
                    subnet_info = find_subnetinfo_by_name(module, name, subnets)
                    result['DataSet'].append(subnet_info)
            module.exit_json(**result)

        if subnetids:
            for index, value in enumerate(subnetids):
                _key = "{0}.{1}".format("SubnetIds", index)
                kwargs[_key] = value
        describe(module, **kwargs)

    if action == 'update':
        kwargs = dict(filter(is_update_subnet_params, kwargs.items()))
        if subnetname and not subnetid:
            kwargs = update_kwargs_by_subnetname(module, subnetname, **kwargs)
        # Ucloud 对于update subnet attribute api 方法 用的是Name 不是SubnetName 为了yml 统一,做如下调整
        if new_subnetname:
            kwargs['Name'] = new_subnetname
        update(module, **kwargs)


if __name__ == "__main__":
    main()
