#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_nat

short_description: create, delete, update, describe

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task


options:
  action: 
    description:
      - the action of eip, create, delete, update, describe
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
    default: cn-sh2

  natgwname:
    description:
      - name of natgw

  subnetworkids:
    description:
      - subnet id
    type: list
  
  subnetnames:
    description:
      - subnet name
    type: list  
  
  eipids:
    description:
      - id of eip
    type: list
    
  eipnames:
    description:
      - eip name
    type: list  
    
  firewallid:
    description:
      - id of firewall  

  firewallname:
    description:
      - firewall name

  vpcid:
    description:
      - id of vpc
  
  vpcname:
    description:
      - vpc name
      
  ifopenf:
    description:
      - open white list or not
    choice: [1, 0]
    type: int
      
  tag:
    description:
      - tag name
    

notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"

author:
  - fu-l@klab.com
'''

EXAMPLES = """

# create natgw
- name: create natgw by id
  ucloud_nat:
    action: create
    region: cn-sh2
    public_key:                                 # required
    private_key:                                # required
    natgwname:                                  # required
    subnetworkids:                              # or subnetnames required
      - xxxx
      - xxxx
    eipids:                                     # or eipnames required
      - xxx
      - xxx     
    firewallid:                                 # or firewallname required
    vpcid:                                      # or vpcname required                                                    
    ifopenf: 0
    tag:                                       


# describe natgw
- name: describe natgw
  ucloud_nat:
    action: describe
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # required
  

# update natgw
- name: update natgw
  ucloud_nat:
    action: update
    public_key:                                 # required                            
    private_key:                                # required    
    region: cn-sh2                              # required


# delete natgw
- name: delete natgw
  ucloud_nat:
    action: delete
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # requried


"""


from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, CORE_PARAMS, CREATENAT_PARAMS, DELETENAT_PARAMS, UPDATENAT_PARAMS, \
    DESCRIBENAT_PARAMS


def create(module, **kwargs):
    ur = UhttpRequests('CreateNATGW', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeNATGW', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def delete(module, **kwargs):
    ur = UhttpRequests('DeleteNATGW', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update(module, **kwargs):
    ur = UhttpRequests('UpdateNATGW', **kwargs)
    resp = ur.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def _list_subnets(module, **kwargs):
    ur = UhttpRequests('DescribeSubnet', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_eips(module, **kwargs):
    ur = UhttpRequests('DescribeEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['EIPSet'] if 'EIPSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_vpcs(module, **kwargs):
    ur = UhttpRequests('DescribeVPC', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_firewall(module, **kwargs):
    ur = UhttpRequests('DescribeFirewall', **kwargs)
    resp = ur.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_nat(module, **kwargs):
    ur = UhttpRequests('DescribeNATGW', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def find_natinfo_by_name(module, name, result):
    match_nat = list(filter(lambda x: x['NATGWName'] == name, result))
    if len(match_nat) > 1:
        module.fail_json(msg='NATGW Named {0} is more than 1'.format(name))
    else:
        return match_nat[0]


def find_natid_by_name(module, name, result, flag='NATGWId'):
    nat_info = find_natinfo_by_name(module, name, result)
    return nat_info[flag]


def find_firewallid_by_name(module, name, result):
    if name in [i['Name'] for i in result]:
        match_firewall = list(filter(lambda x: x['Name'] == name, result))
        if len(match_firewall) > 1:
            module.fail_json(msg='Firewall Named {0} is more than 1'.format(name))
        else:
            return match_firewall[0]['FWId']
    else:
        module.fail_json(msg='Can not Found Firewall Named {0} in firewall list'.format(name))


def find_vpcid_by_name(module, name, result):
    if name in [i['Name'] for i in result]:
        match_vpc = list(filter(lambda x: x['Name'] == name, result))
        if len(match_vpc) > 1:
            module.fail_json(msg='VPC Named {0} is more than 1'.format(name))
        else:
            return match_vpc[0]['VPCId']
    else:
        module.fail_json(msg='Can not Found VPC Named {0} in vpc list'.format(name))


def find_subnetid_by_name(module, name, result):
    if name in [i['SubnetName'] for i in result]:
        match_subnet = list(filter(lambda x: x['SubnetName'] == name, result))
        if len(match_subnet) > 1:
            module.fail_json(msg='Subnet Named {0} is more than 1'.format(name))
        else:
            return match_subnet[0]['SubnetId']
    else:
        module.fail_json(msg='Can not Found Subnet Named {0} in subnet list'.format(name))


def find_eipid_by_name(module, name, result):
    if name in [i['Name'] for i in result]:
        match_eip = list(filter(lambda x: x['Name'] == name, result))
        if len(match_eip) > 1:
            module.fail_json(msg='EIP Named {0} is more than 1'.format(name))
        else:
            return match_eip[0]['EIPId']
    else:
        module.fail_json(msg='Can not Found EIP Named {0} in EIP list'.format(name))


def update_kwargs_by_name(module, name, **kwargs):
    describe_nat_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    nats = _list_nat(module, **describe_nat_params)
    if nats and name in [i['NATGWName'] for i in nats]:
        natgwid = find_natid_by_name(module, name, nats)
        kwargs['NATGWId'] = natgwid
    else:
        module.fail_json(msg='Can not Found NATGW Named {0} in list'.format(name))
    return kwargs


def is_create_nat_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATENAT_PARAMS + CORE_PARAMS else False


def is_delete_nat_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DELETENAT_PARAMS + CORE_PARAMS else False


def is_describe_nat_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBENAT_PARAMS + CORE_PARAMS else False


def is_update_nat_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in UPDATENAT_PARAMS + CORE_PARAMS else False


def main():
    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'delete', 'update', 'describe']),
        projectid=dict(type='str'),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        natgwname=dict(type='str'),
        newnatgwname=dict(tye='str'),
        natgwnames=dict(type='list'),
        natgwid=dict(type='str'),
        natgwids=dict(type='list'),
        subnetworkids=dict(type='list'),
        subnetnames=dict(type='list'),
        eipids=dict(type='list'),
        eipnames=dict(type='list'),
        firewallid=dict(type='str'),
        firewallname=dict(type='str'),
        vpcid=dict(type='str'),
        vpcname=dict(type='str'),
        ifopenf=dict(type='int', choice=[1, 0], default=0),
        tag=dict(type='str')
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    action = module.params.get('action')
    projectid = module.params.get('projectid')
    public_key = module.params.get('public_key')
    private_key = module.params.get('private_key')
    region = module.params.get('region')
    natgwname = module.params.get('natgwname')
    newnatgwname = module.params.get('newnatgwname')
    natgwnames = module.params.get('natgwnames')
    natgwid = module.params.get('natgwid')
    natgwids = module.params.get('natgwids')
    subnetworkids = module.params.get('subnetworkids')
    subnetnames = module.params.get('subnetnames')
    eipids = module.params.get('eipids')
    eipnames = module.params.get('eipnames')
    firewallid = module.params.get('firewallid')
    firewallname = module.params.get('firewallname')
    vpcid = module.params.get('vpcid')
    vpcname = module.params.get('vpcname')
    ifopenf = module.params.get('ifopenf')
    tag = module.params.get('tag')

    kwargs = dict(
        Region=region,
        ProjectId=projectid,
        PublicKey=public_key,
        PrivateKey=private_key,
        NATGWId=natgwid,
        NATGWName=natgwname,
        SubnetworkIds=subnetworkids,
        EIPIds=eipids,
        FirewallId=firewallid,
        VPCId=vpcid,
        ifOpenf=ifopenf,
        Tag=tag,
        Limit=1000
        # Ucloud 的describe (tag)逻辑问题, 目前这边都用1000 来保证取得全部符合条件的Uhost, subnet, natgw, firewall, eip
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'create':
        kwargs = dict(filter(is_create_nat_params, kwargs.items()))

        # 指定subnetnames, 则获取subnetids
        if subnetnames and not subnetworkids:
            describe_subnet_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            subnetworkids = set()
            subnet_list = _list_subnets(module, **describe_subnet_params)
            if not subnet_list:
                module.fail_json(msg='There is no Subnet')

            for subnetname in subnetnames:
                subnetid = find_subnetid_by_name(module, subnetname, subnet_list)
                subnetworkids.add(subnetid)

            for index, value in enumerate(subnetworkids):
                _key = "{0}.{1}".format('SubnetworkIds', index)
                kwargs[_key] = value

        # 指定eip name, 则获取eip id
        if eipnames and not eipids:
            describe_eip_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            eipids = set()
            eip_list = _list_eips(module, **describe_eip_params)
            if not eip_list:
                module.fail_json(msg='There is no EIP')
            for eipname in eipnames:
                eipid = find_eipid_by_name(module, eipname, eip_list)
                eipids.add(eipid)

            for index, value in enumerate(eipids):
                _key = "{0}.{1}".format("EIPIds", index)
                kwargs[_key] = value

        # 指定 firewallname, 则获取firewall id
        if firewallname and not firewallid:
            describe_firewall_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            firewall_list = _list_firewall(module, **describe_firewall_params)
            if not firewall_list:
                module.fail_json(msg='There is no firewall')
            firewallid = find_firewallid_by_name(module, firewallname, firewall_list)
            kwargs['FirewallId'] = firewallid

        # 指定vpc name, 则获取vpc id
        if vpcname and not vpcid:
            describe_vpc_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            vpc_list = _list_vpcs(module, **describe_vpc_params)
            if not vpc_list:
                module.fail_json(msg='There is no vpc')
            vpcid = find_vpcid_by_name(module, vpcname, vpc_list)
            kwargs['VPCId'] = vpcid


        # 检测是否同名
        describe_nat_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )
        nats = _list_nat(module, **describe_nat_params)
        if kwargs['NATGWName'] in [i['NATGWName'] for i in nats]:
            module.warn("NATGW Named {0} is already exists!".format(kwargs['NATGWName']))
            nat_info = find_natinfo_by_name(module, kwargs['NATGWName'], nats)
            module.exit_json(**nat_info)
        else:
            create(module, **kwargs)


    if action == 'delete':
        kwargs = dict(filter(is_delete_nat_params, kwargs.items()))

        #指定 natgw name, 获取natgw id
        if natgwname and not natgwid:
            kwargs = update_kwargs_by_name(module, natgwname, **kwargs)
        delete(module, **kwargs)

    if action == 'update':
        kwargs = dict(filter(is_update_nat_params, kwargs.items()))

        if natgwname and not natgwid:
            kwargs = update_kwargs_by_name(module, natgwname, **kwargs)
        kwargs['NATGWName'] = newnatgwname

        update(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_nat_params, kwargs.items()))

        # 指定 natgwnames, 获取 natgwids
        if natgwnames and not natgwids:
            result = defaultdict(list)
            nats = _list_nat(module, **kwargs)
            for natgwname in natgwnames:
                if natgwname in [i['NATGWName'] for i in nats]:
                    nat_info = find_natinfo_by_name(module, natgwname, nats)
                    result['DataSet'].append(nat_info)
            module.exit_json(**result)

        if natgwids:
            for index, value in enumerate(natgwids):
                _key = "{0}.{1}".format("NATGWIds", index)
                kwargs[_key] = value

        describe(module, **kwargs)


if __name__ == "__main__":
    main()