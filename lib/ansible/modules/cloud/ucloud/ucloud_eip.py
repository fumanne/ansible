#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_eip

short_description: allocate, bind, unbind, release, describe, update eip

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
 

options:
  action: 
    description:
      - the action of eip, allocate, bind, unbind, release, describe
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


  operatorname:
    description:
      - operator name of eip, if action is allocate, it required.
      - "choice: [Telecom, Unicom, Bgp, Duplet]"

  bandwidth:
    description:
      - "eip bandwidth, unit: Mbps"
    type: int

  tag:
    description:
      - tag name
    required: false

  chargetype:
    description:
      - "charge Type, choice: [Year, Month, Dynamic]"
    required: false

  quantity:
    description:
      - time of purchase
    default: 1

  paymode:
    description:
      - "paymode of eip, choice: [Traffic, Bandwidth, ShareBandwidth]"
    default: Bandwidth
    
  sharebandwidthid:
    description:
      - only paymod is ShareBandwidth, it requried
 
  couponid:
    description:
      - coupon id

  name:
    description:
      - name of eip
      
  newname:
    description:
      - if update, newname is required
  
  names:
    description:
      - list name eip
 
  eipids:
    description:
      - id of eip 
    type: list
    
  eipid:
    description:
      - id of eip
      
  resourcetype:
    description:
      - "id of resource, only action is bind or unbind, it required, choice: [uhost, vrouter, ulb, upm, hadoophost]"
    
  resourceid:
    description:
      - id of resource,
 
  uhostname:
    description:
      - uhostname, apply in uhost
    
      
notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"
  
author:
  - fu-l@klab.com
'''

EXAMPLES = """

# allocate eip
- name: allocate eip
  ucloud_eip:
    action: allocate
    public_key:                                 # required
    private_key:                                # required
    operatorname:  Bgp                          # required
    bandwidth:    10                            # required
    tag:
    chargetype: Dynamic
    paymode: Traffic
    name:                                       


# describe eip
- name: describe eip by eip
  ucloud_eip:
    action: describe
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # required
    eipids:                                     # required    
      - xxx
      - zzz


- name: describe eip by name
  ucloud_eip:
    action: describe
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # required
    names:                                      # required
      - mmm
      - nnn

# update eip
- name: update eip by id
  ucloud_eip:
    action: update
    public_key:                                 # required                            
    private_key:                                # required    
    region: cn-sh2                              # required
    eipid:                                      # required
    
- name: update eip by name
  ucloud_eip:
    action: update
    public_key:                                 # required                            
    private_key:                                # required    
    region: cn-sh2                              # required
    name:                                       # required
    newname:
    

# bind eip
- name: bind eip
  ucloud_eip:
    action: bind
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # requried
    name:                                       # or eipid
    resourcetype: uhost
    uhostname: xxx
    
# unbind eip
- name: unbind eip
  ucloud_eip:
    action: unbind
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # requried
    name:                                       # or eipid
    resourcetype: uhost
    uhostname: xxx  
 
# relase eip
- name: release eip
  ucloud_eip:
    action: release
    public_key:                                 # required
    private_key:                                # required
    region: cn-sh2                              # requried
    name:                                       # or eipid
    
"""

from collections import defaultdict
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, CORE_PARAMS, ALLOCATEEIP_PARAMS, BINDEIP_PARAMS, \
    UNBINDEIP_PARAMS, DESCRIBEEIP_PARAMS, UPDATEEIP_PARAMS, RELEASEEIP_PARAMS, MODIDYEIP_PARAMS


def allocate(module, **kwargs):
    ur = UhttpRequests("AllocateEIP", **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.exit_json(msg=resp)


def bind(module, **kwargs):
    ur = UhttpRequests('BindEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def unbind(module, **kwargs):
    ur = UhttpRequests('UnBindEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def update(module, **kwargs):
    ur = UhttpRequests('UpdateEIPAttribute', **kwargs)
    resp = ur.urequest("GET")
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def release(module, **kwargs):
    ur = UhttpRequests('ReleaseEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def modify(module, **kwargs):
    ur = UhttpRequests('ModifyEIPBandwidth', **kwargs)
    resp = ur.urequest("GET")
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def is_allocate_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in ALLOCATEEIP_PARAMS + CORE_PARAMS else False


def is_describe_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEEIP_PARAMS + CORE_PARAMS else False


def is_bind_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in BINDEIP_PARAMS + CORE_PARAMS else False


def is_unbind_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in UNBINDEIP_PARAMS + CORE_PARAMS else False


def is_update_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in UPDATEEIP_PARAMS + CORE_PARAMS else False


def is_release_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in RELEASEEIP_PARAMS + CORE_PARAMS else False


def is_modify_eip_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in MODIDYEIP_PARAMS + CORE_PARAMS else False


def _list_eips(module, **kwargs):
    ur = UhttpRequests('DescribeEIP', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['EIPSet'] if 'EIPSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_uhosts(module, **kwargs):
    ur = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['UHostSet'] if 'UHostSet' in resp else None
    else:
        module.fail_json(msg=resp)


def find_eip_info_by_name(module, name, result):
    match_eip = list(filter(lambda x: x['Name'] == name, result))
    if len(match_eip) > 1:
        module.fail_json(msg="EIP Named {0} is more than 1".format(name))
    else:
        return match_eip[0]


def find_eipid_by_name(module, name, result, flag='EIPId'):
    eip_info = find_eip_info_by_name(module, name, result)
    return eip_info[flag]


def update_kwargs_by_name(module, name, **kwargs):
    describe_eip_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    eips = _list_eips(module, **describe_eip_params)
    if eips and name in [i['Name'] for i in eips]:
        eipid = find_eipid_by_name(module, name, eips)
        kwargs['EIPId'] = eipid
    else:
        module.fail_json(msg='Can not Found EIP Named {0} in list'.format(name))
    return kwargs


def find_uhostid_by_uhostname(module, name, result):
    if name in [i['Name'] for i in result]:
        uhost_info = list(filter(lambda x: x['Name'] == name, result))
        if len(uhost_info) > 1:
            module.fail_json(msg="UHost Named {0} is more than 1".format(name))
        else:
            return uhost_info[0]['UHostId']
    else:
        module.fail_json(msg='Can not Found UHost Named {0} in Host list'.format(name))


def main():
    module_args = dict(
        action=dict(type='str', required=True, choice=['allocate', 'bind', 'unbind', 'release', 'describe', 'modify']),
        projectid=dict(type='str'),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        operatorname=dict(type='str', choice=['Telecom', 'Unicom', 'Bgp', 'Duplet']),
        bandwidth=dict(type='int'),
        tag=dict(type='str'),
        chargetype=dict(type='str', choice=['Year', 'Month', 'Dynamic']),
        quantity=dict(type='int'),
        paymode=dict(type='str', choice=['Traffic', 'Bandwidth', 'ShareBandwidth']),
        sharebandwidthid=dict(type='str'),
        couponid=dict(type='str'),
        name=dict(type='str'),
        newname=dict(type='str'),
        names=dict(type='list'),
        eipids=dict(type='list'),
        eipid=dict(type='str'),
        resourcetype=dict(type='str'),
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
    operatorname = module.params.get('operatorname')
    bandwidth = module.params.get('bandwidth')
    tag = module.params.get('tag')
    chargetype = module.params.get('chargetype')
    quantity = module.params.get('quantity')
    paymode = module.params.get('paymode')
    sharebandwidthid = module.params.get('sharebandwidthid')
    couponid = module.params.get('couponid')
    name = module.params.get('name')
    newname = module.params.get('newname')
    names = module.params.get('names')
    eipid = module.params.get('eipid')
    eipids = module.params.get('eipids')
    resourcetype = module.params.get('resourcetype')
    resourceid = module.params.get('resourceid')
    uhostname = module.params.get('uhostname')
    projectid = module.params.get('projectid')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        OperatorName=operatorname,
        Bandwidth=bandwidth,
        Tag=tag,
        ChargeType=chargetype,
        Quantity=quantity,
        PayMode=paymode,
        ShareBandwidthId=sharebandwidthid,
        CouponId=couponid,
        Name=name,
        EIPId=eipid,
        ResourceType=resourcetype,
        ResourceId=resourceid,
        ProjectId=projectid,
        Limit=1000
        # Ucloud 的describe (tag)逻辑问题, 目前这边都用1000 来保证取得全部符合条件的Uhost, subnet, natgw, firewall, eip
    )
    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'allocate':
        kwargs = dict(filter(is_allocate_eip_params, kwargs.items()))

        # 检测是否同名
        describe_eip_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )
        eips = _list_eips(module, **describe_eip_params)
        if eips and kwargs['Name'] in [i['Name'] for i in eips]:
            module.warn("EIP Named {0} is already exists!".format(kwargs['Name']))
            eip_info = find_eip_info_by_name(module, kwargs['Name'], eips)
            module.exit_json(**eip_info)

        allocate(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_eip_params, kwargs.items()))

        if names and not eipids:
            result = defaultdict(list)
            eips = _list_eips(module, **kwargs)
            if not eips:
                module.fail_json(msg='There is no EIPs')
            for name in names:
                if name in [i['Name'] for i in eips]:
                    eip_info = find_eip_info_by_name(module, name, eips)
                    result['EIPSet'].append(eip_info)
            module.exit_json(**result)

        if eipids:
            for index, value in enumerate(eipids):
                _key = "{0}.{1}".format("EIPIds", index)
                kwargs[_key] = value

        describe(module, **kwargs)

    if action == 'bind':
        kwargs = dict(filter(is_bind_eip_params, kwargs.items()))

        describe_eip_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )
        eips = _list_eips(module, **describe_eip_params)
        if not eips:
            module.fail_json(msg='There is no EIPs')
        # 指定eip name, 获取对应eipid
        if name and not eipid:
            eipid = find_eipid_by_name(module, name, eips)
            kwargs['EIPId'] = eipid

        eip_info = list(filter(lambda x: x['EIPId'] == kwargs['EIPId'], eips))[0]

        # 指定uhost name, 获取对应的uhostid
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
                module.fail_json(msg='There is no UHosts')
            uhostid = find_uhostid_by_uhostname(module, uhostname, uhosts)
            kwargs['ResourceId'] = uhostid

        # 获取到eipid 和 resourceid 后, 判断是否对应的eipid 的info 里已经bind 了 resourceid
        if 'Resource' in eip_info and kwargs['ResourceId'] == eip_info['Resource']['ResourceID']:
            module.warn("EIPId {0} has already bind to Uhost {1}".format(kwargs['EIPId'], kwargs['ResourceId']))
            module.exit_json(**eip_info)

        bind(module, **kwargs)

    if action == 'unbind':
        kwargs = dict(filter(is_unbind_eip_params, kwargs.items()))
        # 指定eip name, 获取对应id
        if name and not eipid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        # 指定uhost name, 获取对应的uhostid
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
                module.fail_json(msg='There is no UHosts')
            uhostid = find_uhostid_by_uhostname(module, uhostname, uhosts)
            kwargs['ResourceId'] = uhostid
        unbind(module, **kwargs)

    if action == 'update':
        kwargs = dict(filter(is_update_eip_params, kwargs.items()))

        # 指定eip name, 获取对应id
        if name and  not eipid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        kwargs['Name'] = newname
        update(module, **kwargs)

    if action == 'release':
        kwargs = dict(filter(is_release_eip_params, kwargs.items()))
        # 指定eip name, 获取对应id
        if name and not eipid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        release(module, **kwargs)

    if action == 'modify':
        kwargs = dict(filter(is_modify_eip_params, kwargs.items()))
        # 指定eip name, 获取对应id
        if name and not eipid:
            kwargs = update_kwargs_by_name(module, name, **kwargs)

        modify(module, **kwargs)

if __name__ == "__main__":
    main()