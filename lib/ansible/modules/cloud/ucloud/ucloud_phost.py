#! /usr/bin/env python
# ! -*- encoding: utf-8 -*-


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_phost

short_description: create, terminate, stop, start, reboot, describe ucloud instance

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
  - any action of uhost, if parameter is surplus, do not care and handle it. make sure the required parameter of specical action

options:
  action:
    description:
      - the action of phost (create, terminate, reboot, stop, start, describe)
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

  zone:
    description:
      - "the zone of ucloud, see https://docs.ucloud.cn/api/summary/regionlist.html"
    default: cn-sh2-02
  
  imageid:
    description:
      - the image id of ucloud, if action is create it must be required
    default: pimg-hd04-snqt2l
  
  password:
    description:
      - the password of uhost, if action is create and loginmode is password it must be required
    default: Klab@sh2017
  
  name:
    description:
      - the name of uhost
    default: Auto
  
  type:
    description:
      - type if machine
    choice: [SSD, DB]
    default: DB
  
  tag:
    description:
      - the business of name
    default: null
  
  couponid:
    description:
      - the ticket id
    default: null
  
  chargetype:
    description:
      - the type of charge
    default: Month
    choice: [Year, Month]
  
  quantity:
    description:
      - the time of purchase
    default: 1
  
  projectid:
    description:
      - the project id
    default: null
   
  count:
    description:
      - number of machine
    default: 1
    
  reserve:
    description:
      - purchase type
    default: 0
    
  vpcid:
    description:
      - vpc id

  vpc:
    description:
      - name of vpc
      
  subnetid:
    description:
      - subnet id

  subnet:
    description:
      - name of subnet

  phostid:
    description:
      - host id, use for one host

  phostids:
    description:
      - host id, use for many hosts
    type: list

  phostname:
    description:
      - host name, use for one host

  phostnames:
    description:
      - host name, use for many hosts
    type: list

notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"

author:
  - fu-l@klab.com
'''

EXAMPLES = '''
# simple create phost
- name: create phost
  ucloud_phost:
    action: create
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    imageid: pimg-hd04-snqt2l       # required
    password: klab@sh2017           # required    
    name: auto_phost
    chargetype: Month
    vpcid:                          # id
    subnetid:                       # id

    
# create phost another argument use vpc  or subnet name
- name: create phost
  ucloud_phost:
    action: create
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    imageid: pimg-hd04-snqt2l       # required
    password: klab@sh2017           # required
    vpc: myvpc                      # name
    subnet: mysubnet                # name
    

# simple describe phost
- name: describe phost
  ucloud_phost:
    action: describe
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    phostids:                       # required
      - upm-od45jw
      - upm-1hlemn
    tag:

# use name to describe phost
- name: describe phost by name
    ucloud_phost:
      action: describe
      public_key:                     # required
      private_key:                    # required
      region: cn-sh2                  # required
      zone: cn-sh2-02
      phostnames:                     # required
        - node1
        - node2
      tag:

# simple terminate phost
- name: terminate phost
  ucloud_phost:
    action: terminate
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # requried
    zone: cn-sh2-02
    phostid:                        # required

# terminate phost by phostname
- name: terminate host by phostname
  ucloud_phost:
    action: terminate
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # requried
    zone: cn-sh2-02
    phostname:                      # required


# simple reboot phost by (phostid or phostname)
- name: reboot phost
  ucloud_phost:
    action: reboot
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    projectid:
    uhostid:                        # required

# simple stop phost
- name: stop phost
  ucloud_phost:
    action: stop
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    phostid:                        # required
    projectid:

# simple start phost
- name: start phost
  ucloud_phost:
    action: start
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    phostid:                        # required
    projectid:

'''

import base64
from collections import defaultdict
import six
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, ZONE, CORE_PARAMS, STARTUHOST_PARAMS, STOPUHOST_PARAMS, \
    REBOOTUHOST_PARAMS, CREATUHOSTSNAP_PARAMS, TERMINATEUHOST_PARAMS, DESCRIBEUHOST_PARAMS, \
    RESETPASSWORD_PARAMS, MODIFYUHOST_PARAMS, DESCRIBEPHOST_PARAMS, TERMINATEPHOST_PARAMS, REBOOTPHOST_PARAMS, \
    POWEROFFPHOST_PARAMS, STARTPHOST_PARAMS



def create(module, **kwargs):
    ui = UhttpRequests('CreatePHost', **kwargs)
    resp = ui.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def poweroff(module, **kwargs):
    ui = UhttpRequests('PoweroffPHost', **kwargs)
    resp = ui.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def reboot(module, **kwargs):
    ui = UhttpRequests('RebootPHost', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def terminate(module, **kwargs):
    ui = UhttpRequests('TerminatePHost', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def start(module, **kwargs):
    ui = UhttpRequests('StartPHost', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ui = UhttpRequests('DescribePHost', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        result = defaultdict(list)
        uhosts = resp['UHostSet']
        for uhost_info in uhosts:
          result['UHostSet'].append(extract_ips(uhost_info))
        module.exit_json(**result)
    else:
        module.fail_json(msg=resp)


def _base64_password(password_str):
    _s = str(password_str) if six.PY2 else bytes(password_str, 'utf-8')
    return base64.standard_b64encode(_s).decode('utf-8')


def _list_phosts(module, **kwargs):
    ui = UhttpRequests('DescribePHost', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['PHostSet'] if 'PHostSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_vpcs(module, **kwargs):
    ui = UhttpRequests('DescribeVPC', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_subnets(module, **kwargs):
    ui = UhttpRequests('DescribeSubnet', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def update_kwargs_by_phostname(module, phostname, **kwargs):
    describe_phost_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    phosts = _list_phosts(module, **describe_phost_params)
    if phosts and phostname in [i['Name'] for i in phosts]:
        phostid = find_phostid_by_name(module, phostname, phosts)
        kwargs['PHostId'] = phostid
    else:
        module.fail_json(msg='Can not Found PHost Named {0} in list'.format(phostname))
    return kwargs


def find_phostinfo_by_name(module, name, result):
    match_phost = list(filter(lambda x: x['Name'] == name, result))
    if len(match_phost) > 1:
        module.fail_json(msg='PHost Named {0} is more than 1'.format(name))
    else:
        return match_phost[0]


def find_phostid_by_name(module, name, result, flag='PHostId'):
    phost_info = find_phostinfo_by_name(module, name, result)
    return phost_info[flag]


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


def find_subnetid_by_name(module, name, result):
    if name in [i['SubnetName'] for i in result]:
        match_subnet = list(filter(lambda x: x['SubnetName'] == name, result))
        if len(match_subnet) > 1:
            module.fail_json(msg="Subnet Named {0} is more than 1".format(name))
        else:
            subnet_info = match_subnet[0]
            return subnet_info['SubnetId']
    else:
        module.fail_json(msg='Can not find {0} in Subnet list'.format(name))


def is_describe_phost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEPHOST_PARAMS + CORE_PARAMS else False


def is_terminate_phost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in TERMINATEPHOST_PARAMS + CORE_PARAMS else False


def is_reboot_phost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in REBOOTPHOST_PARAMS + CORE_PARAMS else False


def is_poweroff_phost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in POWEROFFPHOST_PARAMS + CORE_PARAMS else False


def is_start_phost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in STARTPHOST_PARAMS + CORE_PARAMS else False


def extract_ips(instance):
    if 'IPSet' in instance:
        for ip in instance['IPSet']:
            if 'IP' in ip:
                instance[ip['Type'] + 'IP'] = ip['IP']
            if 'IPAddr' in ip:
                instance[ip['OperatorName'] + 'IP'] = ip['IPAddr']
            instance['PublicIP'] = instance.get('BgpIP') or instance.get('InternationalIP') or instance.get('TelecomIP') or instance.get('UnicomIP')
    return instance

def main():
    # define the available arguments/parameters that a user can pass to
    # the module
    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'poweroff', 'terminate', 'reboot', 'describe', 'start']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        zone=dict(type='str', choice=ZONE),
        imageid=dict(type='str', default='pimg-hd04-snqt2l'),
        password=dict(type='str', default='Klab@sh2017'),
        name=dict(type='str', default='Auto_PHost'),
        type=dict(type='str', choice=['DB', 'SSD']),
        chargetype=dict(type='str', default='Month', choice=['Year', 'Month', 'Dynamic', 'Trial']),
        tag=dict(type='str'),
        couponid=dict(type='str'),
        reserve=dict(type='int', default=0),
        projectid=dict(type='str', default='org-a41n54'),
        vpcid=dict(type='str'),
        vpc=dict(type='str'),
        subnetid=dict(type='str'),
        subnet=dict(type='str'),
        phostid=dict(type='str'),
        phostids=dict(type='list'),
        phostname=dict(type='str'),
        phostnames=dict(type='list')
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    action = module.params.get('action')
    public_key = module.params.get('public_key')
    private_key = module.params.get('private_key')
    region = module.params.get('region')
    zone = module.params.get('zone')
    imageid = module.params.get('imageid')
    password = module.params.get('password')
    name = module.params.get('name')
    chargetype = module.params.get('chargetype')
    tag = module.params.get('tag')
    couponid = module.params.get('couponid')
    projectid = module.params.get('projectid')
    type = module.params.get('type')
    vpcid = module.params.get('vpcid')
    vpc = module.params.get('vpc')
    subnetid = module.params.get('subnetid')
    subnet = module.params.get('subnet')
    phostid = module.params.get('phostid')
    phostids = module.params.get('phostids')
    phostname = module.params.get('phostname')
    phostnames = module.params.get('phostnames')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        Zone=zone,
        ImageId=imageid,
        Password=_base64_password(password) if password else None,
        Name=name,
        Type=type,
        ChargeType=chargetype,
        Tag=tag,
        CouponId=couponid,
        ProjectId=projectid,
        VPCId=vpcid,
        SubnetId=subnetid,
        PHostId=phostid,
        Limit=1000
        # Ucloud 的describe (tag)逻辑问题, 目前这边都用1000 来保证取得全部符合条件的Uhost, subnet, natgw, firewall, eip
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'create':

        # 设定vpc name, 则获取vpcid
        if vpc and 'VPCId' not in kwargs:
            describe_vpc_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey']
            )

            vpc_list = _list_vpcs(module, **describe_vpc_params)
            if not vpc_list:
                module.fail_json(msg='There is no VPC')
            kwargs['VPCId'] = find_vpcid_by_name(module, vpc, vpc_list)

        # 设定subnet name, 则获取subnetid
        if subnet and "SubnetId" not in kwargs:
            describe_subnet_params = dict(
                Region=kwargs['Region'],
                ProjectId=kwargs['ProjectId'],
                PublicKey=kwargs['PublicKey'],
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )
            subnet_list = _list_subnets(module, **describe_subnet_params)
            if not subnet_list:
                module.fail_json(msg='There is no Subnet')
            kwargs['SubnetId'] = find_subnetid_by_name(module, subnet, subnet_list)

        # 检测同名phost, 存在返回 该phost 信息 (Dict)
        describe_phost_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )

        phosts = _list_phosts(module, **describe_phost_params)

        if phosts and kwargs['Name'] in [i['Name'] for i in phosts]:
            module.warn("PHost Named {0} is already exists!".format(kwargs['Name']))
            phost_info = find_phostinfo_by_name(module, kwargs['Name'], phosts)
            module.exit_json(**phost_info)

        create(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_phost_params, kwargs.items()))
        if phostnames and not phostids:
            result = defaultdict(list)
            phosts = _list_phosts(module, **kwargs)
            if not phosts:
                module.fail_json(msg='There is no phosts list')
            for name in phostnames:
                if name in [i['Name'] for i in phosts]:
                    phost_info = find_phostinfo_by_name(module, name, phosts)
                    result['PHostSet'].append(extract_ips(phost_info))
            module.exit_json(**result)

        if phostids:
            for index, value in enumerate(phostids):
                _key = "{0}.{1}".format('PHostIds', index)
                kwargs[_key] = value
        describe(module, **kwargs)

    if action == 'terminate':
        kwargs = dict(filter(is_terminate_phost_params, kwargs.items()))
        if phostname and not phostid:
            kwargs = update_kwargs_by_phostname(module, phostname, **kwargs)

        terminate(module, **kwargs)

    if action == 'reboot':
        kwargs = dict(filter(is_reboot_phost_params, kwargs.items()))
        if phostname and not phostid:
            kwargs = update_kwargs_by_phostname(module, phostname, **kwargs)
        reboot(module, **kwargs)

    if action == 'poweroff':
        kwargs = dict(filter(is_poweroff_phost_params, kwargs.items()))
        if phostname and not phostid:
            kwargs = update_kwargs_by_phostname(module, phostname, **kwargs)
        poweroff(module, **kwargs)

    if action == 'start':
        kwargs = dict(filter(is_start_phost_params, kwargs.items()))
        if phostname and not phostid:
            kwargs = update_kwargs_by_phostname(module, phostname, **kwargs)
        start(module, **kwargs)


if __name__ == '__main__':
    main()
