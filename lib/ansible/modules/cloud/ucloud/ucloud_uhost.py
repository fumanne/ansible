#! /usr/bin/env python
# ! -*- encoding: utf-8 -*-


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_uhost

short_description: create, terminate, stop, start, reboot, describe ucloud instance

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
  - any action of uhost, if parameter is surplus, do not care and handle it. make sure the required parameter of specical action

options:
  action:
    description:
      - the action of uhost (create, terminate, reboot, stop, start, describe)
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
    default: uimage-c14f5s
  
  loginmode:
    description:
      - the mode of login
    default: Password
    choice: [Password, key, KeyPair]
  
  password:
    description:
      - the password of uhost, if action is create and loginmode is password it must be required
    default: Klab@sh2017
  
  cpu:
    description:
      - the cpu count of uhost
    default: 4
    choice: ['1','2','4','8','12','16','24','32']
  
  memory:
    description:
      - "the memory of uhost, unit: MB, range:[1024, 131072]"
    default: 4096        
  
  storagetype:
    description:
      - the type of disk
    default: LocalDisk
    choice: [LocalDisk, UDisk]
  
  diskspace:
    description:
      - "the space of disk, unit: GB, step: 10, range: [20, 2000]"
    default: 20
  
  name:
    description:
      - the name of uhost
    default: Auto
  
  networkid:
    description:
      - the id of network
    default: subnet-3dpfod
  
  securitygroupid:
    description:
      - security id 
    default: null
  
  netcapability:
    description:
      - the mode of network performance     
    default: Normal
    choice: [Enhance, Super, Ultra, Extreme, Normal]
  
  quantity:
    description:
      - the time of purchase, 0 presents the end of months, if use Dynamic chargeType, not use this parameter
  
  chargetype:
    description:
      - the type of charge
    default: Month
    choice: [Year, Month, Dynamic, Trial]
  
  tag:
    description:
      - the business of name
    default: null
  
  couponid:
    description:
      - the ticket id
    default: null
  
  bootdiskspace:
    description:
      - "space of  boot paratition, unit: GB, step: 10, range: [20, 1000]"
    default: 20
  
  projectid:
    description:
      - the project id
    default: null
  
  timemachinefeature:
    description:
      - timemachine feature 
    default: No
    type: bool
  
  hotplugfeature:
    description:
      - the hot plug feature
    default: false
    type: bool   
  
  uhosttype:
    description:
      - the type of uhost
    default: Normal
    choice: [Normal, SATA_SSD, BigData]
  
  gpu:
    description:
      - the count of GPU
    default: null
    choice: ['1','2','3','4']
  
  diskpassword:
    description:
      - the disk encrytion password
    defult: null
  
  vpcid:
    description:
      - the id of vpc
    default: null
  
  vpc:
    description:
      - the name of vpc
  
  subnetid:
    description:
      - the id of subnet
    default: null
    
  subnet:
    description:
      - the name of subnet
  
  installagent:
    description:
      - wheather install agent, yes presents install agent
    default: null
  
  uhostid:
    description:
      - the id of uhost
  
  uhostids:
    description:
      - id of uhost
    type: list
  
  uhostname:
    description:
      - name of uhost
    type: str
    
  uhostnames:
    description:
      - name of uhost
    type: list
         
  destory:
    description:
      - whether put it into recycle
    default: 1
 

notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"

author:
  - fu-l@klab.com
'''

EXAMPLES = '''
# simple create uhost
- name: create uhost
  ucloud_uhost:
    action: create
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    imageid: uimage-c14f5s          # required
    loginmode: Password             # required
    password: klab@sh2017           # required    
    cpu: 2
    memory: 4096
    storagetype: LocalDisk
    bootdiskspace: 20
    diskspace: 40
    name: auto
    chargetype: Month
    vpcid:                          # id
    subnetid:                       # id

    
# create uhost another argument use vpc  or subnet name
- name: create uhost
  ucloud_uhost:
    action: create
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    imageid: uimage-c14f5s          # required
    loginmode: Password             # required
    password: klab@sh2017           # required
    cpu: 2
    memory: 4096
    storagetype: LocalDisk
    diskspace: 40
    vpc: myvpc                      # name
    subnet: mysubnet                # name
    

# simple describe uhost
- name: describe uhost
  ucloud_uhost:
    action: describe
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    uhostids:                       # required
      - uhost-mlu1fo
      - uhost-znasde
    tag:

# use name to describe uhost
- name: describe uhost by name
    ucloud_uhost:
      action: describe
      public_key:                     # required
      private_key:                    # required
      region: cn-sh2                  # required
      zone: cn-sh2-02
      uhostnames:                     # required
        - node1
        - node2
      tag:

# simple terminate uhost
- name: terminate uhost
  ucloud_uhost:
    action: terminate
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # requried
    zone: cn-sh2-02
    uhostid:                        # required
    destory: 1

# terminate uhost by uhostname
- name: terminate uhost by uhostname
  ucloud_uhost:
    action: terminate
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # requried
    zone: cn-sh2-02
    uhostname:                      # required
    destory: 1


# simple reboot uhost by (uhostid or uhostname)
- name: reboot uhost
  ucloud_uhost:
    action: reboot
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    projectid:
    uhostid:                        # required

# simple stop uhost
- name: stop uhost
  ucloud_uhost:
    action: stop
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    uhostid:                        # required
    projectid:

# simple start uhost
- name: start uhost
  ucloud_uhost:
    action: start
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    uhostid:                        # required
    projectid:

# reset password
- name: reset uhost password
  ucloud_uhost:
    action: resetpassword
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    zone: cn-sh2-02
    uhostid: uhost-xxx              # required
    password: aasdasda              # required

# create snapshot
- name: create snapshot
  ucloud_uhost:
    action: createsnap
    public_key:                     # required
    private_key:                    # required
    region: cn-sh2                  # required
    uhostid: uhost-xxx              # required
    
'''

import base64
from collections import defaultdict
import six
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, ZONE, CORE_PARAMS, STARTUHOST_PARAMS, STOPUHOST_PARAMS, \
    REBOOTUHOST_PARAMS, CREATUHOSTSNAP_PARAMS, TERMINATEUHOST_PARAMS, DESCRIBEUHOST_PARAMS, \
    RESETPASSWORD_PARAMS, MODIFYUHOST_PARAMS


def create(module, **kwargs):
    ui = UhttpRequests('CreateUHostInstance', **kwargs)
    resp = ui.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def stop(module, **kwargs):
    ui = UhttpRequests('StopUHostInstance', **kwargs)
    resp = ui.urequest('GET', retry=0)
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def reboot(module, **kwargs):
    ui = UhttpRequests('RebootUHostInstance', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def terminate(module, **kwargs):
    ui = UhttpRequests('TerminateUHostInstance', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def start(module, **kwargs):
    ui = UhttpRequests('StartUHostInstance', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ui = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        result = defaultdict(list)
        uhosts = resp['UHostSet']
        for uhost_info in uhosts:
          result['UHostSet'].append(extract_ips(uhost_info))
        module.exit_json(**result)
    else:
        module.fail_json(msg=resp)

# To List all instance inculde uhosts and phosts, the key use UHostSet
def describe_all(module, **kwargs):
    result = defaultdict(list)
    uh = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = uh.urequest('GET')
    if resp['RetCode'] == 0:
        uhosts = resp['UHostSet']
        for uhost_info in uhosts:
            result['UHostSet'].append(extract_ips(uhost_info))
    else:
        module.fail_json(msg=resp)

    up = UhttpRequests('DescribePHost', **kwargs)
    resp = up.urequest("GET")
    if resp['RetCode'] == 0:
        phosts = resp['PHostSet']
        for phost_info in phosts:
            result['UHostSet'].append(extract_ips(phost_info))
    else:
        module.fail_json(msg=resp)

    module.exit_json(**result)


def resetpassword(module, **kwargs):
    ui = UhttpRequests('ResetUHostInstancePassword', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def createsnap(module, **kwargs):
    ui = UhttpRequests('CreateUHostInstanceSnapshot', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def modifyhostname(module, **kwargs):
    ui = UhttpRequests('ModifyUHostInstanceName', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def _base64_password(password_str):
    _s = str(password_str) if six.PY2 else bytes(password_str, 'utf-8')
    return base64.standard_b64encode(_s).decode('utf-8')


def _list_uhosts(module, **kwargs):
    ui = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['UHostSet'] if 'UHostSet' in resp else None
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


def update_kwargs_by_uhostname(module, uhostname, **kwargs):
    describe_uhost_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    uhosts = _list_uhosts(module, **describe_uhost_params)
    if uhosts and uhostname in [i['Name'] for i in uhosts]:
        uhostid = find_uhostid_by_name(module, uhostname, uhosts)
        kwargs['UHostId'] = uhostid
    else:
        module.fail_json(msg='Can not Found UHost Named {0} in list'.format(uhostname))
    return kwargs


def find_uhostinfo_by_name(module, name, result):
    match_uhost = list(filter(lambda x: x['Name'] == name, result))
    if len(match_uhost) > 1:
        module.fail_json(msg='UHost Named {0} is more than 1'.format(name))
    else:
        return match_uhost[0]


def find_uhostid_by_name(module, name, result, flag='UHostId'):
    uhost_info = find_uhostinfo_by_name(module, name, result)
    return uhost_info[flag]


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


def is_describe_uhost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEUHOST_PARAMS + CORE_PARAMS else False


def is_terminate_uhost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in TERMINATEUHOST_PARAMS + CORE_PARAMS else False


def is_reboot_uhost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in REBOOTUHOST_PARAMS + CORE_PARAMS else False


def is_stop_uhost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in STOPUHOST_PARAMS + CORE_PARAMS else False


def is_start_uhost_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in STARTUHOST_PARAMS + CORE_PARAMS else False


def is_resetpassword_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in RESETPASSWORD_PARAMS + CORE_PARAMS else False


def is_createsnap_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATUHOSTSNAP_PARAMS + CORE_PARAMS else False


def is_modifyname_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in MODIFYUHOST_PARAMS + CORE_PARAMS else False

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
        action=dict(type='str', required=True, choice=['create', 'stop', 'terminate', 'reboot', 'describe']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        zone=dict(type='str', choice=ZONE),
        imageid=dict(type='str', default='uimage-c14f5s'),
        loginmode=dict(type='str', default='Password', choice=['Password', 'key', 'KeyPair']),
        password=dict(type='str', default='Klab@sh2017'),
        cpu=dict(type='int', default=4),
        memory=dict(type='int', default=4096),
        storagetype=dict(type='str', default='LocalDisk', choice=['LocalDisk', 'UDisk']),
        diskspace=dict(type='int', default=20),
        name=dict(type='str', default='Auto'),
        uhosttype=dict(type='str', default='Normal', choice=['Normal', 'SATA_SSD', 'BigData']),
        networkid=dict(type='str', default='subnet-3dpfod'),
        securitygroupid=dict(type='str'),
        netcapability=dict(type='str', default='Normal', choice=['Enhance', 'Super', 'Ultra', 'Extreme', 'Normal']),
        quantity=dict(type='int'),
        chargetype=dict(type='str', default='Month', choice=['Year', 'Month', 'Dynamic', 'Trial']),
        tag=dict(type='str'),
        couponid=dict(type='str'),
        bootdiskspace=dict(type='int', default=20),
        projectid=dict(type='str', default='org-a41n54'),
        timemachinefeature=dict(type='bool', default=False),
        hotplugfeature=dict(type='bool', default=False),
        gpu=dict(type='int', choice=[1, 2, 3, 4]),
        diskpassword=dict(type='str'),
        vpcid=dict(type='str'),
        vpc=dict(type='str'),
        subnetid=dict(type='str'),
        subnet=dict(type='str'),
        installagent=dict(type='bool', default=False),
        uhostid=dict(type='str'),
        uhostids=dict(type='list'),
        uhostname=dict(type='str'),
        uhostnames=dict(type='list'),
        destroy=dict(type='int', default=1, choice=[1, 0])
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
    loginmode = module.params.get('loginmode')
    password = module.params.get('password')
    cpu = module.params.get('cpu')
    memory = module.params.get('memory')
    storagetype = module.params.get('stroagetype')
    diskspace = module.params.get('diskspace')
    name = module.params.get('name')
    networkid = module.params.get('networkid')
    securitygroupid = module.params.get('securitygroupid')
    netcapability = module.params.get('netcapability')
    quantity = module.params.get('quantity')
    chargetype = module.params.get('chargetype')
    tag = module.params.get('tag')
    couponid = module.params.get('couponid')
    bootdiskspace = module.params.get('bootdiskspace')
    projectid = module.params.get('projectid')
    timemachinefeature = module.params.get('timemachinefeature')
    hotplugfeature = module.params.get('hotplugfeature')
    uhosttype = module.params.get('uhosttype')
    gpu = module.params.get('gpu')
    diskpassword = module.params.get('diskpassword')
    vpcid = module.params.get('vpcid')
    vpc = module.params.get('vpc')
    subnetid = module.params.get('subnetid')
    subnet = module.params.get('subnet')
    installagent = module.params.get('installagent')
    uhostid = module.params.get('uhostid')
    uhostids = module.params.get('uhostids')
    uhostname = module.params.get('uhostname')
    uhostnames = module.params.get('uhostnames')
    destroy = module.params.get('destroy')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        Zone=zone,
        ImageId=imageid,
        LoginMode=loginmode,
        Password=_base64_password(password) if password else None,
        CPU=cpu,
        Memory=memory,
        StorageType=storagetype,
        DiskSpace=diskspace,
        Name=name,
        NetworkId=networkid,
        SecurityGroupId=securitygroupid,
        NetCapability=netcapability,
        Quantity=quantity,
        ChargeType=chargetype,
        Tag=tag,
        CouponId=couponid,
        BootDiskSpace=bootdiskspace,
        ProjectId=projectid,
        TimemachineFeature=timemachinefeature,
        HotplugFeature=hotplugfeature,
        UHostType=uhosttype,
        GPU=gpu,
        DiskPassword=diskpassword,
        VPCId=vpcid,
        SubnetId=subnetid,
        InstallAgent=installagent,
        UHostId=uhostid,
        Destroy=destroy,
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
                PrivateKey=kwargs['PrivateKey'],
                Limit=kwargs['Limit']
            )

            vpc_list = _list_vpcs(module, **describe_vpc_params)
            if not vpc_list:
                module.exit_json(msg='There is no VPC')
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

        # 检测同名uhost, 存在返回 该uhost 信息 (Dict)
        describe_uhost_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )

        uhosts = _list_uhosts(module, **describe_uhost_params)

        if uhosts and kwargs['Name'] in [i['Name'] for i in uhosts]:
            module.warn("UHost Named {0} is already exists!".format(kwargs['Name']))
            uhost_info = find_uhostinfo_by_name(module, kwargs['Name'], uhosts)
            module.exit_json(**uhost_info)

        create(module, **kwargs)

    if action == 'describe':
        kwargs = dict(filter(is_describe_uhost_params, kwargs.items()))
        if uhostnames and not uhostids:
            result = defaultdict(list)
            uhosts = _list_uhosts(module, **kwargs)
            if not uhosts:
                module.fail_json(msg='There is no uhosts list')
            for name in uhostnames:
                if name in [i['Name'] for i in uhosts]:
                    uhost_info = find_uhostinfo_by_name(module, name, uhosts)
                    result['UHostSet'].append(extract_ips(uhost_info))
            module.exit_json(**result)

        if uhostids:
            for index, value in enumerate(uhostids):
                _key = "{0}.{1}".format('UHostIds', index)
                kwargs[_key] = value
        describe(module, **kwargs)

    if action == 'terminate':
        kwargs = dict(filter(is_terminate_uhost_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)

        terminate(module, **kwargs)

    if action == 'reboot':
        kwargs = dict(filter(is_reboot_uhost_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        reboot(module, **kwargs)

    if action == 'stop':
        kwargs = dict(filter(is_stop_uhost_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        stop(module, **kwargs)

    if action == 'start':
        kwargs = dict(filter(is_start_uhost_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        start(module, **kwargs)

    if action == 'resetpassword':
        kwargs = dict(filter(is_resetpassword_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        resetpassword(module, **kwargs)

    if action == 'createsnap':
        kwargs = dict(filter(is_createsnap_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        createsnap(module, **kwargs)

    if action == 'modifyhostname':
        kwargs = dict(filter(is_modifyname_params, kwargs.items()))
        if uhostname and not uhostid:
            kwargs = update_kwargs_by_uhostname(module, uhostname, **kwargs)
        modifyhostname(module, **kwargs)

    if action == 'describe_all':
        describe_all(module, **kwargs)


if __name__ == '__main__':
    main()
