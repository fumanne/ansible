#! /usr/local/bin/python
# -*- coding: utf-8 -*-


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_udisk

short_description: create, delete, detach, attach, describe ucloud udisk

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
  - any action of uhost, if parameter is surplus, do not care and handle it. make sure the required parameter of specical action


options:
  action:
    description:
      - the action of uhost (create, attach, detach, delete, describe)
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

  projectid:
    description:
      - the project id
    default: null    
 
 
  name:
    description:
      - the name of udisk
    
  size:
    description:
      - "size of udisk, unit: GB"
    type: int
    
  chargetype:
    description:
      - type of udisk
    choice: [Year, Month, Dynamic, Trial]
    
  quantity:
    description:
      - time of purchase, default is 1
    default: 1
    
  udataArkmode:
    description:
      - wheather to enable store

  tag:
    description:
      - the business of name
    default: null

  disktype:
    description:
      - the kind of udisk
    choice: [DataDisk, SSDDataDisk]
    default: SSDDataDisk
    
  couponid:
    description:
      - the ticket id
    default: null
    
  uhostid:
    description:
      - id of resource,
 
  uhostname:
    description:
      - uhostname, apply in uhost
      
  udiskid:
    description:
      - id if udisk for attach, delete, deatch, describe action
  
  udiskname:
    description:
      - name of udisk, it is generate by create action 
    
'''

EXAMPLES = '''

- name: create udisk
  ucloud_udisk:
    action: create
    public_key:                                 # required
    private_key:                                # required
    region:                                     # required
    zone:                                       # required
    name:  your udisk name
    size: 500
    chargetype: Month
    disktype: SSDDataDisk
    projectid: 
    tag:

- name: attach udisk by uhostid
  ucloud_udisk:
    action: attach
    public_key:
    private_key:
    region:
    zone: 
    uhostid:
    udiskname:
    

- name: attach udisk by uhostname
  ucloud_udisk:
    action: attach
    public_key:
    private_key:
    region:
    zone: 
    uhostname:
    udiskname:
    
    
- name: detach udisk by uhostname
  ucloud_udisk:
    action: detach
    public_key:
    private_key:
    region:
    zone: 
    uhostname:
    udiskname:
 
- name: describe udisk by udiskname
  ucloud_udisk:
    action: describe
    public_key:
    private_key:
    udiskname:
    region:
    zone:
    disktype:
    projectid: 
'''


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, ZONE, CORE_PARAMS, CREATEUDISK_PARAMS, ATTACHUDISK_PARAMS, \
    DETACHUDISK_PARAMS, DELETEUDISK_PARAMS, DESCRIBEUDISK_PARAMS


def create(module, **kwargs):
    ur = UhttpRequests("CreateUDisk", **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def attach(module, **kwargs):
    ur = UhttpRequests("AttachUDisk", **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def detach(module, **kwargs):
    ur = UhttpRequests("DetachUDisk", **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def describe(module, **kwargs):
    ur = UhttpRequests('DescribeUDisk', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def delete(module, **kwargs):
    ur = UhttpRequests('DeleteUDisk', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        module.exit_json(**resp)
    else:
        module.fail_json(msg=resp)


def is_create_udisk_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATEUDISK_PARAMS + CORE_PARAMS else False


def is_attach_udisk_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in ATTACHUDISK_PARAMS + CORE_PARAMS else False


def is_detach_udisk_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DETACHUDISK_PARAMS + CORE_PARAMS else False


def is_describe_udisk_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEUDISK_PARAMS + CORE_PARAMS else False


def is_delete_udisk_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DELETEUDISK_PARAMS + CORE_PARAMS else False


def _list_udisks(module, **kwargs):
    ur = UhttpRequests('DescribeUDisk', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['DataSet'] if 'DataSet' in resp else None
    else:
        module.fail_json(msg=resp)


def _list_uhosts(module, **kwargs):
    ur = UhttpRequests('DescribeUHostInstance', **kwargs)
    resp = ur.urequest('GET')
    if resp['RetCode'] == 0:
        return resp['UHostSet'] if 'UHostSet' in resp else None
    else:
        module.fail_json(msg=resp)


def find_udisk_info_by_name(module, name, result):
    match_udisk = list(filter(lambda x: x['Name'] == name, result))
    if len(match_udisk) > 1:
        module.fail_json(msg="Udisk Named {0} is more than 1".format(name))
    else:
        return match_udisk[0]


def find_udiskid_by_name(module, name, result, flag='UDiskId'):
    eip_info = find_udisk_info_by_name(module, name, result)
    return eip_info[flag]


def find_uhostid_by_uhostname(module, name, result):
    if name in [i['Name'] for i in result]:
        uhost_info = list(filter(lambda x: x['Name'] == name, result))
        if len(uhost_info) > 1:
            module.fail_json(msg="UHost Named {0} is more than 1".format(name))
        else:
            return uhost_info[0]['UHostId']
    else:
        module.fail_json(msg='Can not Found UHost Named {0} in Host list'.format(name))


def update_kwargs_by_name(module, name, **kwargs):
    describe_udisk_params = dict(
        Region=kwargs['Region'],
        ProjectId=kwargs['ProjectId'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey'],
        Limit=kwargs['Limit']
    )
    udisks = _list_udisks(module, **describe_udisk_params)
    if udisks and name in [i['Name'] for i in udisks]:
        udiskid = find_udiskid_by_name(module, name, udisks)
        kwargs['UDiskId'] = udiskid
    else:
        module.fail_json(msg='Can not Found Udisk Named {0} in list'.format(name))

    return kwargs


def main():
    module_args = dict(
        action=dict(type='str', required=True, choice=['create', 'delete', 'attach', 'detach', 'describe']),
        projectid=dict(type='str', default='org-a41n54'),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region=dict(type='str', required=True, choice=REGION),
        zone=dict(type='str', choice=ZONE),
        tag=dict(type='str'),
        name=dict(type='str'),
        size=dict(type='int'),
        chargetype=dict(type='str', choice=['Year', 'Month', 'Dynamic', 'Trial']),
        quantity=dict(type='str', default=1),
        disktype=dict(type='str', choice=['DataDisk', 'SSDDataDisk']),
        couponid=dict(type='str'),
        uhostid=dict(type='str'),
        uhostname=dict(type='str'),
        udataArkmode=dict(type='str'),
        udiskid=dict(type='str'),
        udiskname=dict(type='str')
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
    tag = module.params.get('tag')
    name = module.params.get('name')
    size = module.params.get('size')
    chargetype = module.params.get('chargetype')
    quantity = module.params.get('quantity')
    disktype = module.params.get('disktype')
    couponid = module.params.get('couponid')
    uhostid = module.params.get('uhostid')
    uhostname = module.params.get('uhostname')
    udataArkmode = module.params.get('udataArkmode')
    udiskid = module.params.get('udiskid')
    udiskname = module.params.get('udiskname')
    projectid = module.params.get('projectid')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        Zone=zone,
        Tag=tag,
        Name=name,
        Size=size,
        ChargeType=chargetype,
        Quantity=quantity,
        UDataArkMode=udataArkmode,
        DiskType=disktype,
        ConponId=couponid,
        ProjectId=projectid,
        UDiskId=udiskid,
        UHostId=uhostid,
        Limit=1000
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == "create":
        kwargs = dict(filter(is_create_udisk_params, kwargs.items()))

        # 检测udisk name是否同名
        describe_udisk_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )

        udisks = _list_udisks(module, **describe_udisk_params)
        if udisks and kwargs['Name'] in [i['Name'] for i in udisks]:
            module.warn("Udisk Named {0} is already exists!".format(kwargs['Name']))
            udisk_info = find_udisk_info_by_name(module, kwargs['Name'], udisks)
            module.exit_json(**udisk_info)

        create(module, **kwargs)

    if action == "attach":
        kwargs = dict(filter(is_attach_udisk_params, kwargs.items()))

        describe_udisk_params = dict(
            Region=kwargs['Region'],
            ProjectId=kwargs['ProjectId'],
            PublicKey=kwargs['PublicKey'],
            PrivateKey=kwargs['PrivateKey'],
            Limit=kwargs['Limit']
        )

        udisks = _list_udisks(module, **describe_udisk_params)
        if not udisks:
            module.fail_json(msg='There is no Udisk')

        # 指定udiskname, 获取该udiskid
        if udiskname and not udiskid:
            udiskid = find_udiskid_by_name(module, udiskname, udisks)
            kwargs['UDiskId'] = udiskid

        udisk_info = list(filter(lambda x: x['UDiskId'] == kwargs['UDiskId'], udisks))[0]

        # 指定uhostname, 获取该uhostid
        if uhostname and not uhostid:
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
            kwargs['UHostId'] = uhostid

        # 获取到udiskid 和 uhostud 后, 判断是否对应的udiskid 的info 里已经attach 了 uhostid
        if 'UHostId' in udisk_info and kwargs['UHostId'] == udisk_info['UHostId']:
            module.warn("Udisk {0} has already bind to Uhost {1}".format(kwargs['UDiskId'], kwargs['UHostId']))
            module.exit_json(**udisk_info)

        attach(module, **kwargs)

    if action == "detach":
        kwargs = dict(filter(is_detach_udisk_params, kwargs.items()))

        # 指定udiskname, 获取udiskid
        if udiskname and not udiskid:
            kwargs = update_kwargs_by_name(module, udiskname, **kwargs)

        # 指定uhostname, 获取uhostid
        if uhostname and not uhostid:
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
            kwargs['UHostId'] = uhostid

        detach(module, **kwargs)

    if action == "describe":
        kwargs = dict(filter(is_describe_udisk_params, kwargs.items()))

        if udiskname and not udiskid:
            udisks = _list_udisks(module, **kwargs)
            if udisks and udiskname in [i['Name'] for i in udisks]:
                udisk_info = find_udisk_info_by_name(module, udiskname, udisks)
                module.exit_json(**udisk_info)
            else:
                module.fail_json(msg="Can not Found Udisk Named {0}".format(udiskname))

        describe(module, **kwargs)

    if action == 'delete':
        kwargs = dict(filter(is_delete_udisk_params, kwargs.items()))
        if udiskname and not udiskid:
            kwargs = update_kwargs_by_name(module, udiskname, **kwargs)
        delete(module, **kwargs)


if __name__ == '__main__':
    main()
