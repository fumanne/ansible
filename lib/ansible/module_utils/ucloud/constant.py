#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

REGION = [ 'cn-bj1',
           'cn-bj2',
           'cn-zj',
           'cn-sh1',
           'cn-sh2',
           'cn-gd',
           'hk',
           'us-ca',
           'us-ws',
           'ge-fra',
           'th-bkk',
           'kr-seoul',
           'sg',
           'tw-kh']

ZONE = [ 'cn-bj1-01',
         'cn-bj2-02',
         'cn-bj2-03',
         'cn-bj2-04',
         'cn-zj-01',
         'cn-sh1-01',
         'cn-sh2-01',
         'cn-sh2-02',
         'cn-gd-02',
         'hk-01',
         'us-ca-01',
         'us-ws-01',
         'ge-fra-01',
         'th-bkk-01',
         'kr-seoul-01',
         'sg-01',
         'tw-kh-01']

UCLOUD_HTTP = "http://api.ucloud.cn"
UCLOUD_HTTPS = "https://api.ucloud.cn"

CORE_PARAMS = ('PublicKey', 'PrivateKey')

STARTUHOST_PARAMS = STOPUHOST_PARAMS = REBOOTUHOST_PARAMS  = CREATUHOSTSNAP_PARAMS = ('Region', 'Zone', 'UHostId', 'ProjectId', 'Limit')
TERMINATEUHOST_PARAMS = ('Region', 'Zone', 'UHostId', 'ProjectId', 'Destroy', 'Limit')
DESCRIBEUHOST_PARAMS = ('Region', 'Zone', 'Tag', 'ProjectId', 'Limit') # UHostIds is not list here
RESETPASSWORD_PARAMS = ('Region', 'Zone', 'UHostId', 'Password', 'ProjectId', 'Limit')
MODIFYUHOST_PARAMS = ('Region', 'Zone', 'UHostId', 'ProjectId', 'Name', 'Limit')

DESCRIBEIMAGE_PARAMS = ('Region', 'Zone', 'ImageType', 'OsType', 'ImageId', 'ProjectId', 'Limit')
CREATEIMAGE_PARAMS = ('Region', 'Zone', 'UHostId', 'ImageName', 'ImageDescription', 'ProjectId', 'Limit')
TERMINATEIMAGE_PARAMS = ('Region', 'Zone', 'ImageId', 'ProjectId', 'Limit')

CREATEVPC_PARAMS = ('Region', 'ProjectId', 'Name', 'Tag', 'Remark', 'BusinessId', 'Limit')  # Network.N is not list in here
DESCRIBEVPC_PARAMS = ('ProjectId', 'Region', 'Tag', 'BusinessId', 'Limit')   # VPCId.N is not list in here
DELETEVPC_PARAMS = ('Region', 'ProjectId', 'VPCId', 'Limit')
ADDNETWORKVPC_PARAMS = ('Region', 'VPCId', 'ProjectId', 'Limit') # Network.N is not list in here

CREATESUBNET_PARAMS = ('Region', 'ProjectId', 'VPCId', 'Subnet', 'Netmask', 'SubnetName', 'Tag', 'Remark', 'BusinessId', 'Limit')
DESCRIBESUBNET_PARAMS = ('Region', 'ProjectId', 'SubnetId', 'VPCId', 'Tag', 'BusinessId', 'Limit')
UPDATESUBNET_PARAMS = ('Region', 'ProjectId', 'SubnetId', 'SubnetName', 'Tag', 'Limit')
DELETESUBNET_PARAMS = ('Region', 'ProjectId', 'SubnetId', 'Limit')

CREATEFIREWALL_PARAMS = ('Region', 'ProjectId', 'Name', 'Tag', 'Remark', 'Limit') # rule.N is not list here
DESCRIBEFIREWALL_PARAMS = DELETEFIREWALL_PARAMS = ('Region', 'ProjectId', 'FWId', 'Limit')
UPDATEFIREWALL_PARAMS = DESCRIBERESOURCEFIREALL_PARAMS = ('Region', 'FWId', 'ProjectId', 'Limit') # rule.N is not list here
GRANTFIREWALL_PARAMS = ('Region', 'FWId', 'ResourceType', 'ResourceId', 'ProjectId', 'Limit')

ALLOCATEEIP_PARAMS = ("Region", 'OperatorName', 'Bandwidth', 'Tag', 'ChargeType', 'Quantity', 'PayMode',
                      'ShareBandwidthId', 'CouponId', 'Name', 'ProjectId', 'Limit')
BINDEIP_PARAMS = UNBINDEIP_PARAMS = ('Region', 'EIPId', 'ResourceType', 'ResourceId', 'ProjectId', 'Limit')
DESCRIBEEIP_PARAMS = ('Region', 'ProjectId', 'Limit')
UPDATEEIP_PARAMS = ('Region', 'EIPId', 'Name', 'Tag', 'ProjectId', 'Limit')
RELEASEEIP_PARAMS = ('Region', 'EIPId', 'ProjectId', 'Limit')
MODIDYEIP_PARAMS = ('Region', 'EIPId', 'Bandwidth', 'ProjectId', 'Limit')

CREATENAT_PARAMS = ('Region', 'NATGWName', 'FirewallId', 'VPCId', 'ifOpenf', 'Tag', 'ProjectId', 'Limit') # SubnetworkIds, EIPIds is not list here
DELETENAT_PARAMS = ('Region', 'NATGWId', 'ProjectId', 'Limit')
UPDATENAT_PARAMS = ('Region', 'NATGWId', 'NATGWName', 'Tag', 'ProjectId', 'Limit')
DESCRIBENAT_PARAMS = ('Region', 'ProjectId', 'Limit') # NATGWIds is not list here

DESCRIBEPHOST_PARAMS = ('Region', 'ProjectId', 'Zone', 'Limit') # PHostIds is not list here
STARTPHOST_PARAMS = REBOOTPHOST_PARAMS = TERMINATEPHOST_PARAMS = POWEROFFPHOST_PARAMS = ('Region', 'ProjectId', 'Zone', 'PHostId')

CREATEUDISK_PARAMS = ('Region', 'ProjectId', 'Zone', 'Size', 'Name', 'Limit', 'ChargeType', 'Quantity', 'DiskType', 'ConponId', 'Tag')
ATTACHUDISK_PARAMS = DETACHUDISK_PARAMS = ('Region', 'Zone', 'ProjectId', 'UHostId', 'UDiskId', 'Limit')
DELETEUDISK_PARAMS = ('Region', 'Zone', 'ProjectId', 'Limit')
DESCRIBEUDISK_PARAMS = ('Region', 'Zone', 'ProjectId', 'DiskType', 'Limit')