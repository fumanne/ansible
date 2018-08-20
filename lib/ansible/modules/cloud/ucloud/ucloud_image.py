#! /usr/bin/env python
#! -*- encoding: utf-8 -*-


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
---
module: ucloud_image

short_description: describe, create, terminate ucloud image

version_added: "0.1"

description:
  - private key and public key must be assigned in yml for every task
  - any action of image, describe all image of uhost, and operation of custom image
  
options:
  action: 
    description:
      - the action of image, create, describe. delete
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
     
  zone:
    description:
      -  the zone of ucloud, see "https://docs.ucloud.cn/api/summary/regionlist.html"
    required: false
    default: cn-sh2-02
    
  imagetype:
    description:
      - type of image, base, business, custom
    required: false
    
  ostype:
    description:
      - os type, Linux or Windows
    required: false
    
  imageid:
    description:
      - can list special image you like
    required: false
    
  projectid:
    description:
      - the project id
    required: false
  
  uhostid:
    description:
      - when action is create  it requried.
    
  imagename:
    description:
      - when action is create it requried.

  imagedescription:
    description:
      - detail info of image 
       
notes:
  - "https://docs.ucloud.cn/api/uhost-api/index"
author:
  - fu-l@klab.com
'''

EXAMPLES = """
# describe all images
- name: describe all images
  ucloud_image:
    action: describe
    public_key:
    private_key:
    region: cn-sh2                              # required
    zone: cn-sh2-02
  
  
# create custom image
- name: create image
  ucloud_image:
    action: create
    public_key:                                 
    private_key:                                
    region: cn-sh2                              # required
    uhostid: uhost-xxxx                         # required
    imagename: image-xxxx                       # required    
    
# terminate custom image
- name: terminate image
  ucloud_image:
    action: terminate
    public_key:
    private_key:
    region: cn-sh2                              # requried
    zone: cn-sh2-01    
    imageid: iamge-xxxx                         # requried
"""

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.ucloud.uhttp import UhttpRequests
from ansible.module_utils.ucloud.constant import REGION, ZONE, CORE_PARAMS, DESCRIBEIMAGE_PARAMS, CREATEIMAGE_PARAMS, \
                                            TERMINATEIMAGE_PARAMS

def describe(module, **kwargs):
    ui = UhttpRequests('DescribeImage', **kwargs)
    resp = ui.urequest('GET')
    if resp['RetCode'] == 0:
        return module.exit_json(**resp)
    else:
        return module.fail_json(msg=resp)


def create(module, **kwargs):
    desc_params = dict(
        Region=kwargs['Region'],
        PublicKey=kwargs['PublicKey'],
        PrivateKey=kwargs['PrivateKey']
    )
    images = _list_images_with_create(module, **desc_params)
    if 'ImageName' in kwargs and kwargs['ImageName'] in [i['ImageName'] for i in images]:
        module.warn("Image Named {0} is already exists!".format(kwargs['ImageName']))
        match_image = list(filter(lambda x: x['ImageName'] == kwargs['ImageName'], images))
        # Todo, 当匹配到多个item时, 将其报错
        if len(match_image) != 1:
            module.fail_json(msg="ImageName Named {0} have {1} items".format(kwargs['ImageName'], len(match_image)))
        else:
            image_info = match_image[0]
            module.exit_json(**image_info)

    ui = UhttpRequests('CreateCustomImage', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return module.exit_json(**resp)
    else:
        return module.fail_json(msg=resp)


def terminate(module, **kwargs):
    ui = UhttpRequests('TerminateCustomImage', **kwargs)
    resp = ui.urequest("GET")
    if resp['RetCode'] == 0:
        return module.exit_json(**resp)
    else:
        return module.fail_json(msg=resp)


def _list_images_with_create(module, **kwargs):
    ur = UhttpRequests('DescribeImage', **kwargs)
    resp = ur.urequest("GET")
    if resp['RetCode'] == 0:
        return resp['ImageSet']
    else:
        module.fail_json(msg=resp)


def is_create_image_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in CREATEIMAGE_PARAMS + CORE_PARAMS else False


def is_describe_image_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in DESCRIBEIMAGE_PARAMS + CORE_PARAMS else False


def is_terminate_image_params(item):
    if not isinstance(item, tuple):
        return False
    return True if item[0] in TERMINATEIMAGE_PARAMS + CORE_PARAMS else False


def main():

    module_args = dict(
        action = dict(type='str', required=True, choice=['describe', 'create', 'terminate']),
        public_key=dict(type='str', required=True),
        private_key=dict(type='str', required=True),
        region = dict(type='str', required=True, choice=REGION),
        zone = dict(type='str', choice=ZONE),
        imagetype = dict(type='str'),
        ostype = dict(type='str'),
        imageid = dict(type='str'),
        projectid = dict(type='str'),
        uhostid = dict(type='str'),
        imagename = dict(type='str'),
        imagedescription = dict(type='str')
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
    imagetype = module.params.get('imagetype')
    ostype = module.params.get('ostype')
    imageid = module.params.get('imageid')
    projectid = module.params.get('projectid')
    uhostid = module.params.get('uhostid')
    imagename = module.params.get('imagename')
    imagedescription = module.params.get('imagedescription')

    kwargs = dict(
        Region=region,
        PublicKey=public_key,
        PrivateKey=private_key,
        Zone=zone,
        ImageType=imagetype,
        OsType=ostype,
        ImageId=imageid,
        ProjectId=projectid,
        UHostId=uhostid,
        ImageName=imagename,
        ImageDescription=imagedescription
    )

    kwargs = dict(filter(lambda x: x[1] is not None, kwargs.items()))

    if action == 'describe':
        kwargs = dict(filter(is_describe_image_params, kwargs.items()))
        describe(module, **kwargs)

    if action == 'create':
        kwargs = dict(filter(is_create_image_params, kwargs.items()))
        create(module, **kwargs)

    if action == 'terminate':
        kwargs = dict(filter(is_terminate_image_params, kwargs.items()))
        terminate(module, **kwargs)


if __name__ == '__main__':
    main()
