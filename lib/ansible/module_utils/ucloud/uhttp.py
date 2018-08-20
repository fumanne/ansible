#! /usr/bin/env python
#! -*- encoding: utf-8 -*-

import os
import copy
import hashlib
import requests
#from six.moves import configparser
from ansible.module_utils.ucloud.exceptions import NotFoundRegion, NotFoundZone
from ansible.module_utils.ucloud.constant import REGION, ZONE, UCLOUD_HTTP, UCLOUD_HTTPS


class CommonParameter(object):
    def __init__(self, public_key):
        self.PublicKey = public_key

    def __repr__(self):
        return self.__class__.__name__

    def __call__(self, *args, **kwargs):
        return self.__class__.__name__


class ActionParameter(CommonParameter):
    def __init__(self, action_name, public_key, private_key, **kwargs):
        super(ActionParameter, self).__init__(public_key)
        self.Action = action_name
        self.parameter = copy.deepcopy(self.__dict__)
        self.parameter.update(kwargs)

        self.parameter['Signature'] = self._gen_signature(private_key)

        if 'Region' in self.parameter and self.parameter['Region'] not in REGION:
            raise NotFoundRegion()
        if 'Zone' in self.parameter and self.parameter['Zone'] not in ZONE:
            raise NotFoundZone()

    def __repr__(self):
        return '{}-<{}>'.format(self.__class__.__name__, self.Action)

    def __call__(self, *args, **kwargs):
        return 'Object-{0}'.format(self.Action)


    def _gen_signature(self, private_key):
        items = list(self.parameter.items())
        items.sort()

        params_data = ""
        for k, v in items:
            params_data = params_data + str(k) + str(v)
        params_data = params_data + private_key
        sign = hashlib.sha1()
        sign.update(params_data.encode(encoding="utf-8"))
        return sign.hexdigest()


class UhttpRequests(object):

    def __init__(self, action, with_https=False, **kwargs):
        if with_https:
            self.url = UCLOUD_HTTPS
        else:
            self.url = UCLOUD_HTTP

        pub_key = kwargs.pop('PublicKey')
        pri_key = kwargs.pop('PrivateKey')
        p = ActionParameter(action, pub_key, pri_key, **kwargs)
        self.params = p.parameter


    def urequest(self, method, retry=5):
        resp = requests.request(method, self.url, params=self.params)
        data = resp.json()
        if data['RetCode'] != 0 and retry > 0:
            return self.urequest(method, retry=retry-1)

        else:
            return data

    # def _fetch_keys(self):
    #     _location = os.path.join(os.environ.get('HOME'), '.ucloud.ini')
    #     if not os.path.isfile(_location):
    #         raise FileExistsError('{} is not exists'.format(_location))
    #     _conf = configparser.ConfigParser()
    #     _conf.read(_location)
    #     return _conf.get('ucloud', 'public_key'), _conf.get('ucloud', 'private_key')
