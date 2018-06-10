# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

# Copyright (c) 2018 by Paul Dagnelie.

import datetime
import base64
import hmac
import hashlib
import urllib
import config

def siggy_sign(verb, path, timestamp = datetime.datetime.now(), content_type = "", content_hash = ""):
    message = verb + "\n" + path + "\n" + timestamp.isoformat() + "\n" + content_type + "\n" + content_hash
    hm = hmac.new(config.SIGGY_SECRET, msg=bytes(message, 'utf-8'), digestmod=hashlib.sha256).digest()
    return base64.standard_b64encode(hm).decode('utf-8')

def siggy_request(verb, path, data = None, timestamp = datetime.datetime.now(), content_type = "", content_hash = ""):
    signature = siggy_sign(verb, path, timestamp, content_type, content_hash)
    req = urllib.request.Request(
        "https://siggy.borkedlabs.com/api" + path,
        data=data,
        headers =
        {
            'User-Agent': 'RouteFinder v0.1b',
            'Authorization': 'siggy-HMAC-SHA256 Credential=' + config.SIGGY_KEYID + ":" + signature
        }
    )
    return urllib.request.urlopen(req).read().decode('utf-8')

def get_chain(chainmap_id):
    return siggy_request("GET", "/v1/chainmaps/" + str(chainmap_id))

def get_chainmaps():
    return siggy_request("GET", "/v1/chainmaps")
