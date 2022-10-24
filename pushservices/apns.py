#!/usr/bin/python
# -*- coding: utf-8 -*-

from . import PushService
from util import json_encode
import logging
import hyper
import jwt
import time

#  BASE_URL_DEV = "api.development.push.apple.com:443"
BASE_URL_PROD = "api.push.apple.com:443"
ALGORITHM = "ES256"


class ApnsException(Exception):
    def __init__(self, response_statuscode, error):
        self.response_statuscode = response_statuscode
        self.error = error


class ApnsClient(PushService):
    def __str__(self):
        return " APNsClient %s: %s" % (self.appname, self.instanceid)

    def __init__(self, **kwargs):
        self.auth_key = kwargs["auth_key"]
        self.bundle_id = kwargs["bundle_id"]
        self.key_id = kwargs["key_id"]
        self.team_id = kwargs["team_id"]
        self.appname = kwargs["appname"]
        self.instanceid = kwargs["instanceid"]
        self.last_token_refresh = 0
        self.token = None
        self.http2 = None
        self.last_active = time.perf_counter()
        #  self.http2dev = hyper.HTTPConnection(BASE_URL_DEV)

    def create_token(self):
        now = time.time()
        countdown = now - self.last_token_refresh
        if countdown > 60 * (60 - 10):
            jwt_payload = {"iss": self.team_id, "iat": time.time()}
            token = jwt.encode(
                jwt_payload,
                self.auth_key,
                algorithm=ALGORITHM,
                headers={"alg": ALGORITHM, "kid": self.key_id},
            )
            self.last_token_refresh = now
            self.token = token.decode("ascii")
        return self.token

    def build_headers(self, push_type="alert"):

        token = self.create_token()

        return {
            "apns-expiration": "0",
            "apns-priority": "10",
            "apns-push-type": push_type,  # alert or background
            "apns-topic": self.bundle_id,
            "mutable-content": "1",
            "authorization": "bearer {0}".format(token),
        }

    def process(self, **kwargs):
        alert = kwargs.get("alert", None)
        apns = kwargs.get("apns", {})
        msg = kwargs.get("msg", "")
        token = kwargs["token"]

        if alert is not None and not isinstance(alert, dict):
            alert = {"body": alert, "title": alert}

        filtered_apns = {
            k: v
            for (k, v) in apns.items()
            if k
            in [
                "thread-id",
                "category",
                "content-available",
                "sound",
                "badge",
                "alert",
            ]
        }
        # data structure:
        # https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/PayloadKeyReference.html#//apple_ref/doc/uid/TP40008194-CH17-SW1
        if len(msg) > 0:
            self.payload = msg
        else:
            payload_data = {"aps": {"alert": alert, **filtered_apns}}
            self.payload = json_encode(payload_data)

        PATH = "/3/device/{0}".format(token)
        self.headers = self.build_headers(push_type=apns["push_type"])

        try_count = 1
        while try_count <= 3:
            try:
                if (self.http2 == None) or (time.perf_counter() - self.last_active > 420):
                    logging.info('Connecting to APNS server: ' + BASE_URL_PROD)
                    self.http2 = hyper.HTTPConnection(BASE_URL_PROD)
                self.http2.request("POST", PATH, self.payload, headers=self.headers)
                resp = self.http2.get_response()
            except Exception as e:
                logging.error(repr(e))
                self.http2 = None
                try_count += 1
                continue
            self.last_active = time.perf_counter()
            if resp.status >= 400:
                #  headers = resp.headers
                #  for k, v in headers.items():
                #      logging.error("%s: %s" % (k.decode("utf-8"), v.decode("utf-8")))
                body = resp.read().decode("utf-8")
                logging.error(body)
                raise ApnsException(400, body)
            else:
                break
        if try_count > 3:
            raise ApnsException(400, '{"reason":"Can not connect to apns server."}')
