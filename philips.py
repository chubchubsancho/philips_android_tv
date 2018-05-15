#! /usr/bin/python

from __future__ import print_function, unicode_literals
from base64 import b64encode,b64decode
from datetime import datetime
import json
import sys
import requests
import random
import string
from Crypto.Hash import SHA, HMAC
from requests.auth import HTTPDigestAuth
import argparse

# Key used for generated the HMAC signature
secret_key="ZmVay1EQVFOaZhwQ4Kv81ypLAZNczV9sG4KkseXWn1NEk6cXmPKO/MCa9sryslvLCFMnNe4Z4CPXzToowvhHvA=="

# Turn off ssl warnings
requests.packages.urllib3.disable_warnings()


def createDeviceId():
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(16))


def create_signature(secret_key, to_sign):
    sign = HMAC.new(secret_key, to_sign, SHA)
    return str(b64encode(sign.hexdigest().encode()))

def getDeviceSpecJson(config):
    device_spec =  { "device_name" : "heliotrope", "device_os" : "Android", "app_name" : "ApplicationName", "type" : "native" }
    device_spec['app_id'] = config['application_id']
    device_spec['id'] = config['device_id']
    return device_spec


def pair(config):
    config['application_id'] = "app.id"
    config['device_id'] = createDeviceId()
    data = { 'scope' :  [ "read", "write", "control"] }
    data['device']  = getDeviceSpecJson(config)
    print("Starting pairing request")
    r = requests.post("https://" + config['address'] + ":1926/5/pair/request", json=data, verify=False)
    response = r.json()
    auth_Timestamp = response["timestamp"]
    config['auth_key'] = response["auth_key"]
    auth_Timeout = response["timeout"]

    pin = input("Enter onscreen passcode: ")

    auth = { "auth_AppId" : "1" }
    auth ['pin'] = str(pin)
    auth['auth_timestamp'] = auth_Timestamp
    auth['auth_signature'] = create_signature(b64decode(secret_key), str(auth_Timestamp).encode() + str(pin).encode())

    grant_request = {}
    grant_request['auth'] = auth
    grant_request['device']  = getDeviceSpecJson(config)

    print("Attempting to pair")
    r = requests.post("https://" + config['address'] +":1926/5/pair/grant", json=grant_request, verify=False,auth=HTTPDigestAuth(config['device_id'], config['auth_key']))
    print(r.json())
    print("Username for subsequent calls is: " + config['device_id'])
    print("Password for subsequent calls is: " + config['auth_key'])

def get_command(config):
    r = requests.get("https://" + config['address'] + ":1926/" + config['path'], verify=False,auth=HTTPDigestAuth(config['device_id'], config['auth_key']))
    print(r)
    print(r.url)
    print(r.text)
    print(r.json())


def post_command(config):
    r = requests.post("https://" + config['address'] + ":1926/" + config['path'], json=config['body'], verify=False,auth=HTTPDigestAuth(config['device_id'], config['auth_key']))
    print(r)


def main():
    config={}
    parser = argparse.ArgumentParser(add_help = False, description='Control a Philips Android TV.')
    parser.add_argument("--host", dest='host', help="Host/address of the TV")
    parser.add_argument("-u", "--user", dest='user', help="Username")
    parser.add_argument("-p", "--pass", dest='password', help="Password")
    parser.add_argument("command",  help="Command to run (post/get)")

    args = parser.parse_args()

    config['address'] = args.host
 
    if args.command == "pair":
        pair(config)

    config['device_id'] = args.user
    config['auth_key'] = args.password

    if args.command == "get_channel":
        config['path'] = "5/channeldb/tv"
        get_command(config)

    if args.command == "get_applications":
        config['path'] = "5/applications"
        get_command(config)

    if args.command == "get_volume":
        config['path'] = "5/audio/volume"
        get_command(config)

    if args.command == "get_powerstate":
        config['path'] = "5/powerstate"
        get_command(config)

    if args.command == "get_ambilight_topology":
        config['path'] = "5/ambilight/topology"
        get_command(config)

    if args.command == "get_ambilight_mode":
        config['path'] = "5/ambilight/mode"
        get_command(config)

    if args.command == "get_ambilight_measured":
        config['path'] = "5/ambilight/measured"
        get_command(config)

    if args.command == "get_ambilight_processed":
        config['path'] = "5/ambilight/processed"
        get_command(config)

    if args.command == "get_ambilight_cached":
        config['path'] = "5/ambilight/cached"
        get_command(config)

    if args.command == "get_audio":
        config['path'] = "5/audio/volume"
        get_command(config)

    if args.command == "get":
        # All working commands
                 
        config['path'] = "5/recordings/list"
        config['path'] = "5/ambilight/currentconfiguration"
        config['path'] = "5/channeldb/tv/channelLists/all"
        config['path'] = "5/system/epgsource"
        config['path'] = "5/system"
        config['path'] = "5/system/storage"
        config['path'] = "5/system/timestamp"
        config['path'] = "5/menuitems/settings/structure"
      
        get_command(config)

    if args.command == "standby":
        config['path'] = "5/input/key"
        config['body'] = { "key" : "Standby" }
        post_command(config)

    if args.command == "online":
        config['path'] = "5/imput/key"
        config['body'] = { "key" : "Online" }
        post_command(config)
  
    if args.command == "volumeup":
        config['path'] = "5/input/key"
        config['body'] = { "key" : "VolumeUp" }
        post_command(config)


    if args.command == "mute":
        config['path'] = "5/input/key"
        config['body'] = { "key" : "Mute" }
        post_command(config)
    
main()




