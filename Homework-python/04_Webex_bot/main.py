#!/usr/bin/env python3

import os
import sys
import base64
import json

import requests
from flask import Flask, request, abort, jsonify
from flask_cors import CORS


# LOAD CONFIGURATION
conf_path = "config"
if os.path.exists(conf_path):
  conf = json.loads(open(conf_path).read())
else:
  sys.exit(2)

# FUNCTIONALITIES:

# THREAT JAMMER -> IP ANALYSIS
threat_jammer_base_url = 'https://dublin.api.threatjammer.com'
threat_jammer_api_key = conf['threat_jammer_api_key']
threat_jammer_headers = {'Authorization': f'Bearer {threat_jammer_api_key}'}

def tj_assess_ip(ip):
    res = requests.get(f'{threat_jammer_base_url}/v1/assess/ip/{ip}', headers=threat_jammer_headers)
    data = json.loads(res.text)
    
    score = data['score']
    risk = data['risk']
    asn = data['asn']
    datacenter = data['datacenter']
    
    report = f'''
    Risk assessment for {ip}:
    - score: {score}
    - risk: {risk}
    - asn: {asn}
    - datacenter: {datacenter}
    '''
    return report


def tj_get_geo_location(ip):
    res = requests.get(f'{threat_jammer_base_url}/v1/geo/{ip}', headers=threat_jammer_headers)
    data = json.loads(res.text)
    
    city = data['city_name']
    region = data['region_name']
    country_iso = data['country_iso_code']
    asn_country_iso = data['asn_country_iso_code']

    report = f'''
    Geo-location of {ip}:
    - {city}, {region}, {country_iso}
    - ASN country ISO code: {asn_country_iso}
    '''
    return report

# WHOSI DATA
whois_base_url = 'https://api.ip2whois.com/v2'
whois_api_key = conf['ip2whois_api_key']


def whois(domain):
    url = f'{whois_base_url}?key={whois_api_key}&domain={domain}'
    res = requests.get(url)
    data = json.loads(res.text)
    
    status = data['status']
    registrar = data['registrar']['name']
    registrant_org = data['registrant']['organization']
    registrant_city = data['registrant']['city']
    nameservers = data['nameservers']

    report = f'''
    WHOIS data for {domain}:
    - status: {status}
    - registrar: {registrar}
    - registrant: {registrant_org}, {registrant_city}
    - nameservers: {nameservers}
    '''
    return report


# HASH GENERATOR
def str_to_hash(str, algorithm):
    hashable_url = 'https://hashable-server.herokuapp.com/api/hash'
    params = {'algorithm': algorithm, 'str': str}

    res = requests.get(hashable_url, params=params)
    return res.text


# RADNOM PASSWORD GENERATOR
def pass_generator(len):
  passwordinator_url = f'https://passwordinator.herokuapp.com?num=true&char=true&caps=true&len={len}'

  res = requests.get(passwordinator_url)
  data = json.loads(res.text)
  return data['data']

# Virus Total URL ANALYSIS
def url_analysis(url):
  encoded_url = base64.b64encode(url.encode()).replace(b'=', b'').decode()

  virus_total_api_key = conf['virus_total_api_key']
  virus_total_url = f'https://www.virustotal.com/api/v3/urls/{encoded_url}'
  vt_headers = {'Accept': 'application/json', 'x-apikey':virus_total_api_key}

  res = requests.get(virus_total_url, headers=vt_headers)
  data = json.loads(res.text)

  harmless = data['data']['attributes']['last_analysis_stats']['harmless']
  malicious = data['data']['attributes']['last_analysis_stats']['malicious']
  reputation = data['data']['attributes']['reputation']
  categories = data['data']['attributes']['categories']

  report = f'''
    Virus Total analysis for {url}:
    - harmless vs malicious: {harmless}:{malicious}
    - reputation: {reputation}
    - categories: {categories}
    '''
  return report


def help_menu():
  return '''
                  ####  CYBERSECURITY ASSISTANT BOT

  **Commands:**
    * **help**                              -> lists all currently available functions
    * **checkurl** *{url}*                  -> returns Virus Total report for a given url
    * **checkip**  *{ip}*                   -> returns Threat Jammer report for a given IP address
    * **geoloc**   *{ip}*                   -> returns geo-location for a given IP address
    * **whois**    *{domain}*               -> returns whois data for a given domain
    * **hash**     *{string}* *{algorithm}* -> reuturns hash of a given string; possible algorithm are: MD5, SHA256, SHA512
    * **passgen**  *{lenght}*               -> generates radnom password of specified lenght
  '''


def help_menu_after_error():
  return '''
                  #### CyberAssistant: Something went wrong, please try again.

  **Commands:**
    * **help**                              -> lists all currently available functions
    * **checkurl** *{url}*                  -> returns Virus Total report for a given url
    * **checkip**  *{ip}*                   -> returns Threat Jammer report for a given IP address
    * **geoloc**   *{ip}*                   -> returns geo-location for a given IP address
    * **whois**    *{domain}*               -> returns whois data for a given domain
    * **hash**     *{string}* *{algorithm}* -> reuturns hash of a given string; possible algorithm are: MD5, SHA256, SHA512
    * **passgen**  *{lenght}*               -> generates radnom password of specified lenght
  '''


app = Flask(__name__)

CORS(app)

header = {'content-type': 'application/json; charset=utf-8', 'authorization': 'Bearer ' + conf['bot_token']}

@app.route('/wbhk', methods = ["GET", "POST"])
def bot_reply():
  webhook = request.json
  url = 'https://webexapis.com/v1/messages'
  roomId = webhook['data']['roomId']
  msg = {'roomId':roomId}
  sender = webhook['data']['personEmail']
  message = getMessage().lower()

  if (sender != conf['bot_name']):
    if (message == 'help'):
      msg['markdown'] = help_menu()
    elif ('checkip' in message):
      try:
        ip = message.split(' ')[1].strip()
        msg['markdown'] = tj_assess_ip(ip)
      except:
        msg['markdown'] = help_menu_after_error()
    elif ('geoloc' in message):
      try:
        ip = message.split(' ')[1].strip()
        msg['markdown'] = tj_get_geo_location(ip)
      except:
        msg['markdown'] = help_menu_after_error()
    elif ('whois' in message):
      try:
        domain = message.split(' ')[1].strip()
        msg['markdown'] = whois(domain)
      except:
        msg['markdown'] = help_menu_after_error()
    elif ('hash' in message):
      try:
        string = message.split(' ')[1].strip()
        alg = string = message.split(' ')[2].strip().upper()
        msg['markdown'] = str_to_hash(string, alg)
      except:
        msg['markdown'] = help_menu_after_error()
    elif ('passgen' in message):
      try:
        lenght = message.split(' ')[1].strip()
        msg['markdown'] = pass_generator(lenght)
      except:
        msg['markdown'] = help_menu_after_error()
    elif ('checkurl' in message):
      try:
        url = message.split(' ')[1].strip()
        msg['markdown'] = url_analysis(url)
      except:
        msg['markdown'] = help_menu_after_error()
    else:
      msg['markdown'] = help_menu_after_error()

    requests.post(url, data=json.dumps(msg), headers=header, verify=True)
  return 'ok'


def getMessage():
  webhook = request.json
  wbhk_id = webhook['data']['id']
  url = f'https://webexapis.com/v1/messages/{wbhk_id}'
  get_msgs = requests.get(url, headers=header, verify=True)
  message = get_msgs.json()['text']
  return message


if __name__ == '__main__':
  app.run(host='0.0.0.0', port=5050)
  


