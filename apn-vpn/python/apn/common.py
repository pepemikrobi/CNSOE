# -*- mode: python; python-indent: 4 -*-
# coding=UTF-8
import requests
import json
from datetime import datetime

import _ncs
import ncs.maapi as maapi
import ncs.maagic as maagic

ncs_service_operation = {
   0 : "NCS_SERVICE_CREATE",
   1 : "NCS_SERVICE_UPDATE",
   2 : "NCS_SERVICE_DELETE"
}

omf = {
    "host" : "1.1.1.1",
    "port" : "8081",
    "username" : "admin",
    "password" : "cisco"
}

template_list = {
    "template-asa-pool-routing" :               "[XML-ASA-CPE-FW-POOL-ROUTE--]", 
    "template-asa" :                            "[XML-ASA-CPE-FW-------------]",  
    "template-ext-router-cpe-firewall" :        "[XML-1K-EXT-RT-CPE-FW-------]",  
    "template-ext-router-nat-acl" :             "[XML-1K-EXT-RT-NACL---------]",       
    "template-ext-router-pool" :                "[XML-1K-EXT-RT-POOL---------]",      
    "template-ext-router" :                     "[XML-1K-EXT-RT--------------]",  
    "template-packet-node-apn-context" :        "[XML-5K-APN-----------------]",  
    "template-packet-node-gi-context-pool" :    "[XML-5K-GI-POOL-------------]",
    "template-packet-node-gi-context" :         "[XML-5K-GI------------------]"    
}


def template_descr(template_name):
    return template_list[template_name]

def log_service(self, tctx, op, kp, root):
    self.log.debug('addr: ', tctx.uinfo.addr)
    self.log.debug('lmode: ', tctx.uinfo.lmode)
    self.log.debug('logintime: ', tctx.uinfo.logintime)
    self.log.debug('port: ', tctx.uinfo.port)
    self.log.debug('proto: ', tctx.uinfo.proto)
    self.log.debug('username: ', tctx.uinfo.username)
    self.log.debug('usid ', tctx.uinfo.usid)
    self.log.debug('Operation ', ncs_service_operation[op])

    # get OM endpoint and credentials
    omf['host'] = maagic.cd(root, '/APN:APN/APN:OMF/APN:host')
    omf['port'] = maagic.cd(root, '/APN:APN/APN:OMF/APN:port')
    omf['username'] = maagic.cd(root, '/APN:APN/APN:OMF/APN:username')
    omf['password'] = _ncs.decrypt(maagic.cd(root, '/APN:APN/APN:OMF/APN:password'))
    self.log.debug('OMF config retrieved: hostname(', omf['host'], '), port (', omf['port'], ')')
    #self.log.debug('OMF API credentials retrieved: username(', omf['username'], '), password (', omf['password'], ')')      

    # skip audit for special user
    if (tctx.uinfo.username == 'ncsnoaudit'):
        self.log.info('Accessed by ', tctx.uinfo.username, ' user, so audit data skipped')
        return

    # get current service definition
    operation = ncs_service_operation[op]
    service_definition = ''

    if operation != 'NCS_SERVICE_DELETE':
        service_definition = maagic.as_pyval(maagic.cd(root, kp), include_oper=True, name_type=maagic.NODE_NAME_SHORT)
        if 'private' in service_definition:
            del service_definition['private']
        if 'log' in service_definition:
            del service_definition['log']


    audit_data = {
        "orderType": "NSO_UPDATE_SERVICE",
        "parameters": {
            "SERVICE_PATH": str(kp),
            "EXT_USERNAME": tctx.uinfo.username,
            "EXT_SESSION_ID": str(tctx.uinfo.usid),
            "EXT_LOGIN_TIME": datetime.fromtimestamp(tctx.uinfo.logintime).isoformat() + 'Z',
            "EXT_REMOTE_ADDR": str(tctx.uinfo.addr),
            "OPERATION": operation,
            "SERVICE_DEFINITION": service_definition
        }
    }

    self.log.debug('Audit request data ', audit_data)
    audit_response = requests.post("http://{}:{}/api/apnasr/order/create".format(omf['host'], omf['port']), data=json.dumps(audit_data), headers={"Content-Type" : "application/json", "Accept" : "application/json"}, auth=(omf['username'], omf['password']))
    self.log.info('Audit response status ', audit_response.status_code)
    self.log.debug('Audit response message ', audit_response.text.encode('utf-8').strip())

def replace_pl (input):
    pl_char     = 'ąĄćĆęĘłŁóÓńŃśŚżŻźŹ'
    non_pl_char = 'aAcCeElLoOnNsSzZzZ'
    trans = str.maketrans(pl_char, non_pl_char)
    return input.translate(trans)
