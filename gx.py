#!/usr/bin/env python

# Next two lines are to include parent directory for testing
from binascii import unhexlify
import sys, time, os, subprocess
import socket
import select
import json
import threading
import thread
import sys;
import logging

from file_factories import generate_file, write_file

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

sys.path.append("..")
# Remove them normally

# PGW client - Gx protocol for tests with PCRF simulator

from libDiameter import *

def update(sess, mklist, at):
    CCR_avps = []
    CCR_avps.append(encodeAVP('Session-Id', sess))
    CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
    CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
    CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
    CCR_avps.append(encodeAVP('CC-Request-Type', 2))
    CCR_avps.append(encodeAVP('CC-Request-Number', req_num[sess]))
    if at == "2g":
        CCR_avps.append(encodeAVP('RAT-Type', 1001))
        CCR_avps.append(encodeAVP('Event-Trigger', 2))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '2000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '200000')]))
        CCR_avps.append(encodeAVP('Default-EPS-Bearer-QoS', [encodeAVP('QoS-Class-Identifier', 7),
                                                             encodeAVP('Allocation-Retention-Priority',
                                                                       [encodeAVP('Priority-Level', 1),
                                                                        encodeAVP('Pre-emption-Capability', 0),
                                                                        encodeAVP('Pre-emption-Vulnerability', 0)])]))
    elif at == "3g":
        CCR_avps.append(encodeAVP('RAT-Type', 1000))
        CCR_avps.append(encodeAVP('Event-Trigger', 2))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '42000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '21000000')]))
        CCR_avps.append(encodeAVP('Default-EPS-Bearer-QoS', [encodeAVP('QoS-Class-Identifier', 7),
                                                             encodeAVP('Allocation-Retention-Priority',
                                                                       [encodeAVP('Priority-Level', 1),
                                                                        encodeAVP('Pre-emption-Capability', 0),
                                                                        encodeAVP('Pre-emption-Vulnerability', 0)])]))
    elif at == "3,5g":
        CCR_avps.append(encodeAVP('RAT-Type', 1003))
        CCR_avps.append(encodeAVP('Event-Trigger', 2))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '42000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '121000000')]))
        CCR_avps.append(encodeAVP('Default-EPS-Bearer-QoS', [encodeAVP('QoS-Class-Identifier', 7),
                                                             encodeAVP('Allocation-Retention-Priority',
                                                                       [encodeAVP('Priority-Level', 1),
                                                                        encodeAVP('Pre-emption-Capability', 0),
                                                                        encodeAVP('Pre-emption-Vulnerability', 0)])]))
    elif at == "4g":
        CCR_avps.append(encodeAVP('RAT-Type', 1004))
        CCR_avps.append(encodeAVP('Event-Trigger', 2))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '150000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '100000000')]))
        CCR_avps.append(encodeAVP('Default-EPS-Bearer-QoS', [encodeAVP('QoS-Class-Identifier', 7),
                                                             encodeAVP('Allocation-Retention-Priority',
                                                                       [encodeAVP('Priority-Level', 1),
                                                                        encodeAVP('Pre-emption-Capability', 0),
                                                                        encodeAVP('Pre-emption-Vulnerability', 0)])]))
    # print "read mk"
    # print mklist
    logger.debug(mklist)
    for mk in mklist:
        print mk
        for k in mk:
            v = mk[k]
            print k
            print v
            CCR_avps.append(encodeAVP('Usage-Monitoring-Information',
                                      [encodeAVP('Used-Service-Unit', [encodeAVP('CC-Total-Octets', v)]),
                                       encodeAVP('Monitoring-Key', str(k))]))
            print "added"
    CCR = HDRItem()
    # setFlags(CER,DIAMETER_HDR_PROXIABLE)
    # Set command code
    CCR.cmd = dictCOMMANDname2code('Credit-Control')
    CCR.appId = 16777238
    # Set Hop-by-Hop and End-to-End
    initializeHops(CCR)
    setFlags(CCR, DIAMETER_HDR_PROXIABLE)
    msg = createReq(CCR, CCR_avps)
    # send data
    Conn.send(msg.decode('hex'))

def stop(sess, mklist):
    CCR_avps = []
    CCR_avps.append(encodeAVP('Session-Id', sess))
    CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
    CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
    CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
    CCR_avps.append(encodeAVP('CC-Request-Type', 3))
    CCR_avps.append(encodeAVP('CC-Request-Number', req_num[sess]))
    # print "read mk"
    # print mklist
    if mklist:
        logger.debug(mklist)
        for mk in mklist:
            print mk
            for k in mk:
                v = mk[k]
                print k
                print v
                CCR_avps.append(encodeAVP('Usage-Monitoring-Information',
                                          [encodeAVP('Used-Service-Unit', [encodeAVP('CC-Total-Octets', v)]),
                                           encodeAVP('Monitoring-Key', str(k))]))
    CCR = HDRItem()
    # setFlags(CER,DIAMETER_HDR_PROXIABLE)
    # Set command code
    CCR.cmd = dictCOMMANDname2code('Credit-Control')
    CCR.appId = 16777238
    # Set Hop-by-Hop and End-to-End
    initializeHops(CCR)
    setFlags(CCR, DIAMETER_HDR_PROXIABLE)
    msg = createReq(CCR, CCR_avps)
    # send data
    Conn.send(msg.decode('hex'))

def start(msid, apn, ip, at, tz):
    CCR_avps = []
    CCR_avps.append(encodeAVP('Session-Id', ORIGIN_HOST + ";" + apn + ";" + msid))
    CCR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    CCR_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
    CCR_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
    CCR_avps.append(encodeAVP('Destination-Realm', DEST_REALM))
    CCR_avps.append(encodeAVP('CC-Request-Type', 1))
    CCR_avps.append(encodeAVP('CC-Request-Number', req_num[ORIGIN_HOST + ";" + apn + ";" + msid]))
    CCR_avps.append(encodeAVP('Framed-IP-Address', ip))
    if at == "2g":
        CCR_avps.append(encodeAVP('RAT-Type', 1001))
        CCR_avps.append(encodeAVP('3GPP-SGSN-Address', "112.215.36.97"))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '2000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '200000')]))
    elif at == "3g":
        CCR_avps.append(encodeAVP('RAT-Type', 1000))
        CCR_avps.append(encodeAVP('3GPP-SGSN-Address', "112.215.36.97"))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '42000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '21000000')]))
    elif at == "3,5g":
        CCR_avps.append(encodeAVP('RAT-Type', 1003))
        CCR_avps.append(encodeAVP('3GPP-SGSN-Address', "112.215.36.97"))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '42000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '21000000')]))
    elif at == "4g":
        CCR_avps.append(encodeAVP('RAT-Type', 1004))
        CCR_avps.append(encodeAVP('AN-GW-Address', "112.215.130.1"))
        CCR_avps.append(encodeAVP('QoS-Information', [encodeAVP('APN-Aggregate-Max-Bitrate-DL', '150000000'),
                                                      encodeAVP('APN-Aggregate-Max-Bitrate-UL', '100000000')]))
    CCR_avps.append(
        encodeAVP('Subscription-Id', [encodeAVP('Subscription-Id-Type', 0), encodeAVP('Subscription-Id-Data', msid)]))
    CCR_avps.append(encodeAVP('Subscription-Id', [encodeAVP('Subscription-Id-Type', 1),
                                                  encodeAVP('Subscription-Id-Data', "510113106334338")]))
    CCR_avps.append(encodeAVP('User-Equipment-Info', [encodeAVP('User-Equipment-Info-Type', 0),
                                                      encodeAVP('User-Equipment-Info-Value',
                                                                "\x33\x35\x35\x32\x30\x31\x32\x36\x32\x38\x37\x32\x30\x31\x30\x31")]))
    CCR_avps.append(encodeAVP('Called-Station-Id', apn))
    CCR_avps.append(encodeAVP('IP-CAN-Type', 5))
    CCR_avps.append(encodeAVP('Default-EPS-Bearer-QoS', [encodeAVP('QoS-Class-Identifier', 7),
                                                         encodeAVP('Allocation-Retention-Priority',
                                                                   [encodeAVP('Priority-Level', 1),
                                                                    encodeAVP('Pre-emption-Capability', 0),
                                                                    encodeAVP('Pre-emption-Vulnerability', 0)])]))
    CCR_avps.append(encodeAVP('3GPP-SGSN-MCC-MNC', "51011"))
    CCR_avps.append(encodeAVP('3GPP-User-Location-Info', "\x82\x15\xf0\x11\xa7\xf9\x15\xf0\x11\x06\x8f\xd2\x05"))
    if tz:
        sign = tz[3:4]
        val = tz[4:]
        tot = 4 * int(val)
        stot = str(tot)
        res = stot[1:] + stot[0:1]
        if sign == "-":
            temp = 8 + int(stot[0:1])
            res = stot[1:] + hex(temp)[2:]
        res = res + "00"
        CCR_avps.append(encodeAVP('3GPP-MS-TimeZone', unhexlify(res)))
        CCR_avps.append(encodeAVP('Supported-Features', [encodeAVP('Vendor-Id', 10415), encodeAVP('Feature-List-ID', 1),
                                                         encodeAVP('Feature-List', 3)]))
    CCR = HDRItem()
    # setFlags(CER,DIAMETER_HDR_PROXIABLE)
    # Set command code
    CCR.cmd = dictCOMMANDname2code('Credit-Control')
    CCR.appId = 16777238
    # Set Hop-by-Hop and End-to-End
    initializeHops(CCR)
    setFlags(CCR, DIAMETER_HDR_PROXIABLE)
    msg = createReq(CCR, CCR_avps)
    # send data
    Conn.send(msg.decode('hex'))

def handle_cmd(srv):
    conn, address = srv.accept()
    mydata.peer = str(conn.getpeername())
    while True:
        try:
            received = conn.recv(1024)
            jsonObject = json.loads(received)
            write_file(file_name, jsonObject)
            logger.debug('jsonObject: %s', jsonObject)
            action = jsonObject['action']
            logger.debug('action: %s', action)
            if action == "start":
                msid = jsonObject['msid']
                apn = jsonObject['apn']
                ip = jsonObject['ip']
                at = ""
                if 'at' in jsonObject:
                    at = jsonObject['at']
                tz = ""
                if 'tz' in jsonObject:
                    tz = jsonObject['tz']
                sess = ORIGIN_HOST + ";" + apn + ";" + msid
                client_list[sess] = conn
                sess_list[mydata.peer] = sess
                req_num[sess] = 0
                start(msid, apn, ip, at, tz)
            elif action == "stop":
                req_num[sess_list[mydata.peer]] += 1
                mklist = []
                if 'mk' in jsonObject:
                    mklist = jsonObject['mk']
                stop(sess_list[mydata.peer], mklist)
            elif action == "update":
                req_num[sess_list[mydata.peer]] += 1
                mklist = []
                if 'mk' in jsonObject:
                    mklist = jsonObject['mk']
                at = ""
                if 'at' in jsonObject:
                    at = jsonObject['at']
                update(sess_list[mydata.peer], mklist, at)
            else:
                break
        except:
            break

def handle_gx(conn):
    received = conn.recv(1024)
    msg = received.encode('hex')
    H = HDRItem()
    stripHdr(H, msg)
    avps = splitMsgAVPs(H.msg)
    logger.info('H.cmd: %s', H.cmd)
    for avp in avps:
        aName, rt = decodeAVP(avp)
        # print "Decoded AVP", decodeAVP(avp)
        logger.debug(aName)
        logger.debug(rt)
    if H.cmd == 280:
        DWA_avps = []
        DWA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
        DWA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
        DWA_avps.append(encodeAVP('Result-Code', 2001))
        DWA = HDRItem()
        DWA.cmd = H.cmd
        DWA.appId = H.appId
        DWA.HopByHop = H.HopByHop
        DWA.EndToEnd = H.EndToEnd
        ret = createRes(DWA, DWA_avps)
        conn.send(ret.decode("hex"))
    elif H.cmd == 258:
        RAA_SESSION = findAVP("Session-Id", avps)
        rartype = findAVP("Re-Auth-Request-Type", avps)
        qosinfo = findAVP("QoS-Information", avps)
        mklist = []
        for avp in avps:
            if isinstance(avp, tuple):
                (Name, Value) = avp
            else:
                (Name, Value) = decodeAVP(avp)
            if Name == "Usage-Monitoring-Information":
                mk = findAVP("Monitoring-Key", Value)
                gsu = findAVP("Granted-Service-Unit", Value)
                if gsu != -1:
                    total = findAVP("CC-Total-Octets", gsu)
                    print "mk " + mk
                    print "gsu " + str(total)
                    mkinfo = {}
                    mkinfo[mk] = total
                    mklist.append(mkinfo)
        data = {}
        if mklist:
            data['mk'] = mklist
        data['rartype'] = rartype
        if qosinfo != -1:
            dl = findAVP("APN-Aggregate-Max-Bitrate-DL", qosinfo)
            ul = findAVP("APN-Aggregate-Max-Bitrate-UL", qosinfo)
            if dl == -1:
                dl = findAVP("Max-Requested-Bandwidth-DL", qosinfo)
            if ul == -1:
                ul = findAVP("Max-Requested-Bandwidth-UL", qosinfo)
            if dl != -1:
                data['dl'] = dl
            if ul != -1:
                data['ul'] = ul
        json_data = json.dumps(data)
        client_list[RAA_SESSION].send(json_data + "\n")

        RAA_avps = []
        RAA_avps.append(encodeAVP('Session-Id', RAA_SESSION))
        RAA_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
        RAA_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
        RAA_avps.append(encodeAVP('Origin-State-Id', 15))
        RAA_avps.append(encodeAVP('Result-Code', 2001))
        RAA = HDRItem()
        RAA.cmd = H.cmd
        RAA.appId = H.appId
        RAA.HopByHop = H.HopByHop
        RAA.EndToEnd = H.EndToEnd
        ret = createRes(RAA, RAA_avps)
        conn.send(ret.decode("hex"))
    elif H.cmd == 272:
        CCA_SESSION = findAVP("Session-Id", avps)
        rc = findAVP("Result-Code", avps)
        qosinfo = findAVP("QoS-Information", avps)
        bearer = findAVP("Default-EPS-Bearer-QoS", avps)
        mklist = []
        ruleIlist = []
        rules_removed = []
        for avp in avps:
            if isinstance(avp, tuple):
                (Name, Value) = avp
            else:
                (Name, Value) = decodeAVP(avp)
            if Name == "Usage-Monitoring-Information":
                mk = findAVP("Monitoring-Key", Value)
                gsu = findAVP("Granted-Service-Unit", Value)
                if gsu != -1:
                    total = findAVP("CC-Total-Octets", gsu)
                    print "mk " + mk
                    print "gsu " + str(total)
                    mkinfo = {}
                    mkinfo[mk] = total
                    mklist.append(mkinfo)
            elif Name == "Charging-Rule-Install":
                ruleIlist.append(extract_charging_rule(avp))
            elif Name == "Charging-Rule-Remove":
                rules_removed.append(extract_charging_rule(avp))
                logger.debug('Rules removed: %s', rules_removed)

        data = {}
        if ruleIlist:
            data['ruleInstall'] = ruleIlist
        if rules_removed:
            data['ruleRemoved'] = rules_removed
        if mklist:
            data['monitoringKey'] = mklist
        if qosinfo != -1:
            dl = findAVP("APN-Aggregate-Max-Bitrate-DL", qosinfo)
            ul = findAVP("APN-Aggregate-Max-Bitrate-UL", qosinfo)
            if dl == -1:
                dl = findAVP("Max-Requested-Bandwidth-DL", qosinfo)
            if ul == -1:
                ul = findAVP("Max-Requested-Bandwidth-UL", qosinfo)
            if dl != -1:
                data['downlink'] = dl
            if ul != -1:
                data['uplink'] = ul
        if bearer != -1:
            qci = findAVP("QoS-Class-Identifier", bearer)
            if qci != -1:
                data['qci'] = qci
            arp = findAVP("Allocation-Retention-Priority", bearer)
            if arp != -1:
                arp = findAVP("Priority-Level", arp)
                # capab = findAVP("Pre-emption-Capability", arp)
                # vulner = findAVP("Pre-emption-Vulnerability", arp)
                if arp != -1:
                    data['arp'] = arp
                    # data['capab'] = capab
                    # data['vulner'] = vulner
        data['resultCode'] = rc
        json_data = json.dumps(data)
        logger.debug(json_data)
        write_file(file_name, json_data)
        client_list[CCA_SESSION].send(json_data + "\n")

def extract_charging_rule(avp):
    rules = []
    (Nam, Val) = decodeAVP(avp)
    for av in Val:
        if isinstance(av, tuple):
            (Na, Va) = av
        else:
            (Na, Va) = decodeAVP(av)
        rules.append(Va)
    return rules


if __name__ == '__main__':
    # SET THIS TO YOUR PCRF SIMULATOR IP/PORT

    HOST = "10.23.32.93"
    # HOST = "172.29.30.62"
    PORT = 3868
    ORIGIN_HOST = "gx.qostools.xl.co.id"
    ORIGIN_REALM = "qostools.xl.co.id"
# DEST_REALM="xltest.id"
# DEST_HOST="SAPCCBTTEST.xltest.id"
DEST_REALM = "xl.co.id"
DEST_HOST = "vpcrf.xl.co.id"
IDENTITY = "1234567890"  # This is msisdn of user in SPR DB

# Generate file
file_name = ""

Conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
Conn.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
SOURCE_PORT = 3869
Conn.bind(('0.0.0.0', SOURCE_PORT))
Conn.connect((HOST, PORT))
LoadDictionary("dictDiameter.xml")

###### FIRST WE CREATE CER and receive CEA ###########################
# Let's build CER
CER_avps = []
CER_avps.append(encodeAVP('Origin-Host', ORIGIN_HOST))
CER_avps.append(encodeAVP('Origin-Realm', ORIGIN_REALM))
CER_avps.append(encodeAVP('Host-IP-Address', '10.195.84.157'))
CER_avps.append(encodeAVP('Vendor-Id', '193'))
CER_avps.append(encodeAVP('Product-Name', 'QoSTools'))
CER_avps.append(encodeAVP('Origin-State-Id', 15))
CER_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
CER_avps.append(encodeAVP('Vendor-Specific-Application-Id',
                          [encodeAVP('Vendor-Id', 10415), encodeAVP('Auth-Application-Id', 16777238)]))
CER_avps.append(encodeAVP('Firmware-Revision', 221842434))
# Create message header (empty)
CER = HDRItem()
# Set command code
CER.cmd = dictCOMMANDname2code('Capabilities-Exchange')
# Set Hop-by-Hop and End-to-End
initializeHops(CER)
# Add AVPs to header and calculate remaining fields
msg = createReq(CER, CER_avps)

# msg now contains CER Request as hex string
# send data
Conn.send(msg.decode('hex'))
# Receive response
received = Conn.recv(1024)

# Parse and display received CEA ANSWER
# print "THE CEA ANSWER IS:"
msg = received.encode('hex')
# print msg
H = HDRItem()
stripHdr(H, msg)
avps = splitMsgAVPs(H.msg)
cmd = dictCOMMANDcode2name(H.flags, H.cmd)
if cmd == ERROR:
    logger.debug('Unknown command: %s', H.cmd)
    print 'Unknown command', H.cmd
else:
    logger.debug('Command: %s', cmd)
    print 'Command: ' + cmd
    # print "Hop-by-Hop=", H.HopByHop, "End-to-End=", H.EndToEnd, "ApplicationId=", H.appId
    # print "=" * 30
    # for avp in avps:
    #     print "Decoded AVP", decodeAVP(avp)
    #     print "-" * 30

mydata = threading.local()
sock_list = []
client_list = {}
sess_list = {}
req_num = {}
CMD_HOST = "localhost"
CMD_PORT = 5555
MAX_CLIENTS = 20
CMD_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# fix "Address already in use" error upon restart
CMD_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
CMD_server.bind((CMD_HOST, CMD_PORT))
CMD_server.listen(MAX_CLIENTS)
sock_list.append(CMD_server)
sock_list.append(Conn)
while True:
    try:
        read, write, error = select.select(sock_list, [], [], 1)
    except:
        print "break"
        break
    for r in read:
        if r == Conn:
            thread.start_new_thread(handle_gx, (r,))
        elif r == CMD_server:
            file_name = generate_file()
            thread.start_new_thread(handle_cmd, (r,))


