#!/usr/bin/env python


import re
import sys, getopt
from pysnmp.hlapi import *
import time
from array import *
from multiprocessing import Pool

def banner():
    print(
r""".
 /   _____/ \      \    /     \______    \______   \    |   |    |   \   \/  /
 \_____  \  /   |   \  /  \ /  \|     ___/|     ___/    |   |    |   /\     /
 /        \/    |    \/    Y    \    |    |    |   |    |___|    |  / /     \
/_______  /\____|__  /\____|__  /____|    |____|   |_______ \______/ /___/\  \
        \/         \/         \/                           \/              \_/

Liam Romanis
version 0.4b - beta testing
http://www.pentura.com
."""
)


def opts(argv):
    inputfile = ''
    userfile = ''
    passfile = ''
    commfile = ''

    def usage():
        print ('usage: test.py -i <inputfile> -u <userfile> -p <passfile> -c <communityfile>')


    try:
        opts, args = getopt.getopt(argv, 'i:u:p:c:h', ['ifile=', 'ufile=','pfile=','cfile=','help'])
    except getopt.GetoptError:
        usage()
        raise SystemExit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            raise SystemExit
        elif opt in ('-i', '--ifile'):
            inputfile = arg
        elif opt in ('-u', '--ufile'):
            userfile = arg
        elif opt in ('-p', '--pfile'):
            passfile = arg
        elif opt in ('-c', '--cfile'):
            commfile = arg

    if not inputfile or not userfile or not passfile or not commfile:
        usage()
        raise SystemExit(1)

    return inputfile, userfile, passfile, commfile



def snmp1dict(ip, comm):
    print('1', end='', flush=True)
    errorIndication, errorStatus, errorIndex, varBinds = \
        next(getCmd(SnmpEngine(),
                    CommunityData(comm, mpModel=0),
                    UdpTransportTarget((ip, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
        ))
    if errorIndication:
        pass
    elif errorStatus:
        pass
    else:
        print ("\nSNMPv1: %s: Community:%s" %(ip,comm))



def snmp2dict(ip, comm):
    print('2', end='', flush=True)
    errorIndication, errorStatus, errorIndex, varBinds = \
        next(getCmd(SnmpEngine(),
                    CommunityData(comm),
                    UdpTransportTarget((ip, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0'))
        ))
    if errorIndication:
        pass
    elif errorStatus:
        pass
    else:
        print ("\nSNMPv2: %s: Community:%s" %(ip,comm))



def snmp3_authNone_privNone(ip, user):
    print('3', end='', flush=True)
    errorIndication, errorStatus, errorIndex, varBinds = \
        next(getCmd(SnmpEngine(),
                    UsmUserData(user),
                    UdpTransportTarget((ip, 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
        ))
    if errorIndication:
        pass
    elif errorStatus:
        pass
    else:
        print ("\nSNMPv3 Auth None Priv None: %s: %s - no pass required\n" %(ip, user))



def snmp3_authMD5_privNone(ip, user, passwd):
    print('5', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))
        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth MD5 Priv None: %s: %s:%s" % (ip, user, passwd))
    except:
        print ('exception caused by: %s:%s' % (user,passwd))



def snmp3_authMD5_privDES(ip, user, passwd):
    print('D', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))
        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth MD5 Priv DES: %s: %s:%s" % (ip,user,passwd))
    except:
        print ('exception caused by: %s:%s' % (user,passwd))



def snmp3_authSHA_privAES128(ip,user,passwd):
    print('8', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd, authProtocol=usmHMACSHAAuthProtocol,
                                                          privProtocol=usmAesCfb128Protocol),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))
        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth SHA Priv AES128: %s:%s:auth:usmHMACSHAAuthProtocol:priv:usmAesCfb128Protocol" % (user,passwd))
    except:
        print ('exception caused by: %s:%s:usmHMACSHAAuthProtocol:usmAesCfb128Protocol' % (user,passwd))


def snmp3_authSHA_privAES192(ip,user,passwd):
    print('9', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd, authProtocol=usmHMACSHAAuthProtocol,
                                                          privProtocol=usmAesCfb192Protocol),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))

        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth SHA Priv AES192: %s:%s:auth:usmHMACSHAAuthProtocol:priv:usmAesCfb192Protocol" % (user,passwd))
    except:
        print ('exception caused by: %s:%s:usmHMACSHAAuthProtocol:usmAesCfb192Protocol' % (user,passwd))



def snmp3_authSHA_privAES256(ip,user,passwd):
    print('6', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd, authProtocol=usmHMACSHAAuthProtocol,
                                                          privProtocol=usmAesCfb256Protocol),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))

        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth SHA Priv AES256: %s:%s:auth:usmHMACSHAAuthProtocol:priv:usmAesCfb256Protocol" % (user,passwd))
    except:
        print ('exception caused by: %s:%s:usmHMACSHAAuthProtocol:usmAesCfb256Protocol' % (user,passwd))



def snmp3_authSHA_privDES(ip,user,passwd):
    print('s', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd, authProtocol=usmHMACSHAAuthProtocol,
                                                          privProtocol=usmDESPrivProtocol),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))

        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth SHA Priv DES: %s:%s:auth:usmHMACSHAAuthProtocol:priv:usmDESPrivProtocol" % (user,passwd))
    except:
        print ('exception caused by: %s:%s:usmHMACSHAAuthProtocol:usmDESPrivProtocol' % (user,passwd))



def snmp3_authSHA_priv3DES(ip,user,passwd):
    print('S', end='', flush=True)
    user = user.strip()
    passwd = passwd.strip()
    try:
        errorIndication, errorStatus, errorIndex, varBinds = \
            next(getCmd(SnmpEngine(),
                        UsmUserData(user, passwd, passwd, authProtocol=usmHMACSHAAuthProtocol,
                                                          privProtocol=usm3DESEDEPrivProtocol),
                        UdpTransportTarget((ip, 161)),
                        ContextData(),
                        ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysDescr', 0))
            ))

        if errorIndication:
            pass
        elif errorStatus:
            pass
        else:
            print ("\nSNMPv3 Auth SHA Priv 3DES: %s:%s:auth:usmHMACSHAAuthProtocol:priv:usm3DESEDEPrivProtocol" % (user,passwd))
    except:
        print ('exception caused by: %s:%s:usmHMACSHAAuthProtocol:usm3DESEDEPrivProtocol' % (user,passwd))



def snmp12_helper(args):
    return snmp1dict(*args), snmp2dict(*args)

def snmp3none_helper(args):
    return snmp3_authNone_privNone(*args)

def snmp3md5none_helper(args):
    return snmp3_authMD5_privNone(*args), snmp3_authMD5_privDES(*args)

def snmp3shaaes_helper(args):
    return (snmp3_authSHA_privAES128(*args),
            snmp3_authSHA_privAES192(*args),
            snmp3_authSHA_privAES256(*args),
            snmp3_authSHA_privDES(*args),
            snmp3_authSHA_priv3DES(*args))



if __name__ == "__main__":
    banner()
    inputfile, userfile, passfile, commfile = opts(sys.argv[1:])

    with open(inputfile, "r") as ins:
        targets = ins.read().splitlines()

    with open(userfile, "r") as ins:
        users= ins.read().splitlines()

    with open(passfile, "r") as ins:
        passwords = [line for line in ins.read().splitlines() if len(line) > 8]

    with open(commfile, "r") as ins:
        communities = ins.read().splitlines()

    p = Pool(20)
    job1_args = [(ip, comm) for comm in communities for ip in targs]
    p.map(snmp12_helper, job1_args)
    job2_args = [(ip, user) for user in users for ip in targs]
    p.map(snmp3none_helper, job1_args)
    job3_args = [(ip, user, passwd) for ip in targs for user in users for passwd in passwords]
    p.map(snmp3md5none_helper, job3_args)
    job4_args = [(ip, user, passwd) for ip in targs for user in users for passwd in passwords] 
    p.map(snmp3shaaes_helper, job4_args)
