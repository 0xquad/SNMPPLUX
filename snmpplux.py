#!/usr/bin/env python


import re
import sys
from optparse import OptionParser
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
    modes = []

    def usage():
        print('''\
usage: {0} -1 -C communityfile [-T targets-file | target1 [target2 ...]]
       {0} -2 -C communityfile [-T targets-file | target1 [target2 ...]]
       {0} -3 -U users-file -P pw-file [-T targets-file | target1 [target2 ...]]

versions can be combined as long as the required additional args are present
'''.format(sys.argv[0]))


    parser = OptionParser()
    parser.add_option('-1', '--v1', dest='scan_versions', action='append_const', const=1, default=[], help='scan for version 1 snmp service')
    parser.add_option('-2', '--v2', dest='scan_versions', action='append_const', const=2, default=[], help='scan for version 2c snmp service')
    parser.add_option('-3', '--v3', dest='scan_versions', action='append_const', const=3, default=[], help='scan for all auth modes of version 3 snmp service')
    parser.add_option('-T', '--targets', nargs=1, dest='targets_file', default=None, help='target file')
    parser.add_option('-U', '--usernames', nargs=1, dest='usernames_file', default=None, help='username file')
    parser.add_option('-P', '--passwords', nargs=1, dest='passwords_file', default=None, help='password file')
    parser.add_option('-C', '--communities', nargs=1, dest='communities_file', default=None, help='community file')
    parser.add_option('-t', '--threads', nargs=1, dest='threads', default=20, type='int', action='store', help='number of probes in parallel')
    options, targets = parser.parse_args()

    if not options.targets_file and not targets:
        usage()
        raise RuntimeError('must specify a target list either on command line or with -T')

    if not options.scan_versions:
        usage()
        raise RuntimeError('must specify at least one version to scan with -[123]')

    if 1 in options.scan_versions and not options.communities_file:
        usage()
        raise RuntimeError('versions 1 and 2 require a list of communities with -C')

    if 3 in options.scan_versions and (not options.usernames_file or not options.passwords_file):
        usage()
        raise RuntimeError('version 3 requires a list of usernames and passwords with -U and -P')

    if options.threads < 1:
        usage()
        raise RuntimeError('number of threads must be a positif integer')

    return options, targets



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



def snmp1_helper(args):
    return snmp1dict(*args)

def snmp2_helper(args):
    return snmp2dict(*args)

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
    options, targets = opts(None)

    if options.targets_file:
        with open(options.targets_file, "r") as ins:
            targets += ins.read().splitlines()

    p = Pool(options.threads)

    if 1 in options.scan_versions or 2 in options.scan_versions:
        with open(options.communities_file, "r") as ins:
            communities = ins.read().splitlines()

        job1_args = [(ip, comm) for comm in communities for ip in targets]
        if 1 in options.scan_versions:
            p.map(snmp1_helper, job1_args)
        if 2 in options.scan_versions:
            p.map(snmp2_helper, job1_args)
    if 3 in options.scan_versions:
        with open(options.usernames_file, "r") as ins:
            users= ins.read().splitlines()

        with open(options.passwords_file, "r") as ins:
            passwords = [line for line in ins.read().splitlines() if len(line) > 8]

        job2_args = [(ip, user) for user in users for ip in targets]
        p.map(snmp3none_helper, job2_args)
        job3_args = [(ip, user, passwd) for ip in targets for user in users for passwd in passwords]
        p.map(snmp3md5none_helper, job3_args)
        job4_args = [(ip, user, passwd) for ip in targets for user in users for passwd in passwords]
        p.map(snmp3shaaes_helper, job4_args)
