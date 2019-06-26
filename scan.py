#!/usr/bin/env python
####################
#
# Copyright (c) 2019 Dirk-jan Mollema / Fox-IT (@_dirkjan)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Checks for CVE-2019-1040 vulnerability over SMB.
# The script will establish a connection to the target host(s) and send
# an invalid NTLM authentication. If this is accepted, the host is vulnerable to
# CVE-2019-1040 and you can execute the MIC Remove attack with ntlmrelayx.
#
# See https://dirkjanm.io/exploiting-CVE-2019-1040-relay-vulnerabilities-for-rce-and-domain-admin/
# for more info.
#
# Author:
#  Dirk-jan Mollema (@_dirkjan)
#
####################
import sys
import logging
import argparse
import codecs
import calendar
import struct
import time
from impacket import version
from impacket.examples.logger import ImpacketFormatter
from impacket.smbconnection import SMBConnection, SessionError
from impacket.smb3structs import *
from impacket import ntlm
from impacket.ntlm import AV_PAIRS, NTLMSSP_AV_TIME, NTLMSSP_AV_FLAGS, NTOWFv2, NTLMSSP_AV_TARGET_NAME, NTLMSSP_AV_HOSTNAME,USE_NTLMv2, hmac_md5

# Slightly modified version of impackets computeResponseNTLMv2
def mod_computeResponseNTLMv2(flags, serverChallenge, clientChallenge, serverName, domain, user, password, lmhash='',
                              nthash='', use_ntlmv2=USE_NTLMv2, check=False):

    responseServerVersion = b'\x01'
    hiResponseServerVersion = b'\x01'
    responseKeyNT = NTOWFv2(user, password, domain, nthash)

    av_pairs = AV_PAIRS(serverName)
    av_pairs[NTLMSSP_AV_TARGET_NAME] = 'cifs/'.encode('utf-16le') + av_pairs[NTLMSSP_AV_HOSTNAME][1]
    if av_pairs[NTLMSSP_AV_TIME] is not None:
        aTime = av_pairs[NTLMSSP_AV_TIME][1]
    else:
        aTime = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000))
        av_pairs[NTLMSSP_AV_TIME] = aTime
    av_pairs[NTLMSSP_AV_FLAGS] = b'\x02' + b'\x00' * 3
    serverName = av_pairs.getData()

    temp = responseServerVersion + hiResponseServerVersion + b'\x00' * 6 + aTime + clientChallenge + b'\x00' * 4 + \
           serverName + b'\x00' * 4

    ntProofStr = hmac_md5(responseKeyNT, serverChallenge + temp)

    ntChallengeResponse = ntProofStr + temp
    lmChallengeResponse = hmac_md5(responseKeyNT, serverChallenge + clientChallenge) + clientChallenge
    sessionBaseKey = hmac_md5(responseKeyNT, ntProofStr)

    return ntChallengeResponse, lmChallengeResponse, sessionBaseKey

orig_type1 = ntlm.getNTLMSSPType1
# Wrapper to remove signing flags
def mod_getNTLMSSPType1(workstation='', domain='', signingRequired = False, use_ntlmv2 = USE_NTLMv2):
    return orig_type1(workstation, domain, False, use_ntlmv2)

class checker(object):
    def __init__(self, username='', password='', domain='', port=None,
                 hashes=None):

        self.__username = username
        self.__password = password
        self.__port = port
        self.__domain = domain
        self.__lmhash = ''
        self.__nthash = ''
        if hashes is not None:
            self.__lmhash, self.__nthash = hashes.split(':')
        self.creds_validated = False

    def validate_creds(self, remote_host):
        try:
            smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
            smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
        except SessionError as exc:
            if 'STATUS_LOGON_FAILURE' in str(exc):
                logging.error('Error validating credentials - make sure the supplied credentials are correct')
            else:
                logging.warning('Unexpected Exception while validating credentials against {}: %s'.format(remote_host), exc)
            raise KeyboardInterrupt
        except:
            logging.error('Error during connection to {}. TCP/445 refused, timeout?'.format(remote_host))
    def check(self, remote_host):
        # Validate credentials first
        if not self.creds_validated:
            self.validate_creds(remote_host)
            self.creds_validated = True

        # Now start scanner
        try:
            smbClient = SMBConnection(remote_host, remote_host, sess_port=int(self.__port)) #, preferredDialect=SMB2_DIALECT_21
        except:
            return
        ntlm.computeResponseNTLMv2 = mod_computeResponseNTLMv2
        try:
            smbClient.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            logging.info('Target %s is VULNERABLE to CVE-2019-1040 (authentication was accepted)', remote_host)
        except SessionError as exc:
            if 'STATUS_INVALID_PARAMETER' in str(exc):
                logging.info('Target %s is not vulnerable to CVE-2019-1040 (authentication was rejected)', remote_host)
            else:
                logging.warning('Unexpected Exception while authenticating to %s: %s', remote_host, exc)

        smbClient.close()

# Process command-line arguments.
def main():
    # Init the example's logger theme
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(ImpacketFormatter())
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('utf8')(sys.stdout)

    logging.info('CVE-2019-1040 scanner by @_dirkjan / Fox-IT - Based on impacket by SecureAuth')

    parser = argparse.ArgumentParser(description="CVE-2019-1040 scanner - Connects over SMB and attempts to authenticate "
                                                 "with invalid NTLM packets. If accepted, target is vulnerable to MIC remove attack")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('connection')

    group.add_argument('-target-file',
                       action='store',
                       metavar="file",
                       help='Use the targets in the specified file instead of the one on'\
                            ' the command line (you must still specify something as target name)')
    group.add_argument('-port', choices=['139', '445'], nargs='?', default='445', metavar="destination port",
                       help='Destination port to connect to SMB Server')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    import re

    domain, username, password, remote_name = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(
        options.target).groups('')

    #In case the password contains '@'
    if '@' in remote_name:
        password = password + '@' + remote_name.rpartition('@')[0]
        remote_name = remote_name.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username == '':
        logging.error("Please supply a username/password (you can't use this scanner with anonymous authentication)")
        return

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    remote_names = []
    if options.target_file is not None:
        with open(options.target_file, 'r') as inf:
            for line in inf:
                remote_names.append(line.strip())
    else:
        remote_names.append(remote_name)

    lookup = checker(username, password, domain, int(options.port), options.hashes)
    for remote_name in remote_names:
        try:
            lookup.check(remote_name)
        except KeyboardInterrupt:
            break


if __name__ == '__main__':
    main()
