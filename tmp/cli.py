from osfp.lib.log import logger
from osfp.lib.utils import *
from osfp.lib.mysmb import smb_scan_os
import copy


import os
import sys
import logging
import struct

from pprint import pprint

from impacket import (
    ntlm,
    smb,
    smb3
)


logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__file__)


class SMB1(smb.SMB):
    def scan_os(self, user='', password='', domain='', lmhash='', nthash='', ntlm_fallback=True):
        '''
        modified from impacket.smb.SMB.login()
        '''

        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try:  # just in case they were converted already
                lmhash = smb.a2b_hex(lmhash)
                nthash = smb.a2b_hex(nthash)
            except:
                pass

        self._SMB__userName = user
        self._SMB__password = password
        self._SMB__domain = domain
        self._SMB__lmhash = lmhash
        self._SMB__nthash = nthash
        self._SMB__aesKey = ''
        self._SMB__TGT = None
        self._SMB__TGS = None

        if self._dialects_parameters['Capabilities'] & smb.SMB.CAP_EXTENDED_SECURITY:
            try:
                self.scan_os_extended(
                    user, password, domain, lmhash, nthash, use_ntlmv2=True)
            except:
                # If the target OS is Windows 5.0 or Samba, let's try using NTLMv1
                if ntlm_fallback and ((self.get_server_lanman().find('Windows 2000') != -1) or (self.get_server_lanman().find('Samba') != -1)):
                    self.scan_os_extended(user, password,
                                          domain, lmhash, nthash, use_ntlmv2=False)
                    self._SMB__isNTLMv2 = False
                else:
                    raise
        elif ntlm_fallback:
            self.scan_os_standard('', '', domain, lmhash, nthash)
            self._SMB__isNTLMv2 = False
        else:
            raise smb.SessionError(
                'Cannot authenticate against target, enable ntlm_fallback')

    def scan_os_extended(self, user='', password='', domain='', lmhash='', nthash='', use_ntlmv2=True):
        '''
        modified from impacket.smb.SMB.login()
        '''
        # login feature does not support unicode
        # disable it if enabled
        flags2 = self._SMB__flags2
        if flags2 & smb.SMB.FLAGS2_UNICODE:
            self._SMB__flags2 = flags2 & (flags2 ^ smb.SMB.FLAGS2_UNICODE)

        # Once everything's working we should join login methods into a single one
        smb_request = smb.NewSMBPacket()
        # Are we required to sign SMB? If so we do it, if not we skip it
        if self._SignatureRequired:
            smb_request['Flags2'] |= smb.SMB.FLAGS2_SMB_SECURITY_SIGNATURE

        sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Extended_Parameters()
        sessionSetup['Data'] = smb.SMBSessionSetupAndX_Extended_Data()

        sessionSetup['Parameters']['MaxBufferSize'] = 61440
        sessionSetup['Parameters']['MaxMpxCount'] = 2
        sessionSetup['Parameters']['VcNumber'] = 1
        sessionSetup['Parameters']['SessionKey'] = 0
        sessionSetup['Parameters']['Capabilities'] = smb.SMB.CAP_EXTENDED_SECURITY | smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_UNICODE | smb.SMB.CAP_LARGE_READX | smb.SMB.CAP_LARGE_WRITEX

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = smb.SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [
            smb.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(self.get_client_name(
        ), domain, self._SignatureRequired, use_ntlmv2=use_ntlmv2)
        blob['MechToken'] = auth.getData()

        sessionSetup['Parameters']['SecurityBlobLength'] = len(blob)
        sessionSetup['Parameters'].getData()
        sessionSetup['Data']['SecurityBlob'] = blob.getData()

        # Fake Data here, don't want to get us fingerprinted
        sessionSetup['Data']['NativeOS'] = 'Unix'
        sessionSetup['Data']['NativeLanMan'] = 'Samba'

        smb_request.addCommand(sessionSetup)
        self.sendSMB(smb_request)

        smb_response = self.recvSMB()
        if smb_response.isValidAnswer(smb.SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb_response['Uid']

            # Now we have to extract the blob to continue the auth process
            sessionResponse = smb.SMBCommand(smb_response['Data'][0])
            sessionParameters = smb.SMBSessionSetupAndX_Extended_Response_Parameters(
                sessionResponse['Parameters'])
            sessionData = smb.SMBSessionSetupAndX_Extended_Response_Data(
                flags=smb_response['Flags2'])
            sessionData['SecurityBlobLength'] = sessionParameters['SecurityBlobLength']
            sessionData.fromString(sessionResponse['Data'])
            respToken = smb.SPNEGO_NegTokenResp(sessionData['SecurityBlob'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(
                    ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                    try:
                        self._SMB__server_name = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode(
                            'utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                    try:
                        if self._SMB__server_name != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                            self._SMB__server_domain = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode(
                                'utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                    try:
                        self._SMB__server_dns_domain_name = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode(
                            'utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                    try:
                        self._SMB__server_dns_host_name = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode(
                            'utf-16le')
                    except UnicodeDecodeError:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

            if self._strict_hostname_validation:
                self.perform_hostname_validation()

            # Parse Version to know the target Operating system name. Not provided elsewhere anymore
            if 'Version' in ntlmChallenge.fields:
                version = ntlmChallenge['Version']

                if len(version) >= 4:
                    self._SMB__server_os_major, self._SMB__server_os_minor, self._SMB__server_os_build = struct.unpack(
                        '<BBH', version[:4])

            # type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, respToken['ResponseToken'], user, password, domain, lmhash, nthash, use_ntlmv2 = use_ntlmv2)

            # if exportedSessionKey is not None:
            #     self._SigningSessionKey = exportedSessionKey

            # smb = NewSMBPacket()

            # Are we required to sign SMB? If so we do it, if not we skip it
            # if self._SignatureRequired:
            #    smb['Flags2'] |= SMB.FLAGS2_SMB_SECURITY_SIGNATURE

            # respToken2 = SPNEGO_NegTokenResp()
            # respToken2['ResponseToken'] = type3.getData()

            # Reusing the previous structure
            # sessionSetup['Parameters']['SecurityBlobLength'] = len(respToken2)
            # sessionSetup['Data']['SecurityBlob'] = respToken2.getData()

            # Storing some info for later use
            self._SMB__server_os = sessionData['NativeOS']
            self._SMB__server_lanman = sessionData['NativeLanMan']

            # [unc1e2] new property added by us, `PrimaryDomain` appears occasionally but impacket omitted it in smb.SMBSessionSetupAndX_Extended_Response_Data
            #
            # [MS-SMB] v20210407
            #   2.2.4.6.2 Server Response Extensions
            #       When extended security is being used (see section 3.2.4.2.4), a successful response MUST take the
            #       following form. Aside from the SecurityBlobLength field, the additional capabilities used in the
            #       Capabilities field, the ByteCount and SecurityBlob fields, and the omission of the PrimaryDomain field,
            #       all of the other fields are as specified in [MS-CIFS] section 2.2.4.53.2.

            _properties = sessionData.rawData.strip(b'\x00').split(b'\x00')
            _server_domain = _properties[-1].decode('utf-8') if sys.version_info >= (3, 0) else _properties[-1]
            if _server_domain != self._SMB__server_lanman:
                self._SMB__server_domain = _server_domain

            # smb.addCommand(sessionSetup)
            # self.sendSMB(smb)

            # smb = self.recvSMB()
            # self._uid = 0
            # if smb.isValidAnswer(SMB.SMB_COM_SESSION_SETUP_ANDX):
            #     self._uid = smb['Uid']
            #     sessionResponse   = SMBCommand(smb['Data'][0])
            #     sessionParameters = SMBSessionSetupAndXResponse_Parameters(sessionResponse['Parameters'])

            #     self._action = sessionParameters['Action']
            #     # If smb sign required, let's enable it for the rest of the connection
            #     if self._dialects_parameters['SecurityMode'] & SMB.SECURITY_SIGNATURES_REQUIRED:
            #        self._SignSequenceNumber = 2
            #        self._SignatureEnabled = True

            #     # restore unicode flag if needed
            #     if flags2 & SMB.FLAGS2_UNICODE:
            #         self._SMB__flags2 |= SMB.FLAGS2_UNICODE

            #     return 1
            return 1
        else:
            raise Exception('Error: Could not login successfully')

    def scan_os_standard(self, user='', password='', domain='', lmhash='', nthash=''):
        '''
        modified from impacket.smb.SMB.standard()
        '''
        # login feature does not support unicode
        # disable it if enabled
        flags2 = self._SMB__flags2
        if flags2 & smb.SMB.FLAGS2_UNICODE:
            self._SMB__flags2 = flags2 & (flags2 ^ smb.SMB.FLAGS2_UNICODE)

        # Only supports NTLMv1
        # Password is only encrypted if the server passed us an "encryption key" during protocol dialect negotiation
        if self._dialects_parameters['ChallengeLength'] > 0:
            if lmhash != '' or nthash != '':
                pwd_ansi = self.get_ntlmv1_response(lmhash)
                pwd_unicode = self.get_ntlmv1_response(nthash)
            elif password:
                lmhash = ntlm.compute_lmhash(password)
                nthash = ntlm.compute_nthash(password)
                pwd_ansi = self.get_ntlmv1_response(lmhash)
                pwd_unicode = self.get_ntlmv1_response(nthash)
            else:  # NULL SESSION
                pwd_ansi = ''
                pwd_unicode = ''
        else:
            pwd_ansi = password
            pwd_unicode = ''

        smb_request = smb.NewSMBPacket()

        sessionSetup = smb.SMBCommand(smb.SMB.SMB_COM_SESSION_SETUP_ANDX)
        sessionSetup['Parameters'] = smb.SMBSessionSetupAndX_Parameters()
        sessionSetup['Data'] = smb.SMBSessionSetupAndX_Data()

        sessionSetup['Parameters']['MaxBuffer'] = 61440
        sessionSetup['Parameters']['MaxMpxCount'] = 2
        sessionSetup['Parameters']['VCNumber'] = os.getpid(
        ) & 0xFFFF  # Value has to be expressed in 2 bytes
        sessionSetup['Parameters']['SessionKey'] = self._dialects_parameters['SessionKey']
        sessionSetup['Parameters']['AnsiPwdLength'] = len(pwd_ansi)
        sessionSetup['Parameters']['UnicodePwdLength'] = len(pwd_unicode)
        sessionSetup['Parameters']['Capabilities'] = smb.SMB.CAP_RAW_MODE | smb.SMB.CAP_USE_NT_ERRORS | smb.SMB.CAP_LARGE_READX | smb.SMB.CAP_LARGE_WRITEX

        sessionSetup['Data']['AnsiPwd'] = pwd_ansi
        sessionSetup['Data']['UnicodePwd'] = pwd_unicode
        sessionSetup['Data']['Account'] = str(user)
        sessionSetup['Data']['PrimaryDomain'] = str(domain)
        sessionSetup['Data']['NativeOS'] = str(os.name)
        sessionSetup['Data']['NativeLanMan'] = 'pysmb'
        smb_request.addCommand(sessionSetup)

        self.sendSMB(smb_request)

        smb_response = self.recvSMB()
        if smb_response.isValidAnswer(smb.SMB.SMB_COM_SESSION_SETUP_ANDX):
            # We will need to use this uid field for all future requests/responses
            self._uid = smb_response['Uid']
            sessionResponse = smb.SMBCommand(smb_response['Data'][0])
            sessionParameters = smb.SMBSessionSetupAndXResponse_Parameters(
                sessionResponse['Parameters'])
            sessionData = smb.SMBSessionSetupAndXResponse_Data(
                flags=smb_response['Flags2'], data=sessionResponse['Data'])

            self._action = sessionParameters['Action']

            # Still gotta figure out how to do this with no EXTENDED_SECURITY
            if sessionParameters['Action'] & smb.SMB_SETUP_USE_LANMAN_KEY == 0:
                self._SigningChallengeResponse = sessionSetup['Data']['UnicodePwd']
                self._SigningSessionKey = nthash
            else:
                self._SigningChallengeResponse = sessionSetup['Data']['AnsiPwd']
                self._SigningSessionKey = lmhash

            #self._SignSequenceNumber = 1
            #self.checkSignSMB(smb, self._SigningSessionKey ,self._SigningChallengeResponse)
            #self._SignatureEnabled = True
            self._SMB__server_os = sessionData['NativeOS']
            self._SMB__server_lanman = sessionData['NativeLanMan']
            self._SMB__server_domain = sessionData['PrimaryDomain']

            # restore unicode flag if needed
            if flags2 & smb.SMB.FLAGS2_UNICODE:
                self._SMB__flags2 |= smb.SMB.FLAGS2_UNICODE

            return 1
        else:
            raise Exception('Error: Could not login successfully')


class SMB3(smb3.SMB3):

    def scan_os(self, user='', password='', domain='', lmhash='', nthash=''):
        '''
        modified from impacket.smb3.SMB3.login()
        '''
        # If we have hashes, normalize them
        if lmhash != '' or nthash != '':
            if len(lmhash) % 2:
                lmhash = '0%s' % lmhash
            if len(nthash) % 2:
                nthash = '0%s' % nthash
            try:  # just in case they were converted already
                lmhash = smb3.a2b_hex(lmhash)
                nthash = smb3.a2b_hex(nthash)
            except:
                pass

        self._SMB3__userName = user
        self._SMB3__password = password
        self._SMB3__domain = domain
        self._SMB3__lmhash = lmhash
        self._SMB3__nthash = nthash
        self._SMB3__aesKey = ''
        self._SMB3__TGT = None
        self._SMB3__TGS = None

        sessionSetup = smb3.SMB2SessionSetup()
        if self.RequireMessageSigning is True:
            sessionSetup['SecurityMode'] = smb3.SMB2_NEGOTIATE_SIGNING_REQUIRED
        else:
            sessionSetup['SecurityMode'] = smb3.SMB2_NEGOTIATE_SIGNING_ENABLED

        sessionSetup['Flags'] = 0
        #sessionSetup['Capabilities'] = SMB2_GLOBAL_CAP_LARGE_MTU | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_DFS

        # Let's build a NegTokenInit with the NTLMSSP
        # TODO: In the future we should be able to choose different providers

        blob = smb3.SPNEGO_NegTokenInit()

        # NTLMSSP
        blob['MechTypes'] = [
            smb3.TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']]
        auth = ntlm.getNTLMSSPType1(
            self._Connection['ClientName'], domain, self._Connection['RequireSigning'])
        blob['MechToken'] = auth.getData()

        sessionSetup['SecurityBufferLength'] = len(blob)
        sessionSetup['Buffer'] = blob.getData()

        # ToDo:
        # If this authentication is for establishing an alternative channel for an existing Session, as specified
        # in section 3.2.4.1.7, the client MUST also set the following values:
        # The SessionId field in the SMB2 header MUST be set to the Session.SessionId for the new
        # channel being established.
        # The SMB2_SESSION_FLAG_BINDING bit MUST be set in the Flags field.
        # The PreviousSessionId field MUST be set to zero.

        packet = self.SMB_PACKET()
        packet['Command'] = smb3.SMB2_SESSION_SETUP
        packet['Data'] = sessionSetup

        packetID = self.sendSMB(packet)
        ans = self.recvSMB(packetID)
        if self._Connection['Dialect'] == smb3.SMB2_DIALECT_311:
            self._SMB3__UpdatePreAuthHash(ans.rawData)

        if ans.isValidAnswer(smb3.STATUS_MORE_PROCESSING_REQUIRED):
            self._Session['SessionID'] = ans['SessionID']
            self._Session['SigningRequired'] = self._Connection['RequireSigning']
            self._Session['UserCredentials'] = (
                user, password, domain, lmhash, nthash)
            self._Session['Connection'] = self._NetBIOSSession.get_socket()
            sessionSetupResponse = smb3.SMB2SessionSetup_Response(ans['Data'])
            respToken = smb3.SPNEGO_NegTokenResp(
                sessionSetupResponse['Buffer'])

            # Let's parse some data and keep it to ourselves in case it is asked
            ntlmChallenge = ntlm.NTLMAuthChallenge(respToken['ResponseToken'])
            if ntlmChallenge['TargetInfoFields_len'] > 0:
                av_pairs = ntlm.AV_PAIRS(
                    ntlmChallenge['TargetInfoFields'][:ntlmChallenge['TargetInfoFields_len']])
                if av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] is not None:
                    try:
                        self._Session['ServerName'] = av_pairs[ntlm.NTLMSSP_AV_HOSTNAME][1].decode(
                            'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] is not None:
                    try:
                        if self._Session['ServerName'] != av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode('utf-16le'):
                            self._Session['ServerDomain'] = av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME][1].decode(
                                'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass
                if av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] is not None:
                    try:
                        self._Session['ServerDNSDomainName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME][1].decode(
                            'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] is not None:
                    try:
                        self._Session['ServerDNSHostName'] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME][1].decode(
                            'utf-16le')
                    except:
                        # For some reason, we couldn't decode Unicode here.. silently discard the operation
                        pass

                if self._strict_hostname_validation:
                    self.perform_hostname_validation()

                # Parse Version to know the target Operating system name. Not provided elsewhere anymore
                if 'Version' in ntlmChallenge.fields:
                    version = ntlmChallenge['Version']

                    if len(version) >= 4:
                        self._Session['ServerOS'] = "Windows %d.%d Build %d" % (smb3.indexbytes(
                            version, 0), smb3.indexbytes(version, 1), struct.unpack('<H', version[2:4])[0])
                        self._Session["ServerOSMajor"] = smb3.indexbytes(
                            version, 0)
                        self._Session["ServerOSMinor"] = smb3.indexbytes(
                            version, 1)
                        self._Session["ServerOSBuild"] = struct.unpack('<H', version[2:4])[
                            0]


def _smbv1_scan_os(remote_name, remote_host, sess_port=445, timeout=10,):
    try:
        user = ''
        password = ''
        domain = ''
        smb1_client = SMB1(remote_name=remote_name, remote_host=remote_host,
                           sess_port=sess_port, timeout=timeout)
        smb1_client.scan_os(user=user, password=password, domain=domain)
        smb1_client.close_session()
        return smb1_client.get_server_os()

    except Exception as err:
        logger.error('smb os fp scanner error[smbv1]: %s' % str(err))
        raise


def _smbv3_scan_os(remote_name, remote_host, sess_port=445, timeout=10,):
    try:
        user = ''
        password = ''
        domain = ''
        # smb3_client = smb3.SMB3(remote_name=remote_name, remote_host=remote_host,
        #                       sess_port=sess_port, timeout=timeout)
        # smb3_client.login(user=user, password=password, domain=domain)
        smb3_client = SMB3(remote_name=remote_name, remote_host=remote_host,
                           sess_port=sess_port, timeout=timeout)
        smb3_client.scan_os(user=user, password=password, domain=domain)
        smb3_client.close_session()
        return smb3_client.get_server_os()
    except Exception as err:
        logger.error('smb os fp scanner error[smbv3]: %s' % str(err))
        raise


def smb_scan_os(remote_host, remote_name=None, sess_port=445, timeout=10, smb_version="auto"):
    """
    get operating system version through smb.
    """
    if not remote_name:
        remote_name = remote_host
    result = {}
    is_auto = False
    if smb_version.lower() == 'auto':
        smb_version = ['1', '2', '3']
        is_auto = True

    # print(remote_host, remote_name, sess_port, timeout, smb_version)
    if '1' in smb_version:
        try:
            result = _smbv1_scan_os(
                remote_name=remote_name, remote_host=remote_host,
                sess_port=sess_port, timeout=timeout)
            return result
            if is_auto and result:
                return ""
        except:
            pass

    if '2' in smb_version or '3' in smb_version:
        try:
            result = _smbv3_scan_os(
                remote_name=remote_name, remote_host=remote_host,
                sess_port=sess_port, timeout=timeout)
            return result
        except:
            raise

    return ""


#!/usr/bin/env python
# -*- coding: utf-8 -*-

ALL_OS = {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian", "Palm OS", "Centos", "Ubuntu", "Debain"}

OS_DB = {
	"DF": {
		True: {"FreeBSD", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos", "Ubuntu", "Debain"},
		False: {"FreeBSD", "Symbian", "Palm OS", "Linux", "Windows XP", "Windows 7", "Windows 10", "Centos", "Ubuntu"}
	},
	"TTL": {
		64:	{"Linux", "FreeBSD", "Centos", "Ubuntu"},
		128: {"Windows XP", "Windows 7", "Windows 10"},
		256: {"Symbian", "Palm OS", "Cisco IOS", "Debain"}
	},
	"Win Size": {
		8192: {"Symbian", "Windows 7"},
		14600: {"Linux"},
		16348: {"Palm OS"},
		64240: {"Linux", "Ubuntu", "Centos"},
		65392: {"Windows 10"},
		65535: {"FreeBSD", "Windows XP", "Windows 10"},
		65550: {"FreeBSD"},
		29200: {"Centos"},
		26883: {"Debain"},
		None: {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian", "Palm OS", "Centos", "Ubuntu", "Debain"}
	},
	"MSS": {
		1350: {"Palm OS"},
		1440: {"Windows XP", "Windows 7", "Windows 10"},
		1460: {"Linux", "FreeBSD", "Windows XP", "Windows 7", "Windows 10", "Symbian"},
		1200: {"Centos", "Ubuntu", "Windows 7", "Debain"}
	}
}


def test_os_using_icmp(dst_ip, verbose=False):
	"""
	Tests a machine operating system using the ICMP protocol
	The way to do so is to send a PING to the remote host,
	and analyse the properties of the reply.
	:param dst_ip: str - an IPv4 legal ip address - the address of the machine we wish to test
	:param verbose: bool - print relevant information during the process
	:return: set - Set of optional Operating Systems of the given IP
	"""
	result_set = copy.deepcopy(ALL_OS)
	if verbose:
		print("[ICMP test] OS options are: {0}".format(result_set))

	icmp_reply = get_icmp_reply(dst_ip)
	if icmp_reply is None:
		logger.info("目的主机没有响应icmp请求。无法使用icmp缩小操作系统选项。")
		return copy.deepcopy(ALL_OS)

	# IP
	ip_layer = icmp_reply.getlayer("IP")
	ip_layer_os_set = os_set_from_ip_layer(ip_layer, verbose=verbose)
	result_set.intersection_update(ip_layer_os_set)
	if verbose:
		print("[ICMP test] OS options are: {0}".format(result_set))

	return result_set


def test_os_using_tcp(dst_ip, verbose=False):
	"""
	Tests a machine operating system using the TCP protocol.
	The way to do so is to find an open TCP port at the remote host,
	and analyse the TCP-IP properties of a connection.
	:param dst_ip: str - an IPv4 legal ip address - the address of the machine we wish to test
	:param bool - verbose: print relevant information during the process
	:return: set - Set of optional Operating Systems of the given IP
	"""
	result_set = copy.deepcopy(ALL_OS)
	if verbose:
		print("[TCP test] OS options are: {0}".format(result_set))

	syn_ack = get_syn_ack(dst_ip)
	if syn_ack is None:
		logger.info("找不到打开的TCP端口。无法使用TCP缩小操作系统选项。")
		return copy.deepcopy(ALL_OS)

	# IP
	ip_layer = syn_ack.getlayer("IP")
	ip_layer_os_set = os_set_from_ip_layer(ip_layer, verbose=verbose)
	result_set.intersection_update(ip_layer_os_set)
	if verbose:
		print("[TCP test] OS options are: {0}".format(result_set))

	# TCP
	tcp_layer = syn_ack.getlayer("TCP")
	tcp_layer_os_set = os_set_from_tcp_layer(tcp_layer, verbose=verbose)
	result_set.intersection_update(tcp_layer_os_set)
	if verbose:
		print("[TCP test] OS options are: {0}".format(result_set))

	return result_set