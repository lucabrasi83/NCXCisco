#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2017-2018 Anuta Networks, Inc. All Rights Reserved.

##################################################################################
########      #    #     # #   # #######    #			       ###
########     # #   # #   # #   #    #      # #                                 ###
########    #####  #   # # #   #    #     #####                                ###
########   #     # #     #   #      #    #     #  Created by ndilip 09/07/2017 ###
##################################################################################

from org.apache.http.conn.util import InetAddressUtils
from com.anuta.util import AnutaStringUtils
from ncxparser import parser, tokendecoderhandler, util
from com.google.common.base import Joiner
import traceback
import re

ACCESS_LIST = ["ip", "access-list"]
ACCESS_TYPE = ["standard", "extended"]


class AclRuleVariableDecoder(parser.DefaultVariableDecoder):
    ACCESS_LIST = ["ip", "access-list"]

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('AclRuleVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            print decoderhandler.getCurrentBlockTokens()
            if AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.ACCESS_LIST):
                self.processAccessList(cpc, dc, context, decoderhandler.getCurrentBlock())
                return
            self.processAclRule(cpc, dc, context, decoderhandler.getCurrentBlock())
        except Exception:
            traceback.print_exc()

    def processAccessList(self, cpc,dc,context,block):
        util.log_info('AclRuleVariableDecoder: processAccessList')
        
        try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(block.getTokens(), 2, None)
            aclType = ''
            aclName = ''
            aclType = cursor.getNextToken()
            cursor.advance()
            aclName = cursor.getNextToken()
            util.log_debug('The aclType: %s' %(aclType))
            util.log_debug('The aclName: %s' %(aclName))
            print aclType
            if aclType in ACCESS_TYPE:
                decoderhandler.addTokenValue("../../acl-type", aclType)
            else:
                decoderhandler.addTokenValue("../../name", aclType)
            decoderhandler.addTokenValue("../../name", aclName)
        except Exception:
            traceback.print_exc()

    def processAclRule(self,cpc,dc,context,block):
        util.log_info('AclRuleVariableDecoder: processAclRule')
        acl_dict = ['linenumber,INT', 'action,ACTION', 'layer4protocol,PROTOCOL', 'service_obj_name,STRING', 'source_condition_type,SOURCE_CONDITION', 'source_ip,CIDR', 'source_mask,IP', 'source_obj_name,STRING', 'source_port_operator,PORT_OPERATORS', 'source_port,STRING', 'dest_condition_type,DEST_CONDITION', 'dest_ip,CIDR', 'dest_mask,IP', 'dest_obj_name,STRING', 'dest_port_operator,PORT_OPERATORS', 'dest_port,STRING', 'match_packets,MATCH_PKTS', 'precedence,STRING', 'extra_options,EXTRA_OPTIONS']
        ACTION = ["permit","deny"]
        SOURCE_CONDITION = ["any","host","object-group","addrgroup"]
        DEST_CONDITION = ["any","host","object-group","addrgroup"]
        PORT_OPERATORS = ["eq","gt","lt","neq","range"]
        MATCH_PKTS = ["dscp","fragments","log-input","option","precedence","time-range","tos","ttl","echo","echo-reply","tracked", "ttl-exceeded", "port-unreachable", "established"]
        PROTOCOL = ["object-group", "ahp", "eigrp", "esp", "gre", "icmp", "igmp", "ip", "ipinip", "nos", "ospf", "pcp", "pim", "tcp", "tcp-udp", "udp"]
        EXTRA_OPTIONS = ["log"]
        PORT = ["bgp", "chargen", "cmd", "daytime", "discard", "domain", "drip", "echo", "exec", "finger", "ftp", "ftp-data", "gopher", "hostname", "ident", "irc", "klogin", "kshell", "login", "lpd", "nntp", "onep-plain", "onep-tls", "pim-auto-rp","pop2", "pop3", "smtp", "sunrpc", "tacacs", "talk", "telnet", "time", "uucp", "whois", "www", "msrpc", "biff", "bootpc", "bootps", "dnsix", "isakmp", "msrpc", "mobile-ip", "nameserver", "netbios-dgm", "netbios-ns", "netbios-ss", "non500-isakmp", "ntp", "rip", "snmp", "snmptrap", "syslog", "tftp", "who", "xdmcp"]

        try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(block.getTokens(), 0, None)
            tokens = block.getTokens()
            tokens = Joiner.on(" ").join(block.getTokens())
            tokens = tokens.split(" ")
            print tokens
            found = False
            for token in tokens:
                for acl_action in ACTION:
                    if token == acl_action:
                        found = True
            if not found:
                util.log_debug('Does not look like a valid acl rule. rule = %s' % (tokens))
                return

            i = 1
            for j in range(i,len(tokens)):
                if j > 0 and j == len(tokens)-1:
                    if tokens[j-1] in ACTION and InetAddressUtils.isIPv4Address(tokens[j]):
                        tokens.insert(j, 'host')
                        break
                else:
                    if tokens[j-1] in ACTION and InetAddressUtils.isIPv4Address(tokens[j]) and not InetAddressUtils.isIPv4Address(tokens[j+1]):
                        tokens.insert(j, 'host')
                        break
            util.log_info(tokens)
            decoderhandler.addTokenValue("$name", Joiner.on(" ").join(tokens))

            i = 0
            cidr_pattern = '^(\d{1,3}\.){3}\d{1,3}(/\d\d)$'
            host = False
            host_dest = False
            len_token = 0
            for token in range(len_token,len(tokens)):
                if len_token == token:
                    len_token += 1
                    for j in range(i,len(acl_dict)):
                        options = acl_dict[j].split(',')
                        yang_entity = options[0].replace('_', '-')
                        i+=1
                        if options[1] == 'INT':
                            if decoderhandler.isValidInteger(tokens[token]):
                                util.log_info("1" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'ACTION':
                            if tokens[token] in ACTION:
                                util.log_info("2" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'PROTOCOL':
                            if tokens[token] in PROTOCOL:
                                util.log_info("3" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                if tokens[token] != 'object-group':
                                    i+=1
                                break
                        elif options[1] == 'STRING':
                            if not InetAddressUtils.isIPv4Address(tokens[token]) and tokens[token] not in SOURCE_CONDITION and tokens[token] not in PORT_OPERATORS and tokens[token] not in MATCH_PKTS and tokens[token] not in PROTOCOL and tokens[token] not in EXTRA_OPTIONS and re.search(cidr_pattern, tokens[token]) is None:
                                util.log_info("4" + yang_entity + ":" + tokens[token])
                                if tokens[token].isdigit() or tokens[token] in PORT:
                                    all_ports = tokens[token]
                                    for custom_port in range(len_token, len(tokens)):
                                        if tokens[custom_port].isdigit() or tokens[custom_port] in PORT:
                                            all_ports += ' ' + tokens[custom_port]
                                            len_token += 1
                                        else:
                                            break
                                    util.log_info("4_1" + yang_entity + ":" + all_ports)
                                    decoderhandler.addTokenValue(yang_entity, all_ports)
                                else:
                                    util.log_info("4_2" + yang_entity + ":" + tokens[token])
                                    decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'SOURCE_CONDITION':
                            if tokens[token] in SOURCE_CONDITION:
                                util.log_info("5" + yang_entity + ":" + tokens[token])
                                if tokens[token] == 'any':
                                    i+=2
                                elif tokens[token] == 'host':
                                    host = True
                                elif tokens[token] == 'object-group':
                                    tokens[token] = 'objectgroup'
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'CIDR':
                            if InetAddressUtils.isIPv4Address(tokens[token]):
                                util.log_info("13" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                            elif re.search(cidr_pattern, tokens[token]) is not None:
                                util.log_info("14" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                i+=1
                                break
                        elif options[1] == 'IP':
                            prev_yang_entity = acl_dict[j-1].split(',')[0].replace('_', '-')
                            if InetAddressUtils.isIPv4Address(tokens[token]) and not host and prev_yang_entity == 'source-ip':
                                util.log_info("6" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                if yang_entity == 'source-mask':
                                    util.log_info("7" + yang_entity + ":" + tokens[token])
                                    decoderhandler.addTokenValue('source-condition-type', 'cidr')
                                break
                            elif InetAddressUtils.isIPv4Address(tokens[token]) and not host_dest and prev_yang_entity == 'dest-ip':
                                util.log_info("6_1" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                if yang_entity == 'dest-mask':
                                    util.log_info("8" + yang_entity + ":" + tokens[token])
                                    decoderhandler.addTokenValue('dest-condition-type', 'cidr')
                                break
                        elif options[1] == 'PORT_OPERATORS':
                            if tokens[token] in PORT_OPERATORS:
                                util.log_info("9" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'DEST_CONDITION':
                            if tokens[token] in DEST_CONDITION:
                                util.log_info("10" + yang_entity + ":" + tokens[token])
                                if tokens[token] == 'any':
                                    i+=2
                                elif tokens[token] == 'host':
                                    host_dest = True
                                elif tokens[token] == 'object-group':
                                    tokens[token] = 'objectgroup'
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'MATCH_PKTS':
                            if tokens[token] in MATCH_PKTS:
                                util.log_info("11" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break
                        elif options[1] == 'EXTRA_OPTIONS':
                            if tokens[token] in EXTRA_OPTIONS:
                                util.log_info("12" + yang_entity + ":" + tokens[token])
                                decoderhandler.addTokenValue(yang_entity, tokens[token])
                                break

        except Exception:
            traceback.print_exc()