#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from org.apache.http.conn.util import InetAddressUtils
from ncxparser import parser, tokendecoderhandler, util
from com.anuta.util import AnutaStringUtils
from com.google.common.base import Joiner
import traceback

class ObjectGroupServiceVariableDecoder(parser.DefaultVariableDecoder):

    OBJECT_LIST = ["object-group"]

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('ObjectGroupServiceVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            if AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.OBJECT_LIST):
               self.processAccessList(cpc, dc, context, decoderhandler.getCurrentBlock())
               return
            self.processService(cpc, dc, context, decoderhandler.getCurrentBlock())
        except Exception:
            traceback.print_exc()

    def processAccessList(self, cpc, dc, context, block):
        util.log_debug('ObjectGroupServiceVariableDecoder: processAccessList')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        cursor = util.TokenCursor(block.getTokens(), 1, None)
        objectType = ''
        objectName = ''
        objectType = cursor.getNextToken()
        cursor.advance()
        objectName = cursor.getNextToken()
        if objectType == 'network':
            return
        decoderhandler.addTokenValue("../../type", objectType)
        decoderhandler.addTokenValue("../../name", objectName)

    def processService(self, cpc, dc, context, block):
        util.log_debug('ObjectGroupServiceVariableDecoder: processNetwork')
        compare = ['eq', 'lt', 'gt', 'range']
        ip_protocol_list = ['ahp', 'eigrp', 'esp', 'gre', 'icmp', 'igmp', 'ip', 'ipinip', 'nos', 'ospf', 'pcp', 'pim']
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        lines = block.toString().split("\n")
        lines = [line.strip(' ') for line in lines]
        util.log_info('BLOCK for obj service:', block)
        for line in lines:
            words = line.split(' ')
            if words[0].isdigit():
                decoderhandler.addTokenValue("name", words[0])
                decoderhandler.addTokenValue("ip-protocol", words[0])
                return
            elif words[0] in ip_protocol_list:
                decoderhandler.addTokenValue("name", words[0])
                decoderhandler.addTokenValue("protocol", words[0])
                return
            elif words[0] == 'group-object':
                util.log_debug('ObjectGroup')
            else:
                if InetAddressUtils.isIPv4Address(words[0]) or words[0] == 'host':
                    return
                decoderhandler.addTokenValue("protocol", words[0])
            if len(words)-1 >= 1:
                if words[1] == 'source':
                    decoderhandler.addTokenValue("operation", words[1])
                    if words[2] in compare:
                        decoderhandler.addTokenValue("compare", words[2])
                        decoderhandler.addTokenValue("port", words[3])
                    if words[2] == 'range':
                        decoderhandler.addTokenValue("end-port", words[4])
                    decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))
                elif words[1] in compare:
                    decoderhandler.addTokenValue("compare", words[1])
                    decoderhandler.addTokenValue("port", words[2])
                    if words[1] == 'range':
                        decoderhandler.addTokenValue("end-port", words[3])
                    decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))
                else:
                    if words[0] == 'group-object':
                        decoderhandler.addTokenValue("group-object", words[1])
                    else:
                        decoderhandler.addTokenValue("port", words[1])
                        decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))

