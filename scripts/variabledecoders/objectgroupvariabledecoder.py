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

class ObjectGroupVariableDecoder(parser.DefaultVariableDecoder):

    OBJECT_LIST = ["object-group"]

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('ObjectGroupVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            if AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.OBJECT_LIST):
               self.processAccessList(cpc, dc, context, decoderhandler.getCurrentBlock())
               return
            self.processNetwork(cpc, dc, context, decoderhandler.getCurrentBlock())
        except Exception:
            traceback.print_exc()

    def processAccessList(self, cpc, dc, context, block):
        util.log_debug('ObjectGroupVariableDecoder: processAccessList')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        cursor = util.TokenCursor(block.getTokens(), 1, None)
        objectType = ''
        objectName = ''
        objectType = cursor.getNextToken()
        cursor.advance()
        objectName = cursor.getNextToken()
        decoderhandler.addTokenValue("../../type", objectType)
        decoderhandler.addTokenValue("../../name", objectName)

    def processNetwork(self, cpc, dc, context, block):
        util.log_debug('ObjectGroupVariableDecoder: processNetwork')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        cursor = util.TokenCursor(block.getTokens(), 0, None)
        host = cursor.getNextToken()
        cursor.advance()
        ip = cursor.getNextToken()
        cursor.advance()
        if "host" == host:
            decoderhandler.addTokenValue("host", ip)
            decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))
            return
        if InetAddressUtils.isIPv4Address(host):
            decoderhandler.addTokenValue("ip-address", host)
            decoderhandler.addTokenValue("netmask", ip)
            decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))
            return
        if "group-object" == host:
            decoderhandler.addTokenValue("group-object", ip)
            decoderhandler.addTokenValue("name", Joiner.on(" ").join(block.getTokens()))
            return
