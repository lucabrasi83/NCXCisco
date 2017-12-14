#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import parser, tokendecoderhandler, util
from com.google.common.base import Joiner
from org.apache.http.conn.util import InetAddressUtils
from com.anuta.api.dto.thirdparty import CidrUtils
import traceback

class RouteVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('NewRouteVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 2, None)
            self.parseNetwork(dc, cursor)
            self.parseInterfaceName(dc, cursor)
            self.parseNextHop(dc, cursor)
            self.parseName(dc, cursor)
            decoderhandler.addTokenValue("id", Joiner.on(" ").join(decoderhandler.getCurrentBlock().getTokens()))
        except Exception:
            traceback.print_exc()

    def parseNetwork(self, dc, cursor):
        util.log_debug('NewRouteVariableDecoder: parseNetwork')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        tokenvalue = cursor.getNextToken()
        if "vrf" == tokenvalue:
            cursor.advance()
            cursor.advance()
        if "/" in tokenvalue:
            decoderhandler.addTokenValue("../dest-ip-address", CidrUtils.getNetworkAddress(tokenvalue))
            decoderhandler.addTokenValue("../dest-mask", CidrUtils.getNetmaskFromCidr(tokenvalue))
            cursor.advance()
            return
        decoderhandler.addTokenValue("../dest-ip-address", cursor.getNextToken())
        cursor.advance()
        if not cursor.hasNext():
            return
        decoderhandler.addTokenValue("../dest-mask", cursor.getNextToken())
        cursor.advance()


    def parseInterfaceName(self, dc, cursor):
        util.log_debug('NewRouteVariableDecoder: will parse InterfaceName if exists else if it is a Ip-addess assign it to Next-hop-ip')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        next = cursor.getNextToken()
        if not InetAddressUtils.isIPv4Address(next):
            decoderhandler.addTokenValue("interface-name", cursor.getNextToken())
            cursor.advance()
        else:
            decoderhandler.addTokenValue("next-hop-ip", cursor.getNextToken())
            cursor.advance()


    def parseNextHop(self, dc, cursor):
        util.log_debug('NewRouteVariableDecoder: parse NextHop if it is a ip-address else will check for VRF info and assign')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if InetAddressUtils.isIPv4Address(cursor.getNextToken()):
            decoderhandler.addTokenValue("next-hop-ip", cursor.getNextToken())
            cursor.advance()
            return
        if "vrf" == cursor.getNextToken():
            cursor.advance()
            decoderhandler.addTokenValue("vrf-name", cursor.getNextToken())
            cursor.advance()

    def parseName(self, dc, cursor):
        util.log_debug('NewRouteVariableDecoder: parseName')
        if not cursor.hasNext():
            return
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        next = cursor.getNextToken()
        if "name" == next:
            cursor.advance()
            decoderhandler.addTokenValue("name", cursor.getNextToken())
            cursor.advance()
            
        elif "tag" == next:
            cursor.advance()
            decoderhandler.addTokenValue("tag", cursor.getNextToken())
            cursor.advance()
            
        elif "permanent" == next:
            decoderhandler.addTokenValue("permanent", "true")
            cursor.advance()
            
        elif "track" == next:
            cursor.advance()
            decoderhandler.addTokenValue("track", cursor.getNextToken())
            cursor.advance()
            
        elif "name" != next and "tag" != next and  "track" != next and "permanent" != next and next is not None:
            decoderhandler.addTokenValue("metric", cursor.getNextToken())
            cursor.advance()
        self.parseName(dc, cursor)
