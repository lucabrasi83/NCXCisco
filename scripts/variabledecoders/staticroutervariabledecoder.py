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
from ncxparser import tokendecoderhandler, util, parser
import traceback

ACCESS_LIST = ["ip", "access-list"]
class StaticRouterVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('CiscoStaticRouterVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 2, None)
            self.parseVrf(dc, cursor)
            self.parseNetwork(dc, cursor)
            self.parseInterfaceName(dc, cursor)
            self.parseNextHop(dc, cursor)
            self.parseName(dc, cursor)
            self.parseTag(dc, cursor)
            self.parseMetric(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseVrf(self,dc,cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseVrf')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
           return
        if cursor.getNextToken() == "vrf":
            util.log_debug('CiscoStaticRouterVariableDecoder(parseVrf) next token is vrf')
            cursor.advance()
            if not InetAddressUtils.isIPv4Address(cursor.getNextToken()):
                util.log_debug('CiscoStaticRouterVariableDecoder(parseVrf): next token is = %s' %(cursor.getNextToken()))
                decoderhandler.addTokenValue("../../name", cursor.getNextToken())
                cursor.advance()

    def parseNetwork(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseNetwork')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        util.log_debug('CiscoStaticRouterVariableDecoder(parseNetwork): next token is = %s' %(cursor.getNextToken()))
        decoderhandler.addTokenValue("dest-ip-address", cursor.getNextToken())
        cursor.advance()
        if not cursor.hasNext():
            return
        util.log_debug('CiscoStaticRouterVariableDecoder(parseNetwork): dest-mask next token is = %s' %(cursor.getNextToken()))
        decoderhandler.addTokenValue("dest-mask", cursor.getNextToken())
        cursor.advance()

    def parseInterfaceName(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseInterfaceName')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if not InetAddressUtils.isIPv4Address(cursor.getNextToken()):
            util.log_debug('CiscoStaticRouterVariableDecoder(parseInterfaceName): interface-name next token is = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("interface-name", cursor.getNextToken())
            cursor.advance()

    def parseNextHop(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseNextHop')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        util.log_debug('CiscoStaticRouterVariableDecoder(parseNextHop): next-hop-ip token is = %s' %(cursor.getNextToken()))
        decoderhandler.addTokenValue("next-hop-ip", cursor.getNextToken())
        cursor.advance()

    def parseName(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseName')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        next = cursor.getNextToken()
        if "name" == next:
            cursor.advance()
            util.log_debug('CiscoStaticRouterVariableDecoder(parseName) next is name and next token = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("name", cursor.getNextToken())
            cursor.advance()
        if "tag" == next:
            cursor.advance()
            util.log_debug('CiscoStaticRouterVariableDecoder(parseName) tag is next and next token = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("tag", cursor.getNextToken())
            cursor.advance()
        if "name" != next and "tag" != next and next is not None:
            util.log_debug('CiscoStaticRouterVariableDecoder(parseName) metric next token = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("metric", cursor.getNextToken())
            cursor.advance()

    def parseTag(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseTag')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        next = cursor.getNextToken()
        util.log_debug('CiscoStaticRouterVariableDecoder(parseTag) Next = %s' %(next))
        if "tag" == next:
            cursor.advance()
            util.log_debug('CiscoStaticRouterVariableDecoder(parseTag) tag is next = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("tag", cursor.getNextToken())
            cursor.advance()
        if "name" == next:
            cursor.advance()
            util.log_debug('CiscoStaticRouterVariableDecoder(parseTag) name is next = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("name", cursor.getNextToken())
            cursor.advance()
        if "name" != next and "tag" != next and next is not None:
            util.log_debug('CiscoStaticRouterVariableDecoder(parseTag) metric next token = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("metric", cursor.getNextToken())
            cursor.advance()

    def parseMetric(self, dc, cursor):
        util.log_debug('CiscoStaticRouterVariableDecoder: parseMetric')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        util.log_debug('Has cursor has next token = %s' %(cursor.hasNext()))
        if not cursor.hasNext():
            return
        next = cursor.getNextToken()
        util.log_debug('CiscoStaticRouterVariableDecoder(parseMetric) Next = %s' %(next))
        if "name" != next and "tag" != next and next is not None:
            decoderhandler.addTokenValue("metric", cursor.getNextToken())
            cursor.advance()
        if not cursor.hasNext():
            return
        else:
            nexttk = cursor.getNextToken()
            util.log_debug('CiscoStaticRouterVariableDecoder(parseMetric) nexttk = %s' %(nexttk))
            if "tag" == nexttk:
                cursor.advance()
                util.log_debug('CiscoStaticRouterVariableDecoder(parseMetric) Nextoken is Tag = %s' %(cursor.getNextToken()))
                decoderhandler.addTokenValue("tag", cursor.getNextToken())
                cursor.advance()
            if "name" == nexttk:
                cursor.advance()
                util.log_debug('CiscoStaticRouterVariableDecoder(parseMetric) Nextoken is name = %s' %(cursor.getNextToken()))
                decoderhandler.addTokenValue("name", cursor.getNextToken())
                cursor.advance()
