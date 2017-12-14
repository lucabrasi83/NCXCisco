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
import traceback

class VtyVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('VtyVariableDecoder: Decoding variables for complete line vty configurations block')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self.parseName(dc, cursor);
            self.parseAcl(dc, cursor);
            self.parseAuthType(dc, cursor);
            self.parseTimeOut(dc, cursor);
            self.parseLogging(dc, cursor);
            self.parseHistorySize(dc, cursor);
            self.parsePrivilegeLevel(dc, cursor);
            self.parseTransportType(dc, cursor);
        except Exception:
            traceback.print_exc()

    def parseName(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: parseName will parse the value for Name, minvty and maxvty')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "line" == cursor.getNextToken():
            decoderhandler.addTokenValue("name", Joiner.on(" ").join(decoderhandler.getCurrentBlock().getTokens()))
            cursor.advance()
            cursor.advance()
        else:
            return
        if not cursor.hasNext():
            return
        else:
            decoderhandler.addTokenValue("min-vty", cursor.getNextToken())
            cursor.advance()
        if not cursor.hasNext():
            return
        else:
            decoderhandler.addTokenValue("max-vty", cursor.getNextToken())
            cursor.advance()

    def parseAcl(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: parseAcl will parse the ACL deatils')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "access-class" == cursor.getNextToken():
            cursor.advance()
            decoderhandler.addTokenValue("acl-rule-number", cursor.getNextToken())
            cursor.advance()
            cursor.advance()
            if cursor.hasNext():
                cursor.advance()
                decoderhandler.addTokenValue("vrf", "vrf-also")
            else:
            	return
        else:
            return

    def parseAuthType(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: parseAuthType will parse the Authentication Type')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "login" == cursor.getNextToken():
            cursor.advance()
            #if "local" == cursor.getNextToken() or "synchronous" == cursor.getNextToken():
            if "local" == cursor.getNextToken():
            	decoderhandler.addTokenValue("login-local", "true")
            else:
                cursor.advance()
                decoderhandler.addTokenValue("auth-type", cursor.getNextToken())
                cursor.advance()
        else:
            return
                
    def parseTimeOut(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: TimeOut will parse the time out no.')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "exec-timeout" == cursor.getNextToken():
            cursor.advance()
            decoderhandler.addTokenValue("timeout", cursor.getNextToken())
            cursor.advance()
        else:
            return

    def parseLogging(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: Logging synchronous enabled or not')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "logging" == cursor.getNextToken():
            cursor.advance()
            if "synchronous" == cursor.getNextToken():
                decoderhandler.addTokenValue("logging-synchronous", "true")
        else:
            return

    def parseHistorySize(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: History Size parsing')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "history" == cursor.getNextToken():
            cursor.advance()
            if "size" == cursor.getNextToken():
                cursor.advance()
                decoderhandler.addTokenValue("history-size", cursor.getNextToken())
        else:
            return

    def parsePrivilegeLevel(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: Privilege Level parsing')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "privilege" == cursor.getNextToken():
            cursor.advance()
            if "level" == cursor.getNextToken():
                cursor.advance()
                decoderhandler.addTokenValue("privilege-level", cursor.getNextToken())
        else:
            return

    def parseTransportType(self, dc, cursor):
        util.log_debug('VtyVariableDecoder: parseTransportType will parse the transport type')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "transport" == cursor.getNextToken():
            cursor.advance()
            if "input" == cursor.getNextToken():
                cursor.advance()
                input_value = ""
                while cursor.hasNext():
                        input_value= input_value + " "+ cursor.getNextToken()
                        cursor.advance()
                decoderhandler.addTokenValue("transport-types-in", input_value.strip())
            if "output" == cursor.getNextToken():
                cursor.advance()
                output_value = ""
                while cursor.hasNext():
                        output_value= output_value + " "+ cursor.getNextToken()
                        cursor.advance()
                decoderhandler.addTokenValue("transport-types-out", output_value.strip())
        else:
            return