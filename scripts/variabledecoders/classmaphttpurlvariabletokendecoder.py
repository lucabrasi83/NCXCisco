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
import traceback

class ClassMapHttpUrlVariableTokenDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('ClassMapHttpUrlVariableTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            self. parseMatchTypeandName(dc, cursor)
            self.parseConditionType(dc, cursor)
            self.parseMatchValue(dc, cursor)
            self.parseUrl(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseMatchTypeandName(self, dc, cursor):
        util.log_debug('ClassMapHttpUrlVariableTokenDecoder: parseMatchTypeandName')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return

        if "class-map" == cursor.getNextToken():
            cursor.advance()
            decoderhandler.addTokenValue("../../match-type", cursor.getNextToken())
            cursor.advance()
            decoderhandler.addTokenValue("../../name", cursor.getNextToken())
            cursor.advance()

        if "match" == cursor.getNextToken():
            cursor.advance()


    def parseConditionType(self, dc, cursor):
        util.log_debug('ClassMapHttpUrlVariableTokenDecoder: parseConditionType')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "protocol" == cursor.getNextToken():
            conditiontype = cursor.getNextToken()
            decoderhandler.addTokenValue("../condition-type", conditiontype)
            cursor.advance()

    def parseMatchValue(self, dc, cursor):
        util.log_debug('ClassMapHttpUrlVariableTokenDecoder: parseMatchValue')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "http" == cursor.getNextToken():
            matchtype = cursor.getNextToken()
            decoderhandler.addTokenValue("../match-value", matchtype)
            cursor.advance()

    def parseUrl(self, dc, cursor):
        util.log_debug('ClassMapHttpUrlVariableTokenDecoder: parseUrl')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "url" == cursor.getNextToken():
            cursor.advance()
            url = cursor.getNextToken()
            decoderhandler.addTokenValue("url", url)
            cursor.advance()