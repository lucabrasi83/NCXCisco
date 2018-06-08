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

class ClassMapVariableTokenDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('ClassMapVariableTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            self. parseMatchTypeandName(dc, cursor)
            self.parseConditionType(dc, cursor)
            self.parseMatchValue(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseMatchTypeandName(self, dc, cursor):
        util.log_debug('ClassMapVariableTokenDecoder: parseMatchTypeandName')
        if not cursor.hasNext():
            return
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if "class-map" == cursor.getNextToken():
            cursor.advance()
            decoderhandler.addTokenValue("../match-type", cursor.getNextToken())
            cursor.advance()
            decoderhandler.addTokenValue("../name", cursor.getNextToken())
            cursor.advance()

        if "match" == cursor.getNextToken():
            cursor.advance()


    def parseConditionType(self, dc, cursor):
        util.log_debug('ClassMapVariableTokenDecoder: parseConditionType')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "dscp" == cursor.getNextToken() or "qos-group" == cursor.getNextToken() or "protocol" == cursor.getNextToken():
            conditiontype = cursor.getNextToken()
            cursor.advance()
            decoderhandler.addTokenValue("condition-type", conditiontype)
        if "access-group" == cursor.getNextToken():
            decoderhandler.addTokenValue("condition-type", cursor.getNextToken())
            cursor.advance()
            cursor.advance()
        if "ip" == cursor.getNextToken():
            cursor.advance()
            if "dscp" == cursor.getNextToken():
                decoderhandler.addTokenValue("condition-type", "ip dscp")
                global conditiontype
                conditiontype = "ip dscp"
                cursor.advance()
        if "any" == cursor.getNextToken():
            decoderhandler.addTokenValue("condition-type", cursor.getNextToken())
        if "vlan" == cursor.getNextToken():
            conditiontype = cursor.getNextToken()
            decoderhandler.addTokenValue("condition-type", cursor.getNextToken())
            cursor.advance()

    def parseMatchValue(self, dc, cursor):
        util.log_debug('ClassMapVariableTokenDecoder: parseMatchValue')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if conditiontype == "ip dscp":
            matchvalue = []
            while cursor.getNextToken() is not None:
                matchvalue.append(cursor.getNextToken())
                cursor.advance()
            matchvalue1 = " ".join(matchvalue)
            decoderhandler.addTokenValue("match-value", matchvalue1)
        if conditiontype == "dscp":
            matchvalue = []
            while cursor.getNextToken() is not None:
                matchvalue.append(cursor.getNextToken())
                cursor.advance()
            matchvalue1 = " ".join(matchvalue)
            decoderhandler.addTokenValue("match-value", matchvalue1)
        else:
            part1 = cursor.getNextToken()
            if not cursor.hasNext():
                return
            cursor.advance()
            part2 = cursor.getNextToken()
            if not cursor.hasNext():
                decoderhandler.addTokenValue("match-value", part1)
                return
            cursor.advance()
            if "traffic-class" == part2:
                decoderhandler.addTokenValue("match-value", part1)
                decoderhandler.addTokenValue("traffic-class", cursor.getNextToken())
            elif "business-relevance" == part2:
                decoderhandler.addTokenValue("match-value", part1)
                decoderhandler.addTokenValue("business-relevance", cursor.getNextToken())
            else:
                if part2 is not None:
                    part1 = part1 + " " + part2
                    decoderhandler.addTokenValue("match-value", part1)
                else:
                    decoderhandler.addTokenValue("match-value", part1)
