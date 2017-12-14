#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, util, decoderutil
from ncxparser.tokendecoders import greedytokendecoder
import traceback

class RouteMapMatchConditionTokenDecoder(greedytokendecoder.GreedyTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('Entering into RouteMapMatchConditionTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            ret = super(RouteMapMatchConditionTokenDecoder, self).decodeToken(dc)
            util.log_debug('The return value(RouteMapMatchConditionTokenDecoder): = %s' %(ret))
            if ret <= 0:
                return ret
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 1, None)
            tok = cursor.getNextToken()
            util.log_debug('The Token(RouteMapMatchConditionTokenDecoder) value is : = %s' %(tok))
            if "ip" == tok:
                cursor.advance()
                if "address" == cursor.getNextToken():
                    cursor.advance()
                    if "prefix-list" == cursor.getNextToken():
                        decoderhandler.addTokenValue("condition-type", "prefix-list")
                        cursor.advance()
                        util.log_debug('The return value under "prefix-list" if block is: = %s' %(ret))
                        return ret
                    decoderhandler.addTokenValue("condition-type", "address")
                    cursor.advance()
                    util.log_debug('The final return value under "address" if block is: = %s' %(ret))
                    return ret

            conditionType = cursor.getNextToken()
            if conditionType is not None:
                tokenName = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "condition-type" )
                util.log_debug('The tokenName under if block is: = %s' %(tokenName))
                util.log_debug('The value under if block for conditionType is: = %s' %(conditionType))
                decoderhandler.addTokenValue(tokenName, conditionType)
            util.log_debug('The final return value is: = %s' %(ret))
            return ret
        except Exception:
            traceback.print_exc()
