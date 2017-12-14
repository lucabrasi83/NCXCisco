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
from org.apache.http.conn.util import InetAddressUtils
import traceback

class CryptoProfileMatchIpAddressTokenDecoder(greedytokendecoder.GreedyTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('CryptoProfileMatchIpAddressTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            cursor = util.TokenCursor(None, -1, dc)
            ipAddress = cursor.getNextToken()
            util.log_debug('IpAddress = %s' %(ipAddress))
            cursor.advance()
            decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(tokenText, "ip-address"), ipAddress)
            value = cursor.getNextToken()
            util.log_debug('Value = %s' %(value))
            if value is None:
                return decoderhandler.getSearchTokens().size() - decoderhandler.getCurrentIndex()
            if (InetAddressUtils.isIPv4Address(value)):
                decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(tokenText, "netmask"), value)
                cursor.advance()
                value = cursor.getNextToken()
            if value is not None:
                decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(tokenText, "vrf-name"), value)
            return decoderhandler.getSearchTokensSize() - decoderhandler.getCurrentIndex()
        except Exception:
            traceback.print_exc()