#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class StaticRouteNextHopInterfaceTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('StaticRouteNextHopInterfaceTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getCurrentIndex()
            util.log_debug('The value is = %s' %(value))
            if util.isIpAddress(value):
                tokName = tokenText
                if "/" in tokName:
                    tokName = tokName.rsplit('/', 1)[0] + "/next-hop-ip"
                    util.log_debug('Token Name = %s' %(tokName))
                else:
                    tokName = "$next-hop-ip"
                util.log_debug('Final Token Name = %s' %(tokName))
                decoderhandler.addTokenValue(tokName, value)
                return 1
            decoderhandler.addTokenValue(tokenText, value)
            return 1
        except Exception:
            traceback.print_exc()

    def matchToken(self, cpc, configToken, idx, tokens):
        tok = tokens.get(idx)
        if util.isIpAddress(tok):
            return -1
        return 1