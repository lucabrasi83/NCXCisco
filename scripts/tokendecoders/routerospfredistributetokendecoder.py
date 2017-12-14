#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, parser, util, decoderutil
from ncxparser.tokendecoders import defaulttokendecoder
import traceback

class RouterOspfRedistributeTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('RouterOspfRedistributeTokenDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            searchTokens = decoderhandler.getSearchTokens()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            protocol = util.safe_get(searchTokens, decoderhandler.getCurrentIndex() - 1)
            if protocol is not None:
                decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(tokenText, "protocol"), protocol)
            decoderhandler.addTokenValue(tokenText, value)
            util.log_debug('value = %s' %(value))
            return 1
        except Exception:
            traceback.print_exc()
