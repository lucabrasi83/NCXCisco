#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class VrfDefTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info("Initializing VrfDefTokenDecode")

    def decodeToken(self, dc):
        try:
            util.log_info('VrfDefTokenDecoder: Decode token for Vrf-Definition-mode')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(dc.getToken().getText(), value)
            if 'definition' in decoderhandler.getSearchTokens():
                decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(dc.getToken().getText(), "vrf-definition-mode"), "true")
            else:
                decoderhandler.addTokenValue(decoderutil.DecoderUtil().makeSiblingToken(dc.getToken().getText(), "vrf-definition-mode"), "false")
            return 1
        except Exception:
            traceback.print_exc()


    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1


    def isMultilineDecoder(self):
        return False