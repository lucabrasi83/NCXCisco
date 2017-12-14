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

class NetflowCollectIntTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing NetflowCollectIntTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('NetflowCollectIntTokenDecoder: Decode token for ipv4-option and name leaf')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            currenttokenText = decoderhandler.getCurrentBlockTokens()
            value = decoderhandler.getValueAtCurrentIndex()
            name = "_".join(currenttokenText)
            name = name.replace('-','_')
            decoderhandler.addTokenValue(tokenText, value)
            decoderhandler.addTokenValue('name', name)
        except Exception:
            traceback.print_exc()

    def isMultilineDecoder(self):
        return False
