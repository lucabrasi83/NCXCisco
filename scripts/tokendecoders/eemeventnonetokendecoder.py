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

class EemEventNoneTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing EemEventNoneTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('EemEventNoneTokenDecoder:')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)

            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)

            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]

            for line in lines:
                if line == "event none":
                    decoderhandler.addTokenValue("../events/none", "true")

        except Exception:
            traceback.print_exc()

    def isMultilineDecoder(self):
        return False
