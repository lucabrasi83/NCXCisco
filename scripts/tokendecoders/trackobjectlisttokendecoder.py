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
import re

class TrackObjectTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing TrackObjectTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('TrackObjectTokenDecoder: ')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)
            block = decoderhandler.getCurrentBlock()
            util.log_info("value of block is:%s"%(block))
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info("lines contains:%s"%(lines))
            detect_pattern1 = 'not'

            for line in lines:
                detect_match1 = re.search(detect_pattern1, line)
                if detect_match1 :
                    decoderhandler.addTokenValue("not", "true")

        except Exception:
            traceback.print_exc()

    def isMultilineDecoder(self):
        return False
