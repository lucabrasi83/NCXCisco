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


class TrafficEngTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing TrafficEngTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('TrafficEngTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            dc.addTokenValue(token.getText(), value)
            if value == 'path-option':
                cursor = util.TokenCursor(None, 0, dc)
                path_number = cursor.getNextToken(1)
                dc.addTokenValue("/path-config/path-number", path_number)
                path_type = cursor.getNextToken(2)
                dc.addTokenValue("/path-config/path-type", path_type)

            else:
                return 1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1

    def isMultilineDecoder(self):
        return False