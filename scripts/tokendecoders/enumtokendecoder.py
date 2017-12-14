
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
from ncxparser.tokendecoders import defaulttokendecoder 

class EnumTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):
    enumMap = {}
    skipUnknown = False

    def __init__(self, tokens=[]):
        util.log_info('Initializing EnumTokenDecoder ')
        for token in tokens:
            self.enumMap[token.getName()] = token.getValue()
        pass

    def addToken(self, name, value):
        self.enumMap[name] = value
        return self

    def decodeToken(self, decoderContext):
        util.log_info('decodetoken in EnumTokenDecoder')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
        tokenText = decoderhandler.getTokenText()
        util.log_debug('TokenText = %s' %(tokenText))
        val = decoderhandler.getValueAtCurrentIndex()
        util.log_debug('Value = %s' %(val))
        if val is not None:
            enumVal = self.enumMap[val]
            if enumVal is not None:
                decoderhandler.addTokenValue(tokenText, enumVal)
            elif not self.skipUnknown:
                decoderhandler.addTokenValue(tokenText, val)

        return 1

