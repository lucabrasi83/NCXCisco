#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, parser, util
from ncxparser.tokendecoders import defaulttokendecoder
import traceback


class CiscoInterfaceNumberTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('CiscoInterfaceNumberTokenDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            name = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Name1 = %s' %(name))
            name = decoderhandler.getMatchingToken(".*[^\\d](\\d+)", name)
            util.log_debug('Name2 = %s' %(name))
            if name is not None:
                decoderhandler.addTokenValue(tokenText, name)
            else:
                raise Exception('Can not find number from %s' %(name))

            return 1
        except Exception:
            traceback.print_exc()