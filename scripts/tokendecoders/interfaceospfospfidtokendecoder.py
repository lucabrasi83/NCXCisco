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
import re 


class InterfaceOspfOspfIdTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('InterfaceOspfOspfIdTokenDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('value1 = %s' %(value))
            match = re.search('^\d+$', value)
            util.log_debug('value2 = %s' %(value))
            if match is not None:
                decoderhandler.addTokenValue(tokenText, value)
            else:
                util.log_info("Can not find number from %s" % (value))
            return 1
        except Exception:
            traceback.print_exc()