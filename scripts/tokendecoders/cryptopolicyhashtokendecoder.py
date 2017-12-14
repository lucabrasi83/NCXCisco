#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, util, decoderutil
from ncxparser.tokendecoders import defaulttokendecoder
import traceback
class CryptoPolicyHashTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('CryptoPolicyHashTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = decoderhandler.getToken()
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('The value: = %s' %(value))
            value = value.upper()
            if "SHA" == value:
                value = "SHA1"
            decoderhandler.addTokenValue(token.getText(), value)
            return 1
        except Exception:
            traceback.print_exc()