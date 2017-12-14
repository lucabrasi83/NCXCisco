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

class RouterOspfMetricTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def __init__(self, metricName):
        self.metricName = metricName

    def decodeToken(self, dc):
        try:
            util.log_info('RouterOspfMetricTokenDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_info('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            util.log_info('value = %s' %(value))
            return 1
        except Exception:
            traceback.print_exc()
