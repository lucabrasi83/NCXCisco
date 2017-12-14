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

class TrackBooleanTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing BgpNeighborTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('BgpNeighborTokenDecoder: Decode token for Bgp neighbor ip-address leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            if 'ip' in decoderhandler.getCurrentBlockTokens():
		decoderhandler.addTokenValue(tokenText, 'or')
	    else:
            	util.log_debug('Token text = %s' %(tokenText))
            	value = decoderhandler.getValueAtCurrentIndex()
            	util.log_debug('Value = %s' %(value))
		decoderhandler.addTokenValue(tokenText, value)
        except Exception:
            traceback.print_exc()

    def isMultilineDecoder(self):
        return False
