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
import traceback,re

class NtpServerPreferTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing NtpServerPreferTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('NtpServerPreferTokenDecoder: ')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            print 'Token text = %s' %(tokenText)
            value = decoderhandler.getValueAtCurrentIndex()
            print 'Value1 = %s' %(value)
            decoderhandler.addTokenValue(tokenText,value)
            current_block = decoderhandler.getCurrentBlock()
            block = str(current_block)
            util.log_info("current_block:"+str(block.split()))
            if "prefer" in block:
                decoderhandler.addTokenValue("../prefer","true")
            else:
                decoderhandler.addTokenValue("../prefer","false")
           
        except Exception:
            traceback.print_exc()

    def isMultilineDecoder(self):
        return False
