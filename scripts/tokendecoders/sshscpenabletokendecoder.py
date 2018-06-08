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

class SSHSCPenableTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing SSHSCPenableTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('SSHSCPenableTokenDecoder: Decode token for SSHSCPenable leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getCurrentBlockTokens()
            print value
            if 'no' in value:
                pass
            else:
                decoderhandler.addTokenValue("$scp-enable", "true")
                return 1
        except Exception:
            pass

    def isMultilineDecoder(self):
        return False