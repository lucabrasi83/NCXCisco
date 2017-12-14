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
from org.apache.http.conn.util import InetAddressUtils
import traceback



class SlaDestinationIpTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing SlaDestinationIpTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('SlaDestinationPortTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            value = decoderhandler.getValueAtCurrentIndex()
            #util.log_debug('Value = %s' %(value))
            #dest_port_pattern = '^\d+$'
            #dest_port_match = re.search(dest_port_pattern, value)

            if InetAddressUtils.isIPv4Address(value):
                dc.addTokenValue(token.getText(), value)
                return 1
            else:
                return -1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1

    def isMultilineDecoder(self):
        return False