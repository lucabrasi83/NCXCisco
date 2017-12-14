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

class NtpServerTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing NtpServerTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('NtpServerTokenDecoder: Decode token for Ntp server ip-address leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_info('NTP Server Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_info('NTP Server Value = %s' %(value))
            if value is not None and InetAddressUtils.isIPv4Address(value):
                decoderhandler.addTokenValue('ntp-server-address', value)
                return 1
            else:
                return -1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        if value is not None and InetAddressUtils.isIPv4Address(value):
            return 1
        else:
            return -1


    def isMultilineDecoder(self):
        return False