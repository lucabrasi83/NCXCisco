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
import re

class IpSLAResponderTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing IpSLAResponderTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('IpSLAResponderTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            if value == "responder":
                decoderhandler.addTokenValue("is-responder", "true")
            else:
                decoderhandler.addTokenValue("is-responder", "false")
            return 1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1


    def isMultilineDecoder(self):
        return False

class IpSlaResponderOperationTypeTokenDecoder(tokendecoder.AbstractTokenDecoder):
    operation_types = ["auto-register", "tcp-connect", "twamp", "udp-echo"]
    def __init__(self):
        util.log_info('Initializing IpSlaResponderOperationTypeTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('IpSlaResponderOperationTypeTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            if value in self.operation_types:
                decoderhandler.addTokenValue("operation-type", value)
                return 1
            else:
                util.log_info("Given Value: "+str(value)+ "not in operation_types")
                return -1
            
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        util.log_debug('operation-type-matchtokenValue = %s' %(value))
        if value in self.operation_types:
            return 1
        else:
            return -1

    def isMultilineDecoder(self):
        return False