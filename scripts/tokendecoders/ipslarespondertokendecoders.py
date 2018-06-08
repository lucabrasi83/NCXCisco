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
            util.log_info('ResponderValue = %s' %(value))
            block = decoderhandler.getCurrentBlock()
            util.log_info('ResponderBlock = %s' %(block))
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            for line in lines:
                next_value = line.split(value)

                if len(next_value) >= 2:
                    if value == "logging" and next_value[1] == " traps":
                        decoderhandler.addTokenValue("is-logging-traps", "true")

                    if value == "enable" and next_value[1] == " reaction-alerts":
                        decoderhandler.addTokenValue("is-enable-reaction", "true")

                    if value == "server" and next_value[1] == " twamp":
                        decoderhandler.addTokenValue("is-server-twamp", "true")

                if re.search('^port ', line):
                    next_value = line.split('port ')
                    decoderhandler.addTokenValue("port", next_value[1])

                if re.search('^timer inactivity ', line):
                    next_value = line.split('timer inactivity ')
                    decoderhandler.addTokenValue("timer-inactivity", next_value[1])

            if value == "responder" or value == "logging" or value == "enable" or value == "server":
                decoderhandler.addTokenValue("key-chain", "")
            if value == "responder":
                decoderhandler.addTokenValue("is-responder", "true")

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