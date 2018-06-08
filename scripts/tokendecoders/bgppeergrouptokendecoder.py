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

class BgpPeerGroupTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing BgpPeerGroupTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('BgpPeerGroupTokenDecoder: Decode token for BGP peer-group name leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            command_block = block.toString().split('\n')
            commands = []
            for cmds in command_block:
                commands.append(str(cmds.strip()))
            util.log_info("Commands: ",commands)
            for i in commands:
                commands_1 = i.split()
            util.log_info("Commands1: ", commands_1)
            
            if "bfd" and "fall-over" in commands_1:
                decoderhandler.addTokenValue("bfd-fall-over", "true")
            elif "no" and "bfd" and "fall-over" in commands_1:
                decoderhandler.addTokenValue("bfd-fall-over", "false")


            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            if value is not None and InetAddressUtils.isIPv4Address(value):
                return -1
            else:
                decoderhandler.addTokenValue(tokenText, value)

                bgp_boolean = ["send-community", "next-hop-self", "soft-reconfiguration", "allowas-in", "next-hop-unchanged",
                "route-reflector-client", "as-override", "weight"]

                for bgp_b in bgp_boolean:
                    if bgp_b == "weight":
                        if "weight" in commands_1:
                            decoderhandler.addTokenValue("weight", commands_1[-1])
                    elif bgp_b in commands_1:
                        decoderhandler.addTokenValue(bgp_b, "true")
                return 1
            
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        if value is not None and InetAddressUtils.isIPv4Address(value):
            return -1
        else:
            return 1


    def isMultilineDecoder(self):
        return False