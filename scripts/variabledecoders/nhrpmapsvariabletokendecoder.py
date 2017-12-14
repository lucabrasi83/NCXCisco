#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import parser, tokendecoderhandler, util
import traceback
from com.anuta.util import AnutaStringUtils
from com.google.common.base import Joiner
from org.apache.http.conn.util import InetAddressUtils
import re

class NhrpMapsVariableTokenDecoder(parser.DefaultVariableDecoder):
    NHS_LIST = ["ip", "nhrp", "nhs"]
    MAP_MULTI = ["ip", "nhrp", "map", "multicast"]
    NHRP_MAP = ["ip", "nhrp", "map"]
    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('NhrpMapsVariableTokenDecoder: Entering.')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            util.log_info("BLOCK FOR DECODER:", block)
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            for line in lines:
                words = line.split(' ')
                if ' nbma ' in line and len(words) > 4:
                    decoderhandler.addTokenValue("nhrp-type", "nhs-nbma")
                    decoderhandler.addTokenValue("sourceip", words[3])
                    decoderhandler.addTokenValue("destip", words[5])
                elif AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.NHS_LIST) and len(words) == 4:
                    decoderhandler.addTokenValue("nhrp-type", "nhs")
                elif AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.MAP_MULTI):
                    return
                elif AnutaStringUtils.startsWith(decoderhandler.getCurrentBlockTokens(), self.NHRP_MAP):
                    decoderhandler.addTokenValue("nhrp-type", "nhs")
                    decoderhandler.addTokenValue("sourceip", words[3])
                    decoderhandler.addTokenValue("destip", words[4])

        except Exception:
            traceback.print_exc()