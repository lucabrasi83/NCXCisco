#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2017-2018 Anuta Networks, Inc. All Rights Reserved.

###################################################################################
########      @    @     @ @   @ @@@@@@@@    @                                  ###
########     @ @   @ @   @ @   @    @@      @ @                                 ###
########    @@@@@  @   @ @ @   @    @@     @@@@@                                ###
########   @     @ @     @   @      @@    @     @  Created by ndilip 15/07/2017 ###
###################################################################################

from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
from com.google.common.base import Joiner
import traceback
import re


class PolicyMapRandomTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing PolicyMapRandomTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('PolicyMapRandomTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)
            block = decoderhandler.getCurrentBlock()

            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            detect_pattern = '^random-detect$'
            dscp_tunnel_pattern = '^set dscp tunnel'
            police_rate_percent_pattern = '^police rate percent'
            set_dscp_pattern = '^set dscp'
            police_rate_percent_found = False
            dscp_tunnel_found = False
            set_dscp_found = False

            for line in lines:
                detect_match = re.search(detect_pattern, line)
                if detect_match is not None:
                    decoderhandler.addTokenValue("random-detect", "default")

                dscp_tunnel_match = re.search(dscp_tunnel_pattern, line)
                if dscp_tunnel_match is not None:
                    decoderhandler.addTokenValue("is-dscp-tunnel", "true")
                    dscp_tunnel_found = True

                police_rate_percent_match = re.search(police_rate_percent_pattern, line)
                if police_rate_percent_match is not None:
                    police_rate_percent_found = True

                set_dscp_match = re.search(set_dscp_pattern, line)
                if set_dscp_match is not None:
                    set_dscp_found = True
                    dscp_value = line.split(' ')[-1]


            if not dscp_tunnel_found:
                decoderhandler.addTokenValue("is-dscp-tunnel", "false")

            if police_rate_percent_found:
                decoderhandler.addTokenValue("bit-rate", "")

            if set_dscp_found:
                decoderhandler.addTokenValue("dscp-value", dscp_value)

            return 1
        except Exception:
            traceback.print_exc()
