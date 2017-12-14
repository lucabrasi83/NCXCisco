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
########   @     @ @     @   @      @@    @     @  Created by ndilip 12/07/2017 ###
###################################################################################

from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
from com.google.common.base import Joiner
import traceback
import re


class RouterEigrpAfIntTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing RouterEigrpAfIntTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('RouterEigrpAfIntTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)
            block = decoderhandler.getCurrentBlock()

            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            passive_pattern = '^passive-interface$'
            no_passive_pattern = '^no passive-interface$'
            split_horizon_pattern = '^split-horizon$'
            no_split_horizon_pattern = '^no split-horizon$'
            stub_site_pattern = '^stub-site wan-interface$'
            stub_site_found = False
            split_horizon_found = False
            no_split_horizon_found = False

            for line in lines:
                passive_match = re.search(passive_pattern, line)
                if passive_match is not None:
                    decoderhandler.addTokenValue("passive-interface", "true")

                no_passive_match = re.search(no_passive_pattern, line)
                if no_passive_match is not None:
                    decoderhandler.addTokenValue("passive-interface", "false")

                split_horizon_match = re.search(split_horizon_pattern, line)
                if split_horizon_match is not None:
                    decoderhandler.addTokenValue("split-horizon", "true")
                    split_horizon_found = True

                no_split_horizon_match = re.search(no_split_horizon_pattern, line)
                if no_split_horizon_match is not None:
                    decoderhandler.addTokenValue("split-horizon", "false")
                    no_split_horizon_found = True

                stub_site_match = re.search(stub_site_pattern, line)
                if stub_site_match is not None:
                    decoderhandler.addTokenValue("stub-site", "true")
                    stub_site_found = True

            if not stub_site_found:
                decoderhandler.addTokenValue("stub-site", "false")

            if not split_horizon_found and not no_split_horizon_found:
                decoderhandler.addTokenValue("split-horizon", "true")

            return 1
        except Exception:
            traceback.print_exc()

