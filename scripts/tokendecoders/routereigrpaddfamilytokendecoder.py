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
########   @     @ @     @   @      @@    @     @  Created by ndilip 10/07/2017 ###
###################################################################################

from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
from com.google.common.base import Joiner
import traceback
import re


class RouterEigrpAddFamilyTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing RouterEigrpAddFamilyTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('RouterEigrpAddFamilyTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)
            block = decoderhandler.getCurrentBlock()

            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            nsf_pattern = '^nsf$'
            nsf_found = False
            topology_base_pattern = '^topology base$'
            topology_base_found = False
            summary_pattern = 'summary'
            summary_found = False
            redistributed_pattern = 'redistributed'
            redistributed_found = False

            for line in lines:
                nsf_match = re.search(nsf_pattern, line)
                if nsf_match is not None:
                    decoderhandler.addTokenValue("nsf", "true")
                    nsf_found = True

                topology_base_match = re.search(topology_base_pattern, line)
                if topology_base_match is not None:
                    decoderhandler.addTokenValue("topology-base", "true")
                    topology_base_found = True

                summary_match = re.search(summary_pattern, line)
                redistributed_match = re.search(redistributed_pattern, line)
                if summary_match is not None or redistributed_match is not None:
                    element = line.split(" ")
                    for j in range(3,len(element)):
                        if element[j] == 'summary':
                            decoderhandler.addTokenValue("summary", "true")
                            summary_found = True
                        elif element[j] == 'redistributed':
                            decoderhandler.addTokenValue("redistributed", "true")
                            redistributed_found = True
                        j+=1

            if not nsf_found:
                decoderhandler.addTokenValue("nsf", "false")
            if not topology_base_found:
                decoderhandler.addTokenValue("topology-base", "false")
            if not summary_found:
                decoderhandler.addTokenValue("summary", "false")
            if not redistributed_found:
                decoderhandler.addTokenValue("redistributed", "false")

            return 1
        except Exception:
            traceback.print_exc()

