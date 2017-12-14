#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2017-2018 Anuta Networks, Inc. All Rights Reserved.

##################################################################################
########      #    #     # #   # #######    #			       ###
########     # #   # #   # #   #    #      # #                                 ###
########    #####  #   # # #   #    #     #####                                ###
########   #     # #     #   #      #    #     #  Created by ndilip 12/07/2017 ###
##################################################################################

from org.apache.http.conn.util import InetAddressUtils
from com.anuta.util import AnutaStringUtils
from ncxparser import parser, tokendecoderhandler, util
from com.google.common.base import Joiner
import traceback
import re


class RouterBgpRedistVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('RouterBgpRedistVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            tokens = Joiner.on(" ").join(block.getTokens())
            tokens = tokens.split(" ")
            print tokens
            if "redistribute" not in tokens[0]:
                util.log_debug('Does not look like a valid redistribute. redistribute = %s' % (tokens))
                return
            decoderhandler.addTokenValue("protocol", tokens[1])
            if tokens[1] == 'ospf':
                decoderhandler.addTokenValue("ospf-process-id", tokens[2])
            elif tokens[1] == 'eigrp':
                decoderhandler.addTokenValue("eigrp-process-id", tokens[2])
            for i in range(1,len(tokens)):
                i+=1
                if tokens[i] == "metric":
                    decoderhandler.addTokenValue("metric", tokens[i+1])
                if tokens[i] == "internal":
                    decoderhandler.addTokenValue("ospf-internal", "true")
                if tokens[i] == "external":
                    if tokens[i+1] == "1":
                        decoderhandler.addTokenValue("ospf-external1", "1")
                    elif tokens[i+1] == "2":
                        decoderhandler.addTokenValue("ospf-external2", "2")
                    if tokens[i+2] == "2":
                        decoderhandler.addTokenValue("ospf-external2", "2")
                if tokens[i] == 'route-map':
                    decoderhandler.addTokenValue("route-map", tokens[i+1])
               
                    


        except Exception:
            traceback.print_exc()
