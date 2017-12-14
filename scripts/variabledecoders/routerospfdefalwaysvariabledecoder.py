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
from com.google.common.base import Joiner
import traceback

class RouterOspfDefAlwaysVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('RouterOspfDefAlwaysVariableDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            util.log_info('OSPF value = %s' %(block))
            tokens = Joiner.on(" ").join(block.getTokens())
            tokens = tokens.split(" ")
            if 'always' in str(block):
                decoderhandler.addTokenValue("always", "true")
            else:
                decoderhandler.addTokenValue("always", "false")
            for i in range(1,len(tokens)):
                i+=1
                if tokens[i] == "metric":
                    decoderhandler.addTokenValue("metric", tokens[i+1])
                if tokens[i] == "metric-type":
                    decoderhandler.addTokenValue("metric-type", tokens[i+1])
                if tokens[i] == 'route-map':
                    decoderhandler.addTokenValue("route-map", tokens[i+1])
        except Exception:
            traceback.print_exc()
