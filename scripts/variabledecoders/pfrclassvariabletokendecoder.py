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

class PfrClassVariableTokenDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('PfrClassVariableTokenDecoder: Entering.')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            util.log_info("BLOCK FOR PFR DECODER:", block)
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]

        except Exception:
            traceback.print_exc()