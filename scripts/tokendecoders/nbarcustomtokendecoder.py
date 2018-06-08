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
import traceback

class NbarCustomTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing NbarCustomTokenDecoder')

    def decodeToken(self, dc):
        try:

            util.log_info('NbarCustomTokenDecoder: Decode token Custom NBAR signatures')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info("NBAR Custom: " + str(lines))

            commands = []
            for cmd in lines:
                commands.extend(cmd.split(' '))
                
            if "http" in commands:
                for idx, word in enumerate(commands):
                    if word == "id":
                        decoderhandler.addTokenValue("id", commands[idx + 1 % len(commands)])
                    elif word == "method":
                        decoderhandler.addTokenValue("http-method", commands[idx + 1 % len(commands)])
                    # elif word == "user-agent":
                    #     decoderhandler.addTokenValue("http-user-agent", commands[idx + 1 % len(commands)])
                    elif word == "cookie":
                        decoderhandler.addTokenValue("http-cookie", commands[idx + 1 % len(commands)])
                    # elif word == "url":
                    #     decoderhandler.addTokenValue("http-url", commands[idx + 1 % len(commands)])
            
        except Exception:
            traceback.print_exc()

    