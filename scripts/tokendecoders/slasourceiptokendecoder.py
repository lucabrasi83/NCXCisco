from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
from org.apache.http.conn.util import InetAddressUtils
import traceback
import re

class SlaSourceIpTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing SlaSourceIpTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('SlaSourceIpTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("TokenText : ",decoderhandler.getTokenText())
            tokenText = decoderhandler.getTokenText()
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_info('Value = %s' %(tokenValue))
            decoderhandler.addTokenValue(tokenText,tokenValue)
            ##########
            # block = decoderhandler.getCurrentBlock()
            # lines = block.toString().split("\n")
            # lines = [line.strip(' ') for line in lines]
            # for each_line in lines:
            #     words = each_line.split(" ")
            #     for word in range(0, len(words)):
            #         if words[word] == "num-packets":
            #             decoderhandler.addTokenValue("num-packets", words[word+1])
            #         elif words[word] == "interval":
            #             decoderhandler.addTokenValue("interval", words[word+1])
            #         elif words[word] == "source-port":
            #             decoderhandler.addTokenValue("source-port", words[word+1])
            ##########
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1

    def isMultilineDecoder(self):
        return False
