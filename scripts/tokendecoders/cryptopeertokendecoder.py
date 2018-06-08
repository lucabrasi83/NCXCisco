from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class CryptoPeerTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('CryptoPeerTokenDecoder: Initializing crypto peer')

    def decodeToken(self, dc):
        try:
            util.log_info('CryptoPeerTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info("Crypto Block Line: " + str(lines))
            iskamp_match = re.search('isakmp', lines[0])
            if iskamp_match is not None:
                decoderhandler.addTokenValue("ike-version", "IKEV1")
            decoderhandler.addTokenValue("id", lines[0])
            
        except Exception:
            traceback.print_exc()
