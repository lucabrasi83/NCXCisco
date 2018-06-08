from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback
import re

class PrefixSetMatchTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing PrefixSetMatchTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('PrefixSetMatchTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_info("Block is : ",decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_info("Text :",tokenText)
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_info("Value :",tokenValue)
            tokenValue_1 = tokenValue.strip(",")
            decoderhandler.addTokenValue(tokenText,tokenValue_1)
        except Exception:
            traceback.print_exc()
