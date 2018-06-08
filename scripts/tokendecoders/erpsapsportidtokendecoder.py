from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class ErpsApsPortidTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing ErpsApsPortidTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('ErpsApsPortidTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("Block is : ",decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_debug("Text :",tokenText)
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_debug("Value :",tokenValue)
            if tokenValue == "port0" or tokenValue == "port1": 
                decoderhandler.addTokenValue(tokenText, tokenValue)
        except Exception:
            traceback.print_exc()
