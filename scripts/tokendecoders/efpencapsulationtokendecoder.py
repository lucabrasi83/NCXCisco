from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class EfpEncapsulationTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing EfpEncapsulationTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('EfpEncapsulationTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("Block is : ",decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_debug("Text :",tokenText)
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_debug("Value :",tokenValue)
        except Exception:
            traceback.print_exc()
