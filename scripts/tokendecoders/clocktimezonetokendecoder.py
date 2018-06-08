from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class ClockTimezoneTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing ClockTimezoneTokenDecoder')
        
    def decodeToken(self, dc):
        try:
            util.log_info('ClockTimezoneTokenDecoder: Decoding token')
            util.log_info('DC Value: %s' % dc)
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            if 'clock' not in str(block):
                decoderhandler.addTokenValue("timezone", "UTC")
                return
        except Exception:
            decoderhandler.addTokenValue("timezone", "UTC")
            traceback.print_exc()
