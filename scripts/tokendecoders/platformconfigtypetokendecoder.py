from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class PlatformConfigTypeTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('PlatformConfigTypeTokenDecoder: Initializing platform')

    def decodeToken(self, dc):
        try:
            util.log_info('PlatformConfigTypeTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            config = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Configure = %s' %(config))
            decoderhandler.addTokenValue("configure", config)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")[0].strip(' ')
            decoderhandler.addTokenValue("id", lines)
            
        except Exception:
            traceback.print_exc()
