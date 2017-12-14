from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class EnableSecretPasswordDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing EnableSecretPasswordDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('EnableSecretPasswordDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, tokenValue)
            command_block = decoderhandler.getCurrentBlockTokens()
            util.log_info("Block is : ",decoderhandler.getCurrentBlock())
            
            if 'enable' and 'secret' in command_block:
                decoderhandler.addTokenValue("enable-secret", "true")
            else:
                decoderhandler.addTokenValue("enable-secret", "false")
            
        except Exception:
            traceback.print_exc()
