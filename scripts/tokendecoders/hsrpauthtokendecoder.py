from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class HsrpAuthTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing HsrpAuthTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('HsrpAuthTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            command_block = decoderhandler.getCurrentBlockTokens()
            raw_block = decoderhandler.getCurrentBlock()
            string_block = str(raw_block)
            util.log_info("HSRP Block is : ",decoderhandler.getCurrentBlock())
            
            if "md5" in string_block:
                if "key-string" in string_block:
                    decoderhandler.addTokenValue("auth-type", "md5-key-string")
                    decoderhandler.addTokenValue("auth-key", command_block[-2] + " " + command_block[-1])
                if "key-chain" in string_block:
                    decoderhandler.addTokenValue("auth-type", "md5-key-chain")
                    decoderhandler.addTokenValue("auth-key", command_block[-1])
            else:
                decoderhandler.addTokenValue("auth-type", "text")
                decoderhandler.addTokenValue("auth-key", command_block[-1])

        except Exception:
            traceback.print_exc()
