from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback

class SecondaryNetmaskTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing SecondaryNetmaskTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('SecondaryNetmaskTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            command_block = decoderhandler.getCurrentBlockTokens()
            raw_block = decoderhandler.getCurrentBlock()
            string_block = str(raw_block)
            util.log_info("Secondary Netmask Block is : ",decoderhandler.getCurrentBlock())
            if "secondary" in string_block:
                decoderhandler.addTokenValue("netmask", command_block[3])
                return 1
            else:
                return -1
        except Exception:
            traceback.print_exc()
