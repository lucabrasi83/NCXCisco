from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class CryptoPeerSetAttrTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('CryptoPeerSetAttrTokenDecoder: Initializing crypto peer')

    def decodeToken(self, dc):
        try:
            util.log_info('CryptoPeerSetAttrTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            for new_line in lines:
                util.log_info("Crypto Line is: " + str(new_line))
                if new_line.__contains__('user-fqdn'):
                    util.log_info("In new line Crypto Line is: " + str(new_line))
                    decoderhandler.addTokenValue("endpoint", 'user-fqdn')
                elif new_line.__contains__('fqdn'):
                    decoderhandler.addTokenValue("endpoint", 'fqdn')
                elif new_line.__contains__('ipv4-address'):
                    decoderhandler.addTokenValue("endpoint", 'ipv4-address')
                elif new_line.__contains__('ipv6-address'):
                    decoderhandler.addTokenValue("endpoint", 'ipv6-address')
        except Exception:
            traceback.print_exc()