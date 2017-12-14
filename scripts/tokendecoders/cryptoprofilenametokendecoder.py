from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class CryptoProfileNameTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('CryptoProfileNameTokenDecoder: Initializing crypto profile name')

    def decodeToken(self, dc):
        try:
            util.log_info('CryptoProfileNameTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            ike_profile_name = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Ike Profile Name = %s' %(ike_profile_name))
            decoderhandler.addTokenValue("ike-profile-name", ike_profile_name)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            iskamp_match = re.search('isakmp', lines[0])
            if iskamp_match is not None:
                decoderhandler.addTokenValue("ike-version", "IKEV1")
            ikev2_match = re.search('ikev2', lines[0])
            if ikev2_match is not None:
                decoderhandler.addTokenValue("ike-version", "IKEV2")
        except Exception:
            traceback.print_exc()
