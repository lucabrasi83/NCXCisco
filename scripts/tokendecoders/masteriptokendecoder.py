from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
from org.apache.http.conn.util import InetAddressUtils
import traceback

class MasterIpTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing MasterIpTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('MasterIpTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("Block is : ",decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_debug("Text :",tokenText)
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_debug("Value :",tokenValue)
            if tokenValue is not None and InetAddressUtils.isIPv4Address(tokenValue):
                decoderhandler.addTokenValue(tokenText, tokenValue)
        except Exception:
            traceback.print_exc()
