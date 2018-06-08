from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class RouterBgpAllowasinTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing RouterBgpAllowasinTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('RouterBgpAllowasinTokenDecoder: Decode token for Bgp neighbor ip-address leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            block = decoderhandler.getCurrentBlock()
            util.log_debug("Block : ",block.toString())
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            decoderhandler.addTokenValue(tokenText, value)
            if "allowas-in" in block.toString():
                util.log_debug("Allowas-in Present")
                decoderhandler.addTokenValue("allowas-in", "true")
            else:
                util.log_debug("Allowas-in not Present")
                decoderhandler.addTokenValue("allowas-in", "false")
        except Exception:
            traceback.print_exc()
            
