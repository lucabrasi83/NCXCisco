from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re
pattern= '^\d+$'

class RouterEigrpTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing RouterEigrpTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('RouterEigrpTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_info('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_info('Value = %s' %(value))
            match = re.search(pattern, value)
            util.log_info("match is:", match)
            if match is not None:
                util.log_info('inside if condition')
                util.log_info("eigrp-name Data type is String, given other data type")
                return -1
            else:
                util.log_info('inside else condition')
                decoderhandler.addTokenValue("$eigrp-name", value)
                return 1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        util.log_info('Value = %s' %(value))
        match = re.search(pattern, value)
        util.log_info("match is:", match)
        if match is not None:
            util.log_info("matchtoken-if")
            return -1
        else:
            util.log_info("matchtoken-else")
            return 1

    def isMultilineDecoder(self):
        return False