from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re
pattern= '^\d+$'

class VrfRouterEigrpTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        print 'Initializing VrfRouterEigrpTokenDecoder'

    def decodeToken(self, dc):
        try:
            print 'VrfRouterEigrpTokenDecoder: Decode token'
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            print 'Token text = %s' %(tokenText)
            value = decoderhandler.getValueAtCurrentIndex()
            print 'Value = %s' %(value)
            match = re.search(pattern, value)
            util.log_info("match is:", match)
            if match is not None:
                util.log_info('inside if condition')
                decoderhandler.addTokenValue("$process-id", value)
                return 1
            else:
                util.log_info('inside else condition')
                util.log_info("process-id Data type is uint16, given other data type")
                return -1
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        util.log_info('vrf-matchtokenValue = %s' %(value))
        match = re.search(pattern, value)
        util.log_info("vrf-matchtoken-match is:", match)
        if match is not None:
            util.log_info("vrf-matchtoken-if")
            return 1
        else:
            util.log_info("vrf-matchtoken-else")
            return -1

    def isMultilineDecoder(self):
        return False    