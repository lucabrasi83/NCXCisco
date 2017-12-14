from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class LegacyNetflowInterfaceNamesVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('LegacyNetflowInterfaceNameVariable: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getCurrentBlockTokens()
            print "This is value"
            print value
            if 'interface-names' in value:
                decoderhandler.addTokenValue("interface-names","true")
            if 'interface-names' in value:
                decoderhandler.addTokenValue("$../legacy-netflow","true")
        except Exception:
                traceback.print_exc()
