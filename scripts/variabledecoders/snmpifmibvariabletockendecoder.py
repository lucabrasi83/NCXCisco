from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class SnmpIfMibVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('AAAGroupVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getCurrentBlockTokens()
            print value
            if 'no' in value:
                decoderhandler.addTokenValue("snmp-ifmib-ifindex-persist","false")
            else:
                decoderhandler.addTokenValue("snmp-ifmib-ifindex-persist","true")
        except Exception:
                traceback.print_exc()
