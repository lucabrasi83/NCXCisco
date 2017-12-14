from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class AaaGroupVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('AAAGroupVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getCurrentBlock()
            util.log_info("AAA New Model Value is " + str(value))
            if "no aaa new-model" in str(value):
                decoderhandler.addTokenValue("aaa-new-model", "false")
            elif "aaa new-model" in str(value):
                decoderhandler.addTokenValue("aaa-new-model", "true")
            elif "new-model" not in str(value):
            	decoderhandler.addTokenValue("aaa-new-model", "false")
        except Exception:
                traceback.print_exc()
    
        
