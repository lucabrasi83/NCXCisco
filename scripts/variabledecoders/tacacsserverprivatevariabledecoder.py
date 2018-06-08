from ncxparser import parser, tokendecoderhandler, util
import traceback

class TacacsServerPrivateVariableDecoder(parser.DefaultVariableDecoder):
    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('TacacsServerPrivateVariableDecoder: Decoding Variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            command_block = decoderhandler.getCurrentBlockTokens()
            util.log_info("command_block : ",command_block)
            decoderhandler.addTokenValue('$server-private',command_block[1])
            if command_block[3] == "7":
                decoderhandler.addTokenValue('$privilege-level','7')
                priv_key = " ".join(command_block[4:len(command_block)])
                util.log_info("1 : ",priv_key)
                decoderhandler.addTokenValue('$privilege-key',str(priv_key))
            else:
                priv_key = " ".join(command_block[3:len(command_block)])
                util.log_info("2 : ",priv_key)
                decoderhandler.addTokenValue('$privilege-key',str(priv_key))    
        except Exception:
            traceback.print_exc()
