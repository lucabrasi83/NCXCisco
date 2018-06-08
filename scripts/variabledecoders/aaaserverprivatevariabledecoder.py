from ncxparser import parser, tokendecoderhandler, util
import traceback

class AaaServerPrivateVariableDecoder(parser.DefaultVariableDecoder):
    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('AaaServerPrivateVariableDecoder : Decoding Variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            command_block = decoderhandler.getCurrentBlockTokens()
            util.log_info("command_block : ",command_block)
            if command_block[0] == "server-private":
                decoderhandler.addTokenValue('$aaa-server-private',command_block[1])
                if command_block[3] == "7":
                    decoderhandler.addTokenValue('$privilege-level','7')
                    priv_key = " ".join(command_block[4:len(command_block)])
                    util.log_info("1 : ",priv_key)
                    decoderhandler.addTokenValue('$privilege-key',str(priv_key))
                else:
                    priv_key = " ".join(command_block[3:len(command_block)])
                    util.log_info("2 : ",priv_key)
                    decoderhandler.addTokenValue('$privilege-key',str(priv_key))
            if command_block[0] == "ip":
                if command_block[1] == "vrf":
                    decoderhandler.addTokenValue('$../vrf',command_block[3])
                if command_block[1] == "tacacs":
                    decoderhandler.addTokenValue('$../source-interface',command_block[3])
        except Exception:
            traceback.print_exc()
