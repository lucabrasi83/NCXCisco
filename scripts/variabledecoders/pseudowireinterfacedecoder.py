from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback,re

class PseudoWireInterfaceDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('PseudoWireInterfaceDecoder : Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            command_block = [str(cmd).strip() for cmd in decoderhandler.getCurrentBlock().toString().split("\n")]
            util.log_info("Value : ",command_block)
            pattern = '^interface pseudowire'
            if re.search(pattern,command_block[0]):
                for i in range(len(command_block)):
                    cmd = command_block[i].split(" ")
                    util.log_info("cmd : ",cmd)
                    if cmd[0] == "interface":
                        decoderhandler.addTokenValue("$pseudowire-interface",cmd[1])
                    if cmd[0] == "description":
                        desc = " ".join(cmd[1:])
                        decoderhandler.addTokenValue("$description",desc)
                    if cmd[0] == "encapsulation":
                        decoderhandler.addTokenValue("$encapsulation",cmd[1])
                    if cmd[0] == "neighbor":
                        decoderhandler.addTokenValue("$neighbor-ip",cmd[1])
                        decoderhandler.addTokenValue("$tunnel-id",cmd[2])
                    if cmd[0] == "vc":
                        decoderhandler.addTokenValue("$vc-type",cmd[2])
                    if cmd[0] == "control-word":
                        decoderhandler.addTokenValue("$control-world",cmd[1])
                    if cmd[0] == "preferred-path":
                        decoderhandler.addTokenValue("$interface-name",cmd[2])
            else:
                pass
        except Exception:
                traceback.print_exc()

