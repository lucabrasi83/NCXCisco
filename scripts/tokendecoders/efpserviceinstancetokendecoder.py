from ncxparser import parser, tokendecoderhandler, util
from ncxparser import tokendecoder
import traceback
import re

class EfpServiceInstanceTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self):
        util.log_info('Initializing EfpServiceInstanceTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('EfpServiceInstanceTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("Block is : ",decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_debug("Text :",tokenText)
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            util.log_debug("Value :",tokenValue)
            decoderhandler.addTokenValue(tokenText, tokenValue)
            current_block = decoderhandler.getCurrentBlock().toString()
            block_tokens = str(current_block).split(" ")
            util.log_debug("Block_Tokens : ",block_tokens)
            command_block = []
            for cmds in block_tokens:
                command_block.append(cmds.strip("\n"))
            util.log_debug("command_block : ",command_block)
            if 'trunk' in command_block:
                decoderhandler.addTokenValue("$trunk", "true")
            else:
                decoderhandler.addTokenValue("$trunk", "false")
            if 'symmetric' in command_block:
                decoderhandler.addTokenValue("$symmetric", "true")
            else:
                decoderhandler.addTokenValue("$symmetric", "false")
            if "encapsulation" in block_tokens:        
                i = command_block.index("encapsulation")
                encap_type_list = ['default','dot1ad','dot1q','priority-tagged','untagged']
                encap_type = command_block[i+1]
                if encap_type in encap_type_list: 
                    decoderhandler.addTokenValue("$encapsulation-type", encap_type)
                if 'add' in command_block:
                    vlanid = command_block[i+3]
                    decoderhandler.addTokenValue("$vlan-id", vlanid)
                else:
                    vlanid = command_block[i+2]
                    decoderhandler.addTokenValue("$vlan-id", vlanid)
            if "description" in block_tokens:
                description_tokens = [cmds.strip() for cmds in str(current_block).split("\n")]
                desc_pattern = '^description'
                for i in range(len(description_tokens)):
                    if re.search(desc_pattern,description_tokens[i]):
                        desc_token = description_tokens[i].split("description")
                        desc_block = desc_token[1].strip()
                        decoderhandler.addTokenValue("$description", desc_block)
        except Exception:
            traceback.print_exc()
