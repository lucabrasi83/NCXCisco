from ncxparser import util, parser, tokendecoderhandler, tokendecoder, decoderutil
import traceback

class IpNatPoolOptionsDecoder(tokendecoder.AbstractTokenDecoder):

    def decodeToken(self, dc):
        try:
            util.log_info('IpNatPoolOptionsDecoder : DecodeVariable')
            global decoderhandler
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("Block IS: ",decoderhandler.getCurrentBlock().getTokens())
            global command_block
            command_block = decoderhandler.getCurrentBlock().getTokens()
            util.log_debug("TokenText : ",decoderhandler.getTokenText())
            tokenText = decoderhandler.getTokenText()
            util.log_debug("Value is: ",decoderhandler.getValueAtCurrentIndex())
            tokenValue = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText,tokenValue)
            self.parseOverload(dc)
            self.parseMatchVrf(dc)
            self.parseOer(dc)            
            self.parseExtended(dc)
            self.parseNetwork(dc)
        except Exception:
            traceback.print_exc()

    def  parseOverload(self, dc):
        if "overload" in command_block:
            decoderhandler.addTokenValue("$overload", "true")
        else:
            decoderhandler.addTokenValue("$overload", "false")
        return
    
    def parseMatchVrf(self, dc):
        if "match-in-vrf" in command_block:
            decoderhandler.addTokenValue("$match-in-vrf", "true")
        else:
            decoderhandler.addTokenValue("$match-in-vrf", "false")
        return

    def parseOer(self, dc):
        if "oer" in command_block:
            decoderhandler.addTokenValue("$oer", "true")
        else:
            decoderhandler.addTokenValue("$oer", "false")
        return
        
    def parseExtended(self,dc):
        if "extended" in command_block:
            decoderhandler.addTokenValue("$extended", "true")
        else:
            decoderhandler.addTokenValue("$extended", "false")
        return

    def parseNetwork(self,dc):
        if "network" in command_block:
            decoderhandler.addTokenValue("$network", "true")
        else:
            decoderhandler.addTokenValue("$network", "false")
        return
