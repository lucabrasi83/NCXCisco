from ncxparser import tokendecoderhandler
from ncxparser import tokendecoder, util
import traceback
import re

class NewRouteTargetTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def decodeToken(self, decoderContext):
        try:
            util.log_info('newroutetargettokendecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
            util.log_debug("BLOCK:", decoderhandler.getCurrentBlock())
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            rtpattern1 = "\\d+:\\d+"
            rtpattern2 = "\\d+"
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info("Lines : ",lines)
            for line in range(0,len(lines)):
                if re.search("^import route-target$", lines[line]):
                    for i in range(line+1, len(lines)):
                        if re.search(rtpattern1, lines[i]):
                            decoderhandler.addTokenValue('../rt-import/rt-import', lines[i])
                if re.search("^export route-target$", lines[line]):
                    for i in range(line+1, len(lines)):
                        if re.search(rtpattern1, lines[i]):
                            decoderhandler.addTokenValue('../rt-export/rt-export', lines[i])
                if ("route-target import " + value) in lines or ("route-target export " + value) in lines:
                    if re.search(rtpattern1,value) or re.search(rtpattern2,value):
                        decoderhandler.addTokenValue(tokenText,value)
        except Exception:
            traceback.print_exc()
