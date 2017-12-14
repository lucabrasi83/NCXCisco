from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class RouterBgpAsnumberTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        print 'RouterBgpAsnumberTokenDecoder()'

    def decodeToken(self, dc):
        try:
            print 'RouterBgpAsnumberTokenDecoder(): Decode token'
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            current_block = decoderhandler.getCurrentBlock() 
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 2, None)
            tokenText = decoderhandler.getTokenText()
            print 'Token text = %s' %(tokenText)
            value = decoderhandler.getValueAtCurrentIndex()
            print 'Value1 = %s' %(value)
            decoderhandler.addTokenValue(tokenText,value)
            block = decoderhandler.getCurrentBlock()

            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            log_neighbor = '^bgp log-neighbor-changes$'
            redis_internal = '^bgp redistribute-internal$'
            def_inf = '^default-information originate$'
            log_neighbor_found = False
            redis_internal_found = False
            def_inf_found = False

            for line in lines:
                log_neighbor_match = re.search(log_neighbor, line)
                if log_neighbor_match is not None:
                    decoderhandler.addTokenValue("log-neighbor-changes", "true")
                    log_neighbor_found = True

                # redis_internal_match = re.search(redis_internal, line)
                # if redis_internal_match is not None:
                #     decoderhandler.addTokenValue("redistribute-internal", "true")
                #     redis_internal_found = True

                # def_inf_match = re.search(def_inf, line)
                # if def_inf_match is not None:
                #     decoderhandler.addTokenValue("default-information-originate", "true")
                #     def_inf_found = True

            if not log_neighbor_found:
                decoderhandler.addTokenValue("log-neighbor-changes", "false")
            # if not redis_internal_found:
            #     decoderhandler.addTokenValue("redistribute-internal", "false")
            # if not def_inf_found:
            #     decoderhandler.addTokenValue("default-information-originate", "false")
        except Exception:
            traceback.print_exc()
