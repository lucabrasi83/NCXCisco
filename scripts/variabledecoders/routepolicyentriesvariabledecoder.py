from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class RoutePolicyEntriesVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('RoutePolicyEntriesVariableDecoder : Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            value = decoderhandler.getCurrentBlockTokens()
            util.log_info("BLOCK : ",value)
            if not cursor.hasNext():
                return
            util.log_info(cursor.getNextToken())
            if cursor.getNextToken() == "route-policy":
                cursor.advance()
                util.log_info(cursor.getNextToken())
                decoderhandler.addTokenValue("../name",cursor.getNextToken())
            if cursor.getNextToken() == "if":
                cursor.advance()
                util.log_info(cursor.getNextToken())
                if cursor.getNextToken() == "destination":
                    cursor.advance()
                    util.log_info(cursor.getNextToken())
                    if cursor.getNextToken() == "in":
                        cursor.advance()
                        util.log_info(cursor.getNextToken())
                        decoderhandler.addTokenValue("prefix-set",cursor.getNextToken())
            if cursor.getNextToken() == "set":
                cursor.advance()
                util.log_info(cursor.getNextToken())
                if cursor.getNextToken() == "med":
                    cursor.advance()
                    util.log_info(cursor.getNextToken())
                    decoderhandler.addTokenValue("med",cursor.getNextToken())    
        except Exception:
                traceback.print_exc()
