from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class RouterBgpRouterIdTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        print 'RouterBgpRouterIdTokenDecoder'

    def decodeToken(self, dc):
        try:
            print 'RouterBgpRouterIdTokenDecoder: Decode token'
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 2, None)
            tokenText = decoderhandler.getTokenText()
            print 'Token text = %s' %(tokenText)
            value1 = decoderhandler.getValueAtCurrentIndex()
            print 'Value1 = %s' %(value1)
            cursor.advance()
            value2 = cursor.getNextToken()
            print 'Value2 = %s' %(value2)
            if value2 == None:
                decoderhandler.addTokenValue(tokenText, value1)
            else:
                decoderhandler.addTokenValue(tokenText, ("%s %s" %(value1,value2)))
        except Exception:
            traceback.print_exc()
