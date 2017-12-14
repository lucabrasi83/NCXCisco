from ncxparser import tokendecoderhandler, util, parser
import traceback

class AddressFamilyVariableDecoder(parser.DefaultVariableDecoder):
    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('CiscoRouterBGPAddressFamily: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self.parseAddressFamily(dc,cursor)
        except Exception:
                traceback.print_exc()

    def parseAddressFamily(self,dc,cursor):
        util.log_debug('CiscoRouterBGPAddressFamily: parseAddressFamily')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
           decoderhandler.addTokenValue("address-family", "null")
           return
        if cursor.getNextToken() == "address-family":
            util.log_debug('CiscoRouterBGPAddressFamily: next token is address-family')
            cursor.advance()
            if not cursor.hasNext():
               return
            util.log_debug('CiscoRouterBGPAddressFamily:: next token is = %s' %(cursor.getNextToken()))
            decoderhandler.addTokenValue("address-family", cursor.getNextToken())
            cursor.advance()
            if cursor.getNextToken() == "vrf":
                util.log_debug('CiscoRouterBGPAddressFamily: next token is vrf')
                cursor.advance()
                if not cursor.hasNext():
                   return
                util.log_debug('CiscoRouterBGPAddressFamily:: next token is = %s' %(cursor.getNextToken()))
                decoderhandler.addTokenValue("../../name", cursor.getNextToken())
                cursor.advance()
            elif cursor.getNextToken() == None:
                value = "GLOBAL"
                util.log_debug('CiscoRouterBGPAddressFamily:: next token is = Null ',value)
                decoderhandler.addTokenValue("../../name", value)
        else:
            decoderhandler.addTokenValue("address-family", "null")
            return
