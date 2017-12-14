from ncxparser import tokendecoderhandler, tokendecoder, decoderutil, util
import traceback
class NameServerTokenDecoder(tokendecoder.AbstractTokenDecoder):
    def __init__(self, limit = -1, includespaces = False):
        util.log_debug('Initializing  NameServerTokenDecoder')
        self.limit = limit
        self.includespaces = includespaces

    def decodeToken(self, decoderContext):
        try:
            util.log_debug('NameServerTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
            self.decodeNameServer(decoderContext)
        except Exception:
            traceback.print_exc()

    def decodeNameServer(self, decoderContext):
        try:
            util.log_info('NameServerTokenDecoder : Decoding Variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text with in decodeNameServer is %s'%tokenText)
            searchTokens = decoderhandler.getSearchTokens()
            util.log_debug('Search Tokens %s'%searchTokens)
            end = self.getEndIndex(decoderhandler.getCurrentIndex(), searchTokens)
            util.log_debug('Value of end with in decodeNameServer is %s'%end)
            count = 0
            buffer = ''
            util.log_debug('CurrentIndex with in decodeNameServer is %s' %decoderhandler.getCurrentIndex())
            for i in range(decoderhandler.getCurrentIndex(), end):
                if count > 0:
                    buffer = buffer + ' '

                util.log_debug('current searchtoken with in decodeNameServer  %s' %searchTokens.get(i))
                buffer = buffer + searchTokens.get(i)
                count += 1
            util.log_debug('Final Buffer after execution of decodeNameServer is %s' %buffer)
            ip_addresses = buffer.split(" ")
            for server_ip in ip_addresses:
                decoderhandler.addTokenValue(tokenText, server_ip)
            util.log_debug('count after execution of decodeNameServer is %s' %count)
            return count
        except Exception:
            traceback.print_exc()


    def getEndIndex(self, curIdx, tokens):
        try:
            end = 0
            if self.limit <= 0:
                util.log_debug('Tokens size under getEndIndex is %s' %tokens.size())
                end = tokens.size()
            else:
                end = curIdx + self.limit
            util.log_debug('End val under getEndIndex is %s' %end)
            return end
        except Exception:
            traceback.print_exc()


    def matchToken(self, configParserContext, configToken, idx, toks):
        return self.getEndIndex(idx, toks) - idx
    
    def includespaces(self):
        self.includespaces = True
        return self


    def isMultilineDecoder(self):
        return False
