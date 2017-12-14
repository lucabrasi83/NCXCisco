from ncxparser import tokendecoderhandler, util, parser
import traceback

class SnmpViewNameVariableDecoder(parser.DefaultVariableDecoder):
    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('SnmpViewNameVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self.parseSnmpViewName(dc,cursor)
        except Exception:
                traceback.print_exc()

    def parseSnmpViewName(self,dc,cursor):
        util.log_debug('SnmpViewNameVariableDecoder: parseSnmpViewName')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        util.log_debug('Block is : ',decoderhandler.getCurrentBlockTokens())
        if not cursor.hasNext():
           return
        if cursor.getNextToken() == "snmp-server":
            cursor.advance()
            if cursor.getNextToken() == "group":
                cursor.advance()
                decoderhandler.addTokenValue("$../group-name",cursor.getNextToken())
                cursor.advance()
                snmp_version = str(cursor.getNextToken())
                util.log_debug("snmp-version is : ",snmp_version)
                decoderhandler.addTokenValue("$../snmp-version",cursor.getNextToken())
                if snmp_version != "v3":
                    cursor.advance()
                    decoderhandler.addTokenValue("$../group-priviledge",cursor.getNextToken())
                    cursor.advance()
                    decoderhandler.addTokenValue("$view-name",cursor.getNextToken())
                else:
                    cursor.advance()
                    decoderhandler.addTokenValue("$../group-auth-type",cursor.getNextToken())
                    cursor.advance()
                    decoderhandler.addTokenValue("$../group-priviledge",cursor.getNextToken())
                    cursor.advance()
                    decoderhandler.addTokenValue("$view-name",cursor.getNextToken())
