#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import parser, tokendecoderhandler, util
import traceback

class PortChannelVariableTokenDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('ClassMapVariableTokenDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            self.parseName(dc,cursor)
            self.parseDescription(dc,cursor)
            self.parseotherbooleans(dc,cursor)
        except Exception:
            traceback.print_exc()


    def parseotherbooleans(self,dc,cursor):
	try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            if decoderhandler.getCurrentBlockTokens()[-1] in ['address','redirects','unreachables','proxy-arp','enabled','transmit','receive'] and "no" in decoderhandler.getCurrentBlockTokens():
                token = '-'.join(decoderhandler.getCurrentBlockTokens()[1:])
		decoderhandler.addTokenValue(token, "false")	
            elif decoderhandler.getCurrentBlockTokens()[-1] in ['address','redirects','unreachables','proxy-arp','enabled','transmit','receive']:
                token = '-'.join(decoderhandler.getCurrentBlockTokens())
		decoderhandler.addTokenValue(token, "true")	
        except Exception:
            traceback.print_exc()

    def parseName(self,dc,cursor):
	try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            cursor.advance()
            if "interface" in decoderhandler.getCurrentBlockTokens():
		tokennumber = cursor.getNextToken().split('Port-channel')[-1]
		decoderhandler.addTokenValue("name",tokennumber)	
        except Exception:
            traceback.print_exc()

    def parseDescription(self,dc,cursor):
	try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            cursor.advance()
            if "description" in decoderhandler.getCurrentBlockTokens():
		decoderhandler.addTokenValue("description",cursor.getNextToken())
        except Exception:
            traceback.print_exc()
