#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

class TacacsServerGroupVariableDecoder(parser.DefaultVariableDecoder):

    def __init__(self):
        util.log_info('Initializing TacacsServerGroupVariableDecoder')

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('TacacsServerGroupVariableDecoder: Decode token for TACACS Server Group leaf value')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            block = decoderhandler.getCurrentBlock()
            util.log_info('AAA BLOCK = %s' %(block))
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info('AAA Line is %s' % (lines))
            self.parseAAAServerGroup(dc, cursor);   
        except Exception:
            traceback.print_exc()

    def parseAAAServerGroup(self, dc, cursor):
        util.log_debug('AAAServerGroupDecoder: Parse AAA TACACS Server Group')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "aaa" == cursor.getNextToken():
            cursor.advance()
            if "group" == cursor.getNextToken():
                cursor.advance()
                if "server" == cursor.getNextToken():
                    cursor.advance()
                    if "tacacs+" == cursor.getNextToken():
                        cursor.advance()
                        decoderhandler.addTokenValue('tacacs-server-group', cursor.getNextToken())
            else:
                return
        else:
            return
    