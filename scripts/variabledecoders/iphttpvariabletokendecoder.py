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
from com.google.common.base import Joiner

class IpHttpVariableTokenDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self,cpc,dc,context):
        try:
            util.log_info('IpHttpTokenDecoder: Entering Variable Token Decoder for ip http server and ip http secure-server commands.')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self.parseIpHttp(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseIpHttp(self, dc, cursor):
        util.log_info('IpHttpTokenDecoder: parseIpHttp')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return

        command = Joiner.on(" ").join(decoderhandler.getCurrentBlock().getTokens())
        util.log_info('IpHttpTokenDecoder(parseIpHttp): command is %s' % (command))
        if command == "no ip http secure-server":
            util.log_info("Making no-ip-http-secure-server as 'true'")
            decoderhandler.addTokenValue("no-ip-http-secure-server", 'true')
        if command == "no ip http server":
            util.log_info("Making no-ip-http-server as 'true'")
            decoderhandler.addTokenValue("no-ip-http-server", 'true')
        if command == "ip http secure-server":
            util.log_info("Making no-ip-http-secure-server as 'false'")
            decoderhandler.addTokenValue("no-ip-http-secure-server", 'false')
        if command == "ip http server":
            util.log_info("Making no-ip-http-server as 'false'")
            decoderhandler.addTokenValue("no-ip-http-server", 'false')
        util.log_info("IpHttpTokenDecoder(parseIpHttp):Exiting")
