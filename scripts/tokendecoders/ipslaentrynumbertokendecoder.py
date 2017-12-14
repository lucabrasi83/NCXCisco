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
from org.apache.http.conn.util import InetAddressUtils
import traceback
import re

class IpSlaEntryNumberTokenDecoder(tokendecoder.AbstractTokenDecoder):
    responder_pattern= '^\d+$'
    source_int_pattern = 'source-interface'
    source_ip_pattern = 'source-ip'
    def __init__(self):
        util.log_info('Initializing IpSlaEntryNumberTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('IpSlaEntryNumberTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            value = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Value = %s' %(value))
            match = re.search(self.responder_pattern, value)
            if match is not None:
                decoderhandler.addTokenValue("entry-number", value)
                block = decoderhandler.getCurrentBlock()
                util.log_debug('BLOCK = %s' %(block))
                lines = block.toString().split("\n")
                lines = [line.strip(' ') for line in lines]
                i = 0
                for line in lines:
                    source_int_match = re.search(self.source_int_pattern, line)
                    if source_int_match is not None:
                        decoderhandler.addTokenValue("source", "source-interface")
                    source_ip_match = re.search(self.source_ip_pattern, line)
                    if source_ip_match is not None:
                        decoderhandler.addTokenValue("source", "source-ip")

                    http_url_match = re.search('^http raw http://.*', line)
                    if http_url_match is not None:
                        http_url_entry = line.split(' ')
                        decoderhandler.addTokenValue("http-url", http_url_entry[2])
                        decoderhandler.addTokenValue("http-request-type", "raw")

                    http_raw_req_match = re.search('^http-raw-request$', line)
                    if http_raw_req_match is not None:
                        i = lines.index('http-raw-request')
                if i != 0:
                    raw_req_value = ''
                    for line in range(i+1 , len(lines)):
                        if lines[line] != 'exit':
                            raw_req_value += lines[line]
                    decoderhandler.addTokenValue("http-raw-request", raw_req_value)

                return 1
            else:
                util.log_info("Given Value: "+str(value)+ "is not integer")
                return -1

        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        value = toks.get(idx)
        util.log_debug('entry-number-matchtokenValue = %s' %(value))
        match = re.search(self.responder_pattern, value)
        if match is not None:
            return 1
        else:
            return -1

    def isMultilineDecoder(self):
        return False
