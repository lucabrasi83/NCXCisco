#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2017-2018 Anuta Networks, Inc. All Rights Reserved.


from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re


class DmvpnNameTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing DmvpnNameTokenDecoder')

    def decodeToken(self, dc):
        try:
            util.log_info('DmvpnNameTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            token = dc.getToken()
            searchTokens = dc.getSearchTokens()
            idx = dc.getCurrentIndex()
            name = searchTokens.get(idx)

            decoderhandler.addTokenValue(token.getText(), name)
            block = decoderhandler.getCurrentBlock()

            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            ip_redirect_pattern = '^no ip redirects$'
            ip_redirect_found = False

            qos_pre_pattern = '^qos pre-classify$'
            qos_pre_found = False

            load_interval_pattern = '^load-interval'

            for line in lines:
                ip_redirect_match = re.search(ip_redirect_pattern, line)
                if ip_redirect_match is not None:
                    decoderhandler.addTokenValue("no-ip-redirects", "true")
                    ip_redirect_found = True

                qos_pre_match = re.search(qos_pre_pattern, line)
                if qos_pre_match is not None:
                    decoderhandler.addTokenValue("qos-pre-classify", "true")
                    qos_pre_found = True

                load_interval_match = re.search(load_interval_pattern, line)
                if load_interval_match is not None:
                    delay = line.split(' ')
                    decoderhandler.addTokenValue("load-interval-delay", delay[1])

            if not ip_redirect_found:
                decoderhandler.addTokenValue("no-ip-redirects", "false")

            if not qos_pre_found:
                decoderhandler.addTokenValue("qos-pre-classify", "false")

            return 1
        except Exception:
            traceback.print_exc()
