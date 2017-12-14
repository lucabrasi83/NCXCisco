#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxsdk.packages.systemservicepackages.ncxparser.scripts.tokendecoders import defaulttokendecoder
from ncxsdk.packages.systemservicepackages.ncxparser.scripts import util, tokendecoderhandler

class DmvpnNhrpSourceIpTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    def decodeToken(self, dc):
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        token = decoderhandler.getToken()
        idx = decoderhandler.getCurrentIndex()
        if (idx > 0):
            idx-=1
            if "multicast" == decoderhandler.getSearchTokens().get(idx):
                decoderhandler.addTokenValue(self.replaceTokenName(token.getText(), "destip"), "0.0.0.0")
        return super(DmvpnNhrpSourceIpTokenDecoder, self).decodeToken(dc)