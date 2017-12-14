#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from com.anuta.util import AnutaStringUtils
from ncxparser import tokendecoderhandler, util, decoderutil
from ncxparser.tokendecoders import greedytokendecoder
import traceback


class RouteMapSetActionTokenDecoder(greedytokendecoder.GreedyTokenDecoder):

    AS_PATH_PREPEND = ["set", "as-path", "prepend"]
    COMM_LIST = ["set", "comm-list"]
    VRF = ["set", "vrf"]
    PREFERENCE = ["set", "local-preference"]
    IP = ["set", "ip"]
    WEIGHT = ["set", "weight"]
    COMMUNITY = ["set", "community"]
    def decodeToken(self, dc):
        try:
            util.log_info('RouteMapSetActionTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            if AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.COMM_LIST):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "comm-list")
                tokenText = decoderhandler.getTokenText()
                value = decoderhandler.getValueAtCurrentIndex()
                decoderhandler.addTokenValue(tokenText, value.replace(' delete', ''))
                return 1

            ret = super(RouteMapSetActionTokenDecoder, self).decodeToken(dc)
            util.log_debug('The return value: = %s' %(ret))
            if (ret <= 0):
                return ret
            if AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.AS_PATH_PREPEND):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "as-path prepend")
            elif AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.VRF):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "vrf")
            elif AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.PREFERENCE):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "local-preference")
            elif AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.IP):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "ip")
            elif AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.WEIGHT):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "weight")
            elif AnutaStringUtils.startsWith(decoderhandler.getSearchTokens(), self.COMMUNITY):
                setType = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), "set-type")
                util.log_debug('The SetType: = %s' %(setType))
                decoderhandler.addTokenValue(setType, "community")

            return ret
        except Exception:
            traceback.print_exc()
