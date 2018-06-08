#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import tokendecoderhandler, parser, util
from ncxparser.tokendecoders import defaulttokendecoder
import traceback

class ClassMapMatchValueTokenDecoder(defaulttokendecoder.DefaultTokenDecoder):

    KNOWN_CONDITIONS = ["ip-dscp", "dscp", "protocol","qos-group", "access-group", "any", "vlan"]

    def decodeToken(self, dc):
        try:
            util.log_info('ClassMapMatchValueTokenDecoder decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            util.log_debug('Token text = %s' %(tokenText))
            name = decoderhandler.getValueAtCurrentIndex()
            util.log_debug('Name = %s' %(name))
            decoderhandler.addTokenValue(tokenText, name)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 1, None)
            conditionType = cursor.getNextToken()
            util.log_debug('Condition Type = %s' %(conditionType))
            if ("ip" == conditionType and "dscp" == cursor.getNextToken(1)):
                conditionType = "ip-dscp"
            if conditionType is not None and conditionType in self.KNOWN_CONDITIONS:
                decoderhandler.addTokenValue(dc, self.replaceTokenName(tokenText, "condition-type"), conditionType)
            else:
                util.log_debug('Unknown condition type = %s'%(conditionType))
            return 1
        except Exception:
            traceback.print_exc()
