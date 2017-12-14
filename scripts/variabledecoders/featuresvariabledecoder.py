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

class FeaturesVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('FeaturesVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self. parseFeatureState(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseFeatureState(self, dc, cursor):
        util.log_debug('FeaturesVariableDecoder: parseFeatureState will describe the present state for the feature')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "no" == cursor.getNextToken():
            cursor.advance()
            cursor.advance()
            featurename = cursor.getNextToken()
            if "tacacs+" == featurename:
                featurename = "tacacs"
            elif "domain" == featurename:
                featurename = "domain-lookup"
            decoderhandler.addTokenValue(featurename, "disable")
            cursor.advance()
        elif "feature" == cursor.getNextToken():
            cursor.advance()
            featurename = cursor.getNextToken()
            if "tacacs+" == featurename:
                featurename = "tacacs"
            decoderhandler.addTokenValue(featurename, "enable")
            cursor.advance()
        elif "ip" == cursor.getNextToken():
            featurename = "domain-lookup"
            decoderhandler.addTokenValue(featurename, "enable")

