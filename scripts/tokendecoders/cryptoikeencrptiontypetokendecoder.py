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
from ncxparser.tokendecoders import greedytokendecoder
import traceback


class CryptoIkeEncryptionTypeTokenDecoder(greedytokendecoder.GreedyTokenDecoder):

    def decodeToken(self, dc):
        util.log_info('CryptoIkeEncryptionTypeTokenDecoder: Decode token')
        try:
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 1)
            util.log_debug('CryptoIkeEncryptionTypeTokenDecoder Token text = %s' %(tokenText))
            types = {"AES128" : ["AES128", "aes", "aes 128"],"AES256" : ["AES256", "aes 256"], "AES192" : ["AES192", "aes 192"], "DES" : ["DES", "des"], "3DES" : ["3DES", "3des"] }
            value_1 = decoderhandler.getValueAtCurrentIndex()
            util.log_debug("value_1 is : ", value_1)
            cursor.advance()
            value_2 = cursor.getNextToken()
            util.log_debug("Value_2 is : ", value_2)
            if value_2 is not None:                
                value = "%s %s" %(value_1,value_2)
                util.log_debug("Value is : ", value)
            else:
                value = value_1
                util.log_debug("Value is : ", value)
            for k,v in types.iteritems():
                if value in v:
                    util.log_debug("Key is : ", k)
                    break
            decoderhandler.addTokenValue(tokenText, k)
            util.log_debug("Key is : ", k)
        except Exception:
            traceback.print_exc()
