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

class TransformSetVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('TransformSetVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0, None)
            self.parseTransformset(dc, cursor)
            self.parseIpsecEncryptionType(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseTransformset(self, dc, cursor):
        util.log_debug('TransformSetVariableDecoder: parseTransformset')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        if "crypto" == cursor.getNextToken():
            cursor.advance()
            cursor.advance()
            cursor.advance()
            transformSet = cursor.getNextToken()
            decoderhandler.addTokenValue("transform-set", transformSet)
            cursor.advance()
            
        if "mode" == cursor.getNextToken():
            cursor.advance()
            mode = cursor.getNextToken()
            decoderhandler.addTokenValue("mode", mode)
            cursor.advance()

    def parseIpsecEncryptionType(self, dc, cursor):
        util.log_debug('TransformSetVariableDecoder: parseIpsecEncryptionType')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        if not cursor.hasNext():
            return
        part1 = cursor.getNextToken()
        cursor.advance()
        part2 = cursor.getNextToken()
        cursor.advance()
        if "128" == part2:
            if part1 == 'esp-aes':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-aes 128")
            elif part1 == 'esp-gcm':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-gcm 128")
            if cursor.getNextToken() is not None:
                decoderhandler.addTokenValue("ipsec-authentication-type", cursor.getNextToken())
        elif "192" == part2:
            if part1 == 'esp-aes':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-aes 192")
            elif part1 == 'esp-gcm':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-gcm 192")
            if cursor.getNextToken() is not None:
                decoderhandler.addTokenValue("ipsec-authentication-type", cursor.getNextToken())
        elif "256" == part2:
            if part1 == 'esp-aes':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-aes 256")
            elif part1 == 'esp-gcm':
                decoderhandler.addTokenValue("ipsec-encryption-type", "esp-gcm 256")
            if cursor.getNextToken() is not None:
                decoderhandler.addTokenValue("ipsec-authentication-type", cursor.getNextToken())
        else:
            decoderhandler.addTokenValue("ipsec-encryption-type", part1)
            decoderhandler.addTokenValue("ipsec-authentication-type", part2)
