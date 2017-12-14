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


class ServiceTimeStampsVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
	    util.log_info('ServiceTimeStampsVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
	    cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
	    parse = parseServiceTimestamps(dc, cursor)
	    parse.is_false()
	    parse.field_value()
        except Exception:
            traceback.print_exc()

class parseServiceTimestamps():
	def __init__(self,dc,cursor):
		self.dc = dc
		self.cursor = cursor
		self.is_value_false = False
    
	def is_false(self):
		print "THis is self.cursonr.getnexttoke"	
                print dir(self.cursor)
		print self.cursor.getNextToken()
		if self.cursor.getNextToken() == "no":
			self.is_value_false = True
			self.cursor.advance()
			self.cursor.advance()
		else:
			self.cursor.advance()
		self.decoderhandler = tokendecoderhandler.TokenDecoderHandler(self.dc)

	def field_value(self):
		if self.cursor.getNextToken() == "timestamps":
			self.timestamp_def()
		if self.cursor.getNextToken() == "password-encryption":
			self.password_encry('service-password-encryption')
		if self.cursor.getNextToken() == "tcp-keepalives-in":
			self.password_encry('tcp-keepalives-in')
		if self.cursor.getNextToken() == "secret":
			self.password_encry('enable-secret')
 
	def timestamp_def(self):	
		self.cursor.advance()
                print "This is cursro.getNextotke"
                print self.cursor.getNextToken()
		if self.cursor.getNextToken() == "debug" and self.is_value_false == False:
			self.decoderhandler.addTokenValue("service-timestamps-debug", "true")
		if self.cursor.getNextToken() == "debug" and self.is_value_false == True:
			self.decoderhandler.addTokenValue("service-timestamps-debug", "false")
		if self.cursor.getNextToken() == "log" and self.is_value_false == False:
			self.decoderhandler.addTokenValue("service-timestamps-log", "true")
		if self.cursor.getNextToken() == "log" and self.is_value_false == True:
			self.decoderhandler.addTokenValue("service-timestamps-log", "false")
   
	def password_encry(self,tokenvalue):
		if self.is_value_false == True:
			self.decoderhandler.addTokenValue(tokenvalue, "false")
		else:
			self.decoderhandler.addTokenValue(tokenvalue, "true")
			if tokenvalue == "enable-secret":
				self.cursor.advance()
				self.decoderhandler.addTokenValue("enable-secret-password", self.cursor.getNextToken())
