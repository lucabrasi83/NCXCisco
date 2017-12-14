#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser.tokendecoders import defaulttokendecoder
from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback

OPERATORS = ["eq", "neq", "gt", "lt"]
MATCHPKTS = ["dscp", "fragments", "log", "log-input", "option", "precedence", "time-range", "tos", "ttl", "echo", "echo-reply", "tracked"]
PRECEDENCE_TYPES = ["routine", "priority", "immediate", "flash", "flash-override", "critical", "internet", "network"]
class AclRuleTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('Initializing AclRuleTokendecoder')

    def decodeToken(self, dc):
        util.log_info('AclTokenDecoder: decodeToken')
        cursor = util.TokenCursor(None, -1, dc)
        action = cursor.getNextToken(-3)
        self.setToken(dc, "action", action)
        src = self.parseSourceCondition(dc, cursor)
        util.log_debug('The source condition')
        util.log_debug('src', src)
        dest = self.parseDestCondition(dc, cursor)
        util.log_debug('The destination condition')
        util.log_debug('dest', dest)
        util.log_debug('paramMap = %s' % (dc.getMap()))
        #LOGGER.info("[{}] ==> {}, {}", dc.getSearchTokens(), src, dest)
        return tokendecoderhandler.TokenDecoderHandler(dc).getSearchTokensSize() - tokendecoderhandler.TokenDecoderHandler(dc).getCurrentIndex()


    def parseSourceCondition(self, dc, cursor):
        util.log_info('AclTokenDecoder: parseSourceCondition')
        #print 'The decodercontext = %s' %(dc)
        srcCondition = Condition(cursor)
        self.setToken(dc, "source-condition-type", srcCondition.getType())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-condition-type')
        self.setToken(dc, "source-obj-name", srcCondition.getObjectGroup())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-obj-name')
        self.setToken(dc, "source-ip", srcCondition.getIpAddress())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-ip')
        self.setToken(dc, "source-mask", srcCondition.getMask())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-mask')
        self.setToken(dc, "source-port-operator", srcCondition.getOperator())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-port-operator')
        self.setToken(dc, "source-port", srcCondition.getValue())
        util.log_debug('Done setting AclTokenDecoder: parseSourceCondition: source-port')
        return srcCondition


    def parseDestCondition(self, dc, cursor):
        util.log_info('AclTokenDecoder: parseDestCondition')
        #print 'The decodercontext = %s' %(dc)
        destCondition = Condition(cursor)
        self.setToken(dc, "dest-condition-type", destCondition.getType())
        self.setToken(dc, "dest-obj-name", destCondition.getObjectGroup())
        self.setToken(dc, "dest-ip", destCondition.getIpAddress())
        self.setToken(dc, "dest-mask", destCondition.getMask())
        self.setToken(dc, "dest-port-operator", destCondition.getOperator())
        self.setToken(dc, "dest-port", destCondition.getValue())
        return destCondition

    def setToken(self, dc, name, value):
        try:
            util.log_info('AclTokenDecoder: setToken name = %s' %(name))
            #print 'The decodercontext = %s' %(dc)
            if value == None:
                util.log_debug('setToken value is None')
                return
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenName = decoderutil.DecoderUtil().makeSiblingToken(decoderhandler.getTokenText(), name)
            util.log_debug('AclTokenDecoder: setToken tokenName  = %s' %(tokenName))
            util.log_debug('AclTokenDecoder: setToken value  = %s' %(value))
            decoderhandler.addTokenValue(tokenName, value)
        except Exception:
            traceback.print_exc()


    def getEndIndex(self, curIdx, tokens):
        end = None
        if self.limit <= 0:
            end = tokens.size()
        else:
            end = curIdx + self.limit
        return end


    def matchToken(self, configParserContext, configToken, idx, toks):
        return self.getEndIndex(idx, toks) - idx


    def isMultilineDecoder(self):
        return 0

class Condition():
    #type, ipaddress, netmask, operator, value, objectGroup = None
    
    def __init__(self, cursor = None):
        self.type = None
        self.ipaddress = None
        self.netmask = None
        self.operator = None
        self.value = None
        self.objectGroup = None
        if cursor is not None:
            self.parseType(cursor)

    def getIpAddress(self):
        return self.ipaddress

    def getMask(self):
        return self.netmask

    def getOperator(self):
        return self.operator

    def getObjectGroup(self):
        return self.objectGroup

    def getValue(self):
        return self.value

    def getType(self):
        return self.type

    @staticmethod
    def emptyCondition(self):
        self.type = "any"
        return self


    def parseType(self, cursor):
        util.log_info('AclTokenDecoder: parseType')
        if not cursor.hasNext():
            return
        next = cursor.getNextToken()
        util.log_debug('The Next token in parseType = %s' %(next))
        if "host" == next:
            self.type = "host"
            cursor.advance()
            util.log_debug('AclTokenDecoder: calling parseHost')
            self.parseHost(cursor)
        elif "object-group" == next:
            self.type = "objectgroup"
            cursor.advance()
            util.log_debug('AclTokenDecoder: calling parseObjectGroup')
            self.parseObjectGroup(cursor)
        elif "any" == next:
            self.type = "any"
            cursor.advance()
            util.log_debug('AclTokenDecoder: calling parseOperator')
            self.parseOperator(cursor)
        elif self.hasCidr(cursor):
            self.type = "cidr"
            util.log_debug('AclTokenDecoder: calling parseCidr')
            self.parseCidr(cursor)
        else:
            self.type = "host"
            util.log_debug('AclTokenDecoder: calling parseHost in else')
            self.parseHost(cursor)

    def parseHost(self, cursor):
        util.log_info('AclTokenDecoder: parseHost')
        if not cursor.hasNext():
            return
        self.ipaddress = cursor.getNextToken()
        cursor.advance()
        self.parseOperator(cursor)

    def parseObjectGroup(self, cursor):
        objectGroup = cursor.getNextToken()
        cursor.advance()
        self.parseOperator(cursor)

    def parseOperator(self, cursor):
        util.log_info('AclTokenDecoder: parseOperator')
        if not cursor.hasNext():
            return    
        next = cursor.getNextToken()
        util.log_debug('The Next token in parseOperator = %s' %(next))
        if next not in OPERATORS:
            return
        self.operator = next
        cursor.advance()
        value1 = cursor.getNextToken()
        util.log_debug('The value1 in parseOperator = %s' %(value1))
        cursor.advance()
        if not cursor.hasNext():
            self.value = value1
            util.log_debug('The port in parseOperator = %s' %(value1))
            return
        value2 = cursor.getNextToken()
        util.log_debug("The value2 in parseOperator= %s" %(value2))
        cursor.advance()
        if value2 in MATCHPKTS:
            if not cursor.hasNext():
                self.value = value1+" "+value2
                util.log_info('The port in parseOperator(matchpackaets) = %s' %(self.value))
                return
        value3 = cursor.getNextToken()
        util.log_debug("The value3 in parseOperator= %s" %(value3))
        cursor.advance()
        if value3 in PRECEDENCE_TYPES:
            if not cursor.hasNext():
                self.value = value1+ " "+value2+" "+value3
                util.log_debug('The port in parseOperator(precedencetype) = %s' %(self.value))
                return
        


    def hasCidr(self, cursor):
        from com.anuta.api.dto.thirdparty import CidrUtils
        if not cursor.hasNext():
            return 0
        next = cursor.getNextToken()
        if next.find('/') > 0:
            return 1
        other = cursor.getNextToken(1)
        ret = 0
        if CidrUtils.isIpAddress(next) and other is not None and CidrUtils.isIpAddress(other):
            ret = 1
        return ret


    def parseCidr(self, cursor):
        from com.anuta.api.dto.thirdparty import CidrUtils
        util.log_info('AclTokenDecoder: parseCidr')
        next = cursor.getNextToken()
        util.log_debug('The Next token in parseCidr = %s' %(next))
        cursor.advance()
        if next.find('/') > 0:
            util.log_debug('AclTokenDecoder: found /')
            self.ipaddress = CidrUtils.getNetworkAddress(next)
            self.netmask = CidrUtils.getNetmaskFromCidr(next)
        else:
            self.ipaddress = next
            self.netmask = cursor.getNextToken()
            cursor.advance()
        self.parseOperator(cursor)


    def toString(self):
        buf = ''
        buf = buf + ('[') + self.type + ']'
        if self.ipaddress is not None:
            buf = buf + ". Address = " + self.ipaddress

        if self.netmask is not None:
            buf = buf + ", Mask = " + self.netmask

        if self.objectGroup is not None:
            buf = buf + ". ObjectGroup = " + self.objectGroup

        if self.operator is not None:
            buf = buf + ' ' + self.operator

        if self.value is not None:
            buf = buf + " [" + self.value + "] "

        return buf





