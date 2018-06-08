from ncxparser import parser, tokendecoderhandler, util
from com.google.common.base import Joiner
import traceback
import re

class IfrpsetActionVariableDecoder(parser.DefaultVariableDecoder):

    def decodeVariables(self, cpc, dc, context):
        try:
            util.log_info('IfrpsetActionVariableDecoder: Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            util.log_debug("If Rp Set Block is : ",decoderhandler.getCurrentBlock())
            util.log_debug("Individual Line is : ",decoderhandler.getCurrentBlock().getTokens())
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 0)
            self.parseRoutePolicyIfRPSetAction(dc, cursor)
        except Exception:
            traceback.print_exc()

    def parseRoutePolicyIfRPSetAction(self, dc, cursor):
        util.log_info('RoutePolicyIfRPSetActionVariableDecoder: parseRoutePolicyIfRPSetAction')
        decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
        command_block = [str(cmd).strip() for cmd in decoderhandler.getCurrentBlock().toString().split('\n')]
        util.log_info(command_block)
        rp_name = command_block[0].split(" ")
        util.log_info(rp_name)
        decoderhandler.addTokenValue("$name",rp_name[1])
        if_then = command_block[1].split(" ")
        util.log_info(if_then)
        if if_then[0] == 'if':
            decoderhandler.addTokenValue("$if_rp_set/match",if_then[1])
            decoderhandler.addTokenValue("$if_rp_set/prefix-set",if_then[3])
            for i in range(2,len(command_block)):
                command = command_block[i].split()
                if "prepend" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/as-path",command[2])
                if "med" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/med",command[2])
                if "local-preference" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/local-preference",command[2])
                if "set" and "next-hop" and "self" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/next-hop-self","true")
                if "set" and "next-hop" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/next-hop",command[2])
                if "community" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/community",command[2])
                if "weight" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/weight",command[2])
                if "pass" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/pass","true")
                if "drop" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/drop","true")
                if "done" in command:
                    decoderhandler.addTokenValue("$if_rp_set/action/done","true")
                if "endif" in command:
                    return
                decoderhandler.addTokenValue("$if_rp_set/action/id",command_block[i])

        elif if_then[0] != "if":
            for i in range(1,len(command_block)):
                command = command_block[i].split()
                util.log_info(command)
                if "prepend" in command:
                    decoderhandler.addTokenValue("$action/as-path",command[2])
                if "med" in command:
                    decoderhandler.addTokenValue("$action/med",command[2])
                if "local-preference" in command:
                    decoderhandler.addTokenValue("$action/local-preference",command[2])
                if "set" and "next-hop" and "self" in command:
                    decoderhandler.addTokenValue("$action/next-hop-self","true")
                if "set" and "next-hop" in command:
                    decoderhandler.addTokenValue("$action/next-hop",command[2])
                if "community" in command:
                    decoderhandler.addTokenValue("$action/community",command[2])
                if "weight" in command:
                    decoderhandler.addTokenValue("$action/weight",command[2])
                if "pass" in command:
                    decoderhandler.addTokenValue("$action/pass","true")
                if "drop" in command:
                    decoderhandler.addTokenValue("$action/drop","true")
                if "done" in command:
                    decoderhandler.addTokenValue("$action/done","true")
                if "endif" in command:
                    return
                decoderhandler.addTokenValue("$action/id",command_block[i])
        else:
            return
