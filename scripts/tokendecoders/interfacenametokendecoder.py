#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.


from org.apache.http.conn.util import InetAddressUtils
from ncxparser import tokendecoderhandler
from ncxparser import tokendecoder, util
import traceback, re

class InterfaceNameTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def decodeToken(self, decoderContext):
        try:
            util.log_info('InterfaceNameTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
            tokenText = decoderhandler.getTokenText()
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            block = decoderhandler.getCurrentBlock()
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info('BLOCK for INFNAME= %s' %(block))
            found_trunk = False
            found_dynamic = False
            found_access = False
            found_voice = False
            found_span_port = False
            found_span_bpd = False
            found_dot1q = False
            
            for line in lines:
                if re.search('^switchport mode trunk$', line) is not None:
                    found_trunk = True
                elif re.search('^switchport mode access$', line) is not None:
                    found_access = True
                elif re.search('^switchport mode dynamic', line) is not None:
                    found_dynamic = True
                elif re.search('^switchport voice', line) is not None:
                    found_voice = True
                elif re.search('^switchport mode dot1q-tunnel$', line) is not None:
                    found_dot1q = True
                elif re.search('^spanning-tree portfast$', line) is not None:
                    found_span_port = True
                elif re.search('^spanning-tree bpduguard enable$', line) is not None:
                    found_span_bpd = True
                

            if not found_span_port:
                decoderhandler.addTokenValue("portfast", "false")
            else:
                decoderhandler.addTokenValue("portfast", "true")
            if not found_span_bpd:
                decoderhandler.addTokenValue("bpduguard", "false")
            else:
                decoderhandler.addTokenValue("bpduguard", "true")

            if found_trunk:
                decoderhandler.addTokenValue("mode", "trunk")
            elif found_voice:
                decoderhandler.addTokenValue("mode", "voice")
            elif found_access:
                decoderhandler.addTokenValue("mode", "access")
            elif found_dynamic:
                decoderhandler.addTokenValue("mode", "dynamic")
            elif found_dot1q:
                decoderhandler.addTokenValue("mode", "dot1q-tunnel")

            if not found_trunk and not found_access and not found_voice and not found_dynamic and not found_dot1q:
                if value.__contains__('.'):
                    decoderhandler.addTokenValue("mode", "sub-interface")
                elif value.__contains__('vlan') or value.__contains__('Vlan'):
                    decoderhandler.addTokenValue("mode", "vlan")
                elif value.__contains__('Loopback') or value.__contains__('loopback'):
                    decoderhandler.addTokenValue("mode", "loopback-interface")
                elif value.__contains__('tunnel') or value.__contains__('Tunnel'):
                    decoderhandler.addTokenValue("mode", "tunnel")
                else:
                    decoderhandler.addTokenValue("mode", "l3-interface")
    
            self.interfaceBooleans(decoderContext)
            return 1
        except Exception:
            traceback.print_exc()

    def interfaceBooleans(self,decoderContext):
        try:
            util.log_info('InterfaceNameTokenDecoder : InterfaceBooleans : Decoding variable')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(decoderContext)
            current_block = decoderhandler.getCurrentBlock().toString()
            block_tokens = str(current_block).split(" ")
            util.log_info("Block_Tokens : ",block_tokens)
            command_block = []
            for cmds in block_tokens:
                command_block.append(cmds.strip("\n"))
            util.log_info("command_block : ",command_block)
            if "redirects" in command_block:
                redirects_index = command_block.index("redirects")
                if command_block[redirects_index-2] == "no" and command_block[redirects_index-1] == "ipv4":
                    decoderhandler.addTokenValue("$interface-ext:ipv4-redirects", "false")
                elif command_block[redirects_index-1] == "ipv4":
                    decoderhandler.addTokenValue("$interface-ext:ipv4-redirects", "true")
                if command_block[redirects_index-2] == "no" and command_block[redirects_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-redirects", "false")
                elif command_block[redirects_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-redirects", "true")
            if "unreachables" in command_block:
                unreachables_index = command_block.index("unreachables")
                if command_block[unreachables_index-2] == "no" and command_block[unreachables_index-1] == "ipv4":
                    decoderhandler.addTokenValue("$interface-ext:ipv4-unreachables-disable", "false")
                elif command_block[unreachables_index-1] == "ipv4":
                    decoderhandler.addTokenValue("$interface-ext:ipv4-unreachables-disable", "true")
                if command_block[unreachables_index-2] == "no" and command_block[unreachables_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-unreachables", "false")
                elif command_block[unreachables_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-unreachables", "true")
            if "proxy-arp" in command_block:
                proxy_arp_index = command_block.index("proxy-arp")
                if command_block[proxy_arp_index-2] == "no" and command_block[proxy_arp_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-proxy-arp", "false")
                elif command_block[proxy_arp_index-1] == "ip":
                    decoderhandler.addTokenValue("$interface-ext:ip-proxy-arp", "true")
            if "dampening" in command_block:
                dampening_index = command_block.index("dampening")
                if command_block[dampening_index-1] == "no":
                    decoderhandler.addTokenValue("$interface-ext:dampening", "false")
                else:
                    decoderhandler.addTokenValue("$interface-ext:dampening", "true")
            if "no ip address" in current_block:
                decoderhandler.addTokenValue("$interface-ext:no-ip-address", "true")
            else:
                decoderhandler.addTokenValue("$interface-ext:no-ip-address", "false")
            cdp_index = []
            for cdp in range(len(command_block)):
                if command_block[cdp] == "cdp":
                    cdp_index.append(cdp)
            if command_block[-1] == "cdp":
                if command_block[-2] == "no":
                    decoderhandler.addTokenValue("$cdp", "disable")
                else:
                    decoderhandler.addTokenValue("$cdp", "enable")
            else:
                for cdpid in cdp_index:
                    if command_block[cdpid+1] == "tlv":
                        if command_block[cdpid-1] == "no":
                            decoderhandler.addTokenValue("$interface-ext:cdp-tlv-app", "false")
                        else:
                            decoderhandler.addTokenValue("$interface-ext:cdp-tlv-app", "true")
                    else:
                        if command_block[cdpid-1] == "no":
                            decoderhandler.addTokenValue("$cdp", "disable")
                        else:
                            decoderhandler.addTokenValue("$cdp", "enable")
        except Exception:
            traceback.print_exc()

    def matchToken(self, configParserContext, configToken, idx, toks):
        return 1


    def isMultilineDecoder(self):
        return False


