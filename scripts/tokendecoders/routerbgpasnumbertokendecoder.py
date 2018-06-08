from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class RouterBgpAsnumberTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        print 'RouterBgpAsnumberTokenDecoder()'

    def decodeToken(self, dc):
        try:
            util.log_info( 'RouterBgpAsnumberTokenDecoder(): Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            current_block = decoderhandler.getCurrentBlock() 
            cursor = util.TokenCursor(decoderhandler.getSearchTokens(), 2, None)
            tokenText = decoderhandler.getTokenText()
            print 'Token text = %s' %(tokenText)
            value = decoderhandler.getValueAtCurrentIndex()
            print 'Value1 = %s' %(value)
            decoderhandler.addTokenValue(tokenText,value)
            block = decoderhandler.getCurrentBlock()
            util.log_info('BLOCK for BGP:', block)
            lines_noformat = block.toString().split("\n")
            lines = []
            for line in lines_noformat:
                if re.search('bgp redistribute-internal', line) is None:
                    line = line.strip(' ')
                    lines.append(line)
                else:
                    lines.append(line)

            log_neighbor = '^bgp log-neighbor-changes$'
            redis_internal = '.*bgp redistribute-internal$'
            redis_internal_vrf = '.*bgp redistribute-internal$'
            def_inf = '^default-information originate$'
            router_id = '^bgp router-id'
            asoverride = 'as-override$'
            redistribute_connected = 'redistribute connected$'
            log_neighbor_found = False
            redis_internal_found = False
            redis_internal_found_vrf = False
            def_inf_found = False
            asoverride_found = False
            redistribute_connected_found = False
            for line in lines:
                if re.search(' vrf ', block.toString()) is None:
                    log_neighbor_match = re.search(log_neighbor, line)
                    if log_neighbor_match is not None:
                        decoderhandler.addTokenValue("log-neighbor-changes", "true")
                        log_neighbor_found = True

                if re.search(' vrf ', block.toString()) is None:
                    router_id_match = re.search(router_id, line)
                    if router_id_match is not None:
                        decoderhandler.addTokenValue("router-id", line.split('bgp router-id ')[1])

                if re.search(' vrf ', block.toString()) is None:
                    redis_internal_match = re.search(redis_internal, line)
                    if redis_internal_match is not None:
                        decoderhandler.addTokenValue("../../name", "GLOBAL")
                        decoderhandler.addTokenValue("redistribute-internal", "true")
                        redis_internal_found = True
                else:
                    vrf = ''
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                    redis_internal_match = re.search(redis_internal_vrf, line)
                    if redis_internal_match is not None:
                        decoderhandler.addTokenValue("../../name", vrf)
                        decoderhandler.addTokenValue("redistribute-internal", "true")
                        redis_internal_found_vrf = True

                if re.search(' vrf ', block.toString()) is None:
                    def_inf_match = re.search(def_inf, line)
                    if def_inf_match is not None:
                        decoderhandler.addTokenValue("../../name", "GLOBAL")
                        decoderhandler.addTokenValue("default-information-originate", "true")
                        def_inf_found = True
                else:
                    vrf = ''
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                    def_inf_match = re.search(def_inf, line)
                    if def_inf_match is not None:
                        decoderhandler.addTokenValue("../../name", vrf)
                        decoderhandler.addTokenValue("default-information-originate", "true")
                        def_inf_found = True

                if re.search(' vrf ', block.toString()) is None:
                    asoverride_match = re.search(asoverride, line)
                    if asoverride_match is not None:
                        decoderhandler.addTokenValue("../../name", "GLOBAL")
                        decoderhandler.addTokenValue("$neighbor/as-override", "true")
                        asoverride_found = True
                else:
                    vrf = ''
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                    asoverride_match = re.search(asoverride, line)
                    if asoverride_match is not None:
                        decoderhandler.addTokenValue("../../name", vrf)
                        decoderhandler.addTokenValue("$neighbor/as-override", "true")
                        asoverride_found = True
                        
                if re.search(' vrf ', block.toString()) is None:
                    redistribute_connected_match = re.search(redistribute_connected, line)
                    if redistribute_connected_match is not None:
                        decoderhandler.addTokenValue("../../name", "GLOBAL")
                        decoderhandler.addTokenValue("$redistribute/protocol", "connected")
                        redistribute_connected_found = True
                else:
                    vrf = ''
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                    redistribute_connected_match = re.search(redistribute_connected, line)
                    if redistribute_connected_match is not None:
                        decoderhandler.addTokenValue("../../name", vrf)
                        decoderhandler.addTokenValue("$redistribute/protocol", "connected")
                        redistribute_connected_found = True

            if not log_neighbor_found:
                decoderhandler.addTokenValue("log-neighbor-changes", "false")

            if not redis_internal_found and re.search(' vrf ', block.toString()) is None:
                decoderhandler.addTokenValue("../../name", "GLOBAL")
                decoderhandler.addTokenValue("redistribute-internal", "false")
            elif not redis_internal_found_vrf and re.search(' vrf ', block.toString()) is not None:
                vrf = ''
                for line in lines:
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                decoderhandler.addTokenValue("../../name", vrf)
                decoderhandler.addTokenValue("redistribute-internal", "false")

            if not def_inf_found and re.search(' vrf ', block.toString()) is None:
                decoderhandler.addTokenValue("../../name", "GLOBAL")
                decoderhandler.addTokenValue("default-information-originate", "false")
            elif not def_inf_found and re.search(' vrf ', block.toString()) is not None:
                vrf = ''
                for line in lines:
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                decoderhandler.addTokenValue("../../name", vrf)
                decoderhandler.addTokenValue("default-information-originate", "false")

            if not asoverride_found and re.search(' vrf ', block.toString()) is None:
                decoderhandler.addTokenValue("../../name", "GLOBAL")
                decoderhandler.addTokenValue("$neighbor/as-override", "false")
            elif not asoverride_found and re.search(' vrf ', block.toString()) is not None:
                vrf = ''
                for line in lines:
                    if re.search(' vrf ', line) is not None:
                        vrf = line.split(' vrf ')[1]
                decoderhandler.addTokenValue("../../name", vrf)
                decoderhandler.addTokenValue("$neighbor/as-override", "false")

            for i in lines:
                if "bgp default ipv4-unicast" == i:
                    decoderhandler.addTokenValue("$bgp-default-ipv4-unicast", "true")
                elif "no bgp default ipv4-unicast" == i:
                    decoderhandler.addTokenValue("$bgp-default-ipv4-unicast", "false")
        except Exception:
            traceback.print_exc()
