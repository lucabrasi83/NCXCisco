from ncxparser import util, parser, tokendecoderhandler, decoderutil
from ncxparser import tokendecoder
import traceback
import re

class RouterOspfNetTokenDecoder(tokendecoder.AbstractTokenDecoder):

    def __init__(self):
        util.log_info('RouterOspfNetTokenDecoder: Initializing ospf network')

    def decodeToken(self, dc):
        try:
            util.log_info('RouterOspfNetTokenDecoder: Decode token')
            decoderhandler = tokendecoderhandler.TokenDecoderHandler(dc)
            tokenText = decoderhandler.getTokenText()
            value = decoderhandler.getValueAtCurrentIndex()
            decoderhandler.addTokenValue(tokenText, value)
            block = decoderhandler.getCurrentBlock()
            util.log_info("OSPF Block is: " + str(block))
            lines = block.toString().split("\n")
            lines = [line.strip(' ') for line in lines]
            util.log_info("OSPF Lines is: " + str(lines))
            area_nssa_list = []
            for new_line in lines:
                if new_line.__contains__('area') and new_line.__contains__('nssa'):
                    area_nssa_list.append(new_line)
            util.log_info("Area NSSA List is : " + str(area_nssa_list))
            for new_line in lines:
                if new_line.__contains__('vrf-lite'):
                    decoderhandler.addTokenValue("vrf-lite", "true")
                elif new_line.__contains__('network'):
                    network_line = new_line.split(' ')
                    decoderhandler.addTokenValue("../router-ospf/network/ip-address", network_line[1])
                    decoderhandler.addTokenValue("../router-ospf/network/wild-card", network_line[2])
                    decoderhandler.addTokenValue("../router-ospf/network/area", network_line[4])
                    for area in area_nssa_list:
                        area_line = area.split(' ')
                        util.log_info("Area Line is: " + str(area_line))
                        util.log_info("Network Line is: " + str(network_line))
                        if network_line[4] == area_line[1]:
                            decoderhandler.addTokenValue("../router-ospf/network/nssa", "true")
                            if "suppress-fa" in area_line:
                                decoderhandler.addTokenValue("../router-ospf/network/translate", "true")
                            else:
                                decoderhandler.addTokenValue("../router-ospf/network/translate", "false")
                        else:
                            decoderhandler.addTokenValue("../router-ospf/network/nssa", "false")

        except Exception:
            traceback.print_exc()