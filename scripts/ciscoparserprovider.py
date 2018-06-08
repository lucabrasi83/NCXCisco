#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2014-2015 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import parser, decoderutil, util
import traceback
from ncxparser.tokendecoders import greedytokendecoder, accesstokendecoder, routepolicytokendecoder, \
    routetargettokendecoder, snmpversiontokendecoder, commauthtypetokendecoder, interfacetokendecoder, slatokendecoder, \
    rtimporttokendecoder, passwordleveltokendecoder

from cisco.tokendecoders import staticroutenexthopinterfacetokendecoder, routemapsetactiontokendecoder, \
    routemapmatchconditiontokendecoder, cryptoprofilematchipaddresstokendecoder, cryptopolicyhashtokendecoder, \
    classmapmatchvaluetokendecoder, interfacenumbertokendecoder, interfaceospfospfidtokendecoder, cryptoikeencrptiontypetokendecoder, \
    routerospfmetrictokendecoder, routerospfredistributetokendecoder, enumtokendecoder, sladestinationporttokendecoder, \
    routereigrptokendecoder, vrfroutereigrptokendecoder, ipslaoperationtypetokendecoder, slahttprequesttypetokendecoder,vrfdeftokendecoder, \
    ipslaentrynumbertokendecoder, ipslarespondertokendecoders, bgpneighbortokendecoder, bgppeergrouptokendecoder, routereigrpaddfamilytokendecoder, \
    routereigrpafinttokendecoder, policymaprandomtokendecoder, routerbgprouteridtokendecoder, natstatictokendecoder,trackiptypetokendecoder, \
    trackbooleantypetokendecoder, tracklisttypetokendecoder,netflowipv4optionstokendecoder, netflowapplicationoptiontokendecoder, \
    netflowartoptiontokendecoder, netflowcounteroptiontokendecoder, netflowtimestamptokendecoder, netflowtransporttokendecoder, trackdelaytokendecoder, cryptoprofilenametokendecoder, \
    nameservertokendecoder, ipnatpooloptionsdecoder, slasourceiptokendecoder, enablesecretpassworddecoder, legacynetflowsourcetokendecoder, \
    legacynetflowversiontokendecoder, ntpserverprefertokendecoder, eemactionstatementtokendecoder, newroutetargettokendecoder, cryptopolicyikeversion, \
    routerbgpasnumbertokendecoder, snmpsystemshutdowntokendecoder, sladestinationiptokendecoder, netflowcollectinttokendecoder, trackiptypetokendecoder, \
    cryptopeertokendecoder, platformconfigtypetokendecoder, masteriptokendecoder, trackiptokendecoder, efpencapsulationtokendecoder, \
    routerbgpallowasintokendecoder, efpserviceinstancetokendecoder, sshscpenabletokendecoder, erpsapsportidtokendecoder, interfacenametokendecoder, \
    trackobjectlisttokendecoder, prefixsetmatchtokendecoder, hsrpauthtokendecoder, cryptopeersetattrtokendecoder, routerospfnettokendecoder, \
    dmvpnnametokendecoder, mplsprioritytokendecoder, trafficengtokendecoder, secondaryipaddtokendecoder, secondarynetmasktokendecoder, \
    nbarcustomtokendecoder
    

from cisco.variabledecoders import objectgroupvariabledecoder, aclrulevariabledecoder, \
    classmaphttpurlvariabletokendecoder, classmapvariabletokendecoder, newroutevariabledecoder, \
    newvrfroutevariabledecoder, transformsetvariabledecoder, vtyvariabledecoder, featuresvariabledecoder, \
    routereigrpredistvariabledecoder, aaagroupvariabledecoder,portchannelipredirectsvariabletokendecoder,servicetimestampsvariabledecoder, \
    snmpifmibvariabletockendecoder, iphttpvariabletokendecoder,legacynetflowinterfacenamesvariabledecoder, nhrpmapsvariabletokendecoder, \
    routerospfredistvariabledecoder, routevariabledecoder, \
    routepolicyentriesvariabledecoder, snmpviewnamevariabledecoder, routerospfdefalwaysvariabledecoder, routerbgpredistvariabledecoder, \
    pfrclassvariabletokendecoder, ifrpsetactionvariabledecoder, objectgroupservicevariabledecoder, pseudowireinterfacedecoder, \
    tacacsserverprivatevariabledecoder, aaaserverprivatevariabledecoder


class CiscoParserConfigProvider(parser.AbstractParserConfigProvider):
    def __init__(self):
        try:
            parser.AbstractParserConfigProvider.__init__(self, 'ALL|ALL|ALL|IOSXE|Cisco Systems')
            self.set_result_processor('ALL|ALL|ALL|IOSXE|Cisco Systems')
            self.set_block_parser('ALL|ALL|ALL|IOSXE|Cisco Systems')
            self.set_tree_selector('ALL|ALL|ALL|IOSXE|Cisco Systems')
            self.variableDecoderMap = {
                #'/controller:devices/device/l3features:vrfs/vrf/static-routes/static-route': staticroutervariabledecoder.StaticRouterVariableDecoder(),
                #'/controller:devices/device/l3features:static-routes/static-route': staticroutervariabledecoder.StaticRouterVariableDecoder(),
                '/controller:devices/device/acl:object-groups-acl/object-group/networks/network': objectgroupvariabledecoder.ObjectGroupVariableDecoder(),
                '/controller:devices/device/acl:object-groups-acl/object-group/services/service': objectgroupservicevariabledecoder.ObjectGroupServiceVariableDecoder(),
                '/controller:devices/device/acl:access-lists/access-list/acl-rules/acl-rule': aclrulevariabledecoder.AclRuleVariableDecoder(),
                '/controller:devices/device/qos:class-maps/class-map/class-match-condition/http-url': classmaphttpurlvariabletokendecoder.ClassMapHttpUrlVariableTokenDecoder(),
                '/controller:devices/device/qos:class-maps/class-map/class-match-condition': classmapvariabletokendecoder.ClassMapVariableTokenDecoder(),
                '/controller:devices/device/qos:pfr-classes/pfr-class': pfrclassvariabletokendecoder.PfrClassVariableTokenDecoder(),
                '/controller:devices/device/l3features:routes/route': newroutevariabledecoder.NewRouteVariableDecoder(),
                '/controller:devices/device/l3features:routes/route/options': routevariabledecoder.RouteVariableDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/routes/route/options': newvrfroutevariabledecoder.NewVrfRouteVariableDecoder(),
                '/controller:devices/device/dmvpn:transform-sets/transform-set': transformsetvariabledecoder.TransformSetVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:vty-configs/vty-config': vtyvariabledecoder.VtyVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:features': featuresvariabledecoder.FeaturesVariableDecoder(),
                '/controller:devices/device/l2features:port-channels/port-channel': portchannelipredirectsvariabletokendecoder.PortChannelVariableTokenDecoder(),
                '/controller:devices/device/l3features:eigrp/router-eigrp/address-family/redistribute':routereigrpredistvariabledecoder.RouterEigrpRedistVariableDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/redistribute':routerbgpredistvariabledecoder.RouterBgpRedistVariableDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-eigrp/eigrp/redistribute':routereigrpredistvariabledecoder.RouterEigrpRedistVariableDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute':routerospfredistvariabledecoder.RouterOspfRedistVariableDecoder(),
		        '/controller:devices/device/basicDeviceConfigs:service-time-stamps':servicetimestampsvariabledecoder.ServiceTimeStampsVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/snmp-ifmib-ifindex-persist':snmpifmibvariabletockendecoder.SnmpIfMibVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:aaa-group/aaa-new-model':aaagroupvariabledecoder.AaaGroupVariableDecoder(),
                #'/controller:devices/device/basicDeviceConfigs:aaa-group/tacacs-server-group':tacacsservergroupvariabledecoder.TacacsServerGroupVariableDecoder(),
                '/controller:devices/device/l3features:netflow/flow-exports/interface-names': legacynetflowinterfacenamesvariabledecoder.LegacyNetflowInterfaceNamesVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:http':iphttpvariabletokendecoder.IpHttpVariableTokenDecoder(),
                #'/controller:devices/device/l3features:vrfs/vrf/router-bgp/address-family': addressfamilyvariabledecoder.AddressFamilyVariableDecoder(),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/nhrp-maps':nhrpmapsvariabletokendecoder.NhrpMapsVariableTokenDecoder(),
                '/controller:devices/device/l3features:route-policies/route-policy/route-policy-entries':routepolicyentriesvariabledecoder.RoutePolicyEntriesVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/view-name':snmpviewnamevariabledecoder.SnmpViewNameVariableDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/inject-default-route': routerospfdefalwaysvariabledecoder.RouterOspfDefAlwaysVariableDecoder(),
                '/controller:devices/device/l3features:routepolicies/routepolicy/if_rp_set/action':ifrpsetactionvariabledecoder.IfrpsetActionVariableDecoder(),
                '/controller:devices/device/l3features:routepolicies/routepolicy/action':ifrpsetactionvariabledecoder.IfrpsetActionVariableDecoder(),
                 '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/description':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/encapsulation':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/neighbor-ip':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/interface-name':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/vc-type':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/l2features:psuedo-wire/pseudo-wire-interface/control-world':pseudowireinterfacedecoder.PseudoWireInterfaceDecoder(),
                '/controller:devices/device/basicDeviceConfigs:aaa-group/tacacs-group-servers/tacacs-servers-private':tacacsserverprivatevariabledecoder.TacacsServerPrivateVariableDecoder(),
                '/controller:devices/device/basicDeviceConfigs:aaa-group/aaa-servers-private':aaaserverprivatevariabledecoder.AaaServerPrivateVariableDecoder()
                }

            self.decoderMap = {
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/ipv4/ipv4-options/ipv4-option': netflowipv4optionstokendecoder.NetflowIPv4TokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/application/application-options/application-option': netflowapplicationoptiontokendecoder.ApplicationOptionTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/art/art-options/art-option': netflowartoptiontokendecoder.ArtOptionTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/interface/interface-options/interface-option': netflowcollectinttokendecoder.NetflowCollectIntTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/counter/counter-options/counter-option': netflowcounteroptiontokendecoder.CounterOptionTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/transport/transport-options/transport-option': netflowtransporttokendecoder.TransportOptionTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/collect/timestamp/timestamp-options/timestamp-option': netflowtimestamptokendecoder.TimeStampsOptionTokenDecoder(),
                '/controller:devices/device/l3features:eem-applets/event-manager-applet/actions/action/label':eemactionstatementtokendecoder.EEMActionStatementTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/system-shutdown':snmpsystemshutdowntokendecoder.SNMPSystemShutDownTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-exports/source': legacynetflowsourcetokendecoder.LegacyNetflowSourceTokenDecoder(),
                '/controller:devices/device/l3features:netflow/flow-exports/version': legacynetflowversiontokendecoder.LegacyNetflowVersionTokenDecoder(),
                #'/controller:devices/device/l3features:tracks/track/delay-down-time': trackdelaytokendecoder.TrackDelayTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/ip-type': trackiptypetokendecoder.TrackIPTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/list-type': tracklisttypetokendecoder.TrackListTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/boolean-type': trackbooleantypetokendecoder.TrackBooleanTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/ip-address': trackiptokendecoder.TrackIpTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/netmask': trackiptokendecoder.TrackIpTokenDecoder(),
                '/controller:devices/device/l3features:tracks/track/object-list/object-number': trackobjectlisttokendecoder.TrackObjectTokenDecoder(),
                '/controller:devices/device/qos:platform-configs/platform-config/configure': platformconfigtypetokendecoder.PlatformConfigTypeTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/neighbor/ip-address':bgpneighbortokendecoder.BgpNeighborTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/peer-group/name':bgppeergrouptokendecoder.BgpPeerGroupTokenDecoder(),
                '/controller:devices/device/l3features:ip-nat/address-translation/inside-global-ip':natstatictokendecoder.NatStaticTokenDecoder(),
                '/controller:devices/device/l3features:eigrp/router-eigrp/eigrp-name':routereigrptokendecoder.RouterEigrpTokenDecoder(),
                '/controller:devices/device/l3features:eigrp/router-eigrp/address-family/as-number':routereigrpaddfamilytokendecoder.RouterEigrpAddFamilyTokenDecoder(),
                '/controller:devices/device/l3features:eigrp/router-eigrp/address-family/af-interface/interface':routereigrpafinttokendecoder.RouterEigrpAfIntTokenDecoder(),
                '/controller:devices/device/qos:policy-maps/policy-map/class-entry/class-name':policymaprandomtokendecoder.PolicyMapRandomTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/name':vrfdeftokendecoder.VrfDefTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-eigrp/eigrp/process-id':vrfroutereigrptokendecoder.VrfRouterEigrpTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/access': accesstokendecoder.AccessTokenDecoder(),
                '/controller:devices/device/l3features:route-policies/route-policy/name': routepolicytokendecoder.RoutePolicyTokenDecoder(
                    'cpl-string'),
                '/controller:devices/device/l3features:vrfs/vrf/rt-import/rt-import': newroutetargettokendecoder.NewRouteTargetTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/rt-export/rt-export': newroutetargettokendecoder.NewRouteTargetTokenDecoder(),
                #'/controller:devices/device/basicDeviceConfigs:snmp/snmp-version': snmpversiontokendecoder.SnmpVersionTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/comm-auth-type': commauthtypetokendecoder.CommAuthTypeTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/name': interfacenametokendecoder.InterfaceNameTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/ip-address': interfacetokendecoder.InterfaceTokenDecoder(),
                #'/controller:devices/device/l3features:static-routes/static-route/interface-name': staticroutenexthopinterfacetokendecoder.StaticRouteNextHopInterfaceTokenDecoder(),
                '/controller:devices/device/l3features:route-maps/route-map/route-map-entries/set-action/value': routemapsetactiontokendecoder.RouteMapSetActionTokenDecoder(),
                '/controller:devices/device/l3features:route-maps/route-map/route-map-entries/match-condition/value': routemapmatchconditiontokendecoder.RouteMapMatchConditionTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto/crypto-profile/match/ip-address': cryptoprofilematchipaddresstokendecoder.CryptoProfileMatchIpAddressTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-policies/crypto-policy/hash': cryptopolicyhashtokendecoder.CryptoPolicyHashTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-policies/crypto-policy/ike-encryption-type': cryptoikeencrptiontypetokendecoder.CryptoIkeEncryptionTypeTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-peers/crypto-peer/address': cryptopeertokendecoder.CryptoPeerTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-peers/crypto-peer/hostname': cryptopeertokendecoder.CryptoPeerTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-peers/crypto-peer/set-attributes/attribute': cryptopeersetattrtokendecoder.CryptoPeerSetAttrTokenDecoder(),
                '/controller:devices/device/qos:class-maps/class-map/class-match-condition/match-value': classmapmatchvaluetokendecoder.ClassMapMatchValueTokenDecoder(),
                #'/controller:devices/device/l2features:port-channels/port-channel/name': interfacenumbertokendecoder.CiscoInterfaceNumberTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/ospf/ospf-id': interfaceospfospfidtokendecoder.InterfaceOspfOspfIdTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/entry-number': ipslaentrynumbertokendecoder.IpSlaEntryNumberTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/responder/is-responder': ipslarespondertokendecoders.IpSLAResponderTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/responder/responder-options/operation-type': ipslarespondertokendecoders.IpSlaResponderOperationTypeTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/operation-type': ipslaoperationtypetokendecoder.IpSlaOperationTypeTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/http-request-type': slahttprequesttypetokendecoder.SlaHttpRequestTypeTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/destination-port': sladestinationporttokendecoder.SlaDestinationPortTokenDecoder(),
                #'/controller:devices/device/l3features:vrfs/vrf/rt-import/rt-import': rtimporttokendecoder.RtImportTokenDecoder(),
                #'/controller:devices/device/l3features:vrfs/vrf/rt-export/rt-export': rtimporttokendecoder.RtImportTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:local-credentials/local-credential/password-level': passwordleveltokendecoder.PasswordLevelTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/aggregate-summary-network/network': greedytokendecoder.GreedyTokenDecoder(2),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/neighbor/description': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/l3features:netflow/flow-exports/flow-export/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/l3features:netflow/flow-records/flow-record/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/l3features:netflow/flow-monitors/flow-monitor/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/l3features:route-maps/route-map/route-map-entries/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/l3features:eem-script/eem-if-errors/interface/correlate': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:clock/summer-time':greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/description':greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto/crypto-profile/description': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/qos:nbar-custom-signatures/nbar-custom-signature/ip-address': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/qos:nbar-custom-signatures/nbar-custom-signature/port-number': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/qos:nbar-custom-signatures/nbar-custom-signature/name': nbarcustomtokendecoder.NbarCustomTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:protocol-discovery': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:secondary-ip-addresses/secondary-ip-address/ip-address': secondaryipaddtokendecoder.SecondaryIpTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:secondary-ip-addresses/secondary-ip-address/netmask': secondarynetmasktokendecoder.SecondaryNetmaskTokenDecoder(),
                '/controller:devices/device/l3features:key-chain/router-key-chain/keys/key-string-password': greedytokendecoder.GreedyTokenDecoder(-1, True),
                '/controller:devices/device/interface:interfaces/interface/hsrp:hsrp/auth-key': hsrpauthtokendecoder.HsrpAuthTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/process-id': routerospfnettokendecoder.RouterOspfNetTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute/value1': routerospfmetrictokendecoder.RouterOspfMetricTokenDecoder(
                    'metric1'),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute/value2': routerospfmetrictokendecoder.RouterOspfMetricTokenDecoder(
                    'metric2'),
                #'/controller:devices/device/l3features:vrfs/vrf/router-ospf/default-inf-value': routerospfmetrictokendecoder.RouterOspfMetricTokenDecoder(
                    #'default-inf-metric'),
                #'/controller:devices/device/l3features:vrfs/vrf/router-ospf/default-inf-value1': routerospfmetrictokendecoder.RouterOspfMetricTokenDecoder(
                    #'default-inf-metric1'),
                #'/controller:devices/device/l3features:vrfs/vrf/router-ospf/default-inf-value2': routerospfmetrictokendecoder.RouterOspfMetricTokenDecoder(
                    #'default-inf-metric2'),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute/bgp-as-number': routerospfredistributetokendecoder.RouterOspfRedistributeTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute/process-id-entry': routerospfredistributetokendecoder.RouterOspfRedistributeTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-ospf/redistribute/ospf-redistribute/eigrp-as-number': routerospfredistributetokendecoder.RouterOspfRedistributeTokenDecoder(),
                #'/controller:devices/device/dmvpn:crypto/crypto-profile/ike-version': enumtokendecoder.EnumTokenDecoder().addToken(
                #    "isakmp", "IKEV1").addToken("ikev2", "IKEV2"),
                '/controller:devices/device/dmvpn:crypto/crypto-profile/ike-profile-name': cryptoprofilenametokendecoder.CryptoProfileNameTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-policies/crypto-policy/policy-number': cryptopolicyikeversion.CryptoPolicyIkeVersionTokenDecoder(),
                '/controller:devices/device/dmvpn:crypto-proposals/crypto-proposal/ike-authentication-type': enumtokendecoder.EnumTokenDecoder().addToken(
                    "md5", "MD5").addToken("sha1", "SHA1").addToken("sha256", "SHA256").addToken("sha384",
                                                                                                 "SHA384").addToken(
                    "sha512", "SHA512"),
                '/controller:devices/device/dmvpn:crypto-proposals/crypto-proposal/ike-encryption-type': enumtokendecoder.EnumTokenDecoder().addToken(
                    "aes-cbc-128", "AES128").addToken("aes-cbc-192", "AES192").addToken("aes-cbc-256", "AES256").addToken("aes-gcm-128","aes-gcm-128").addToken("aes-gcm-256","aes-gcm-256").addToken(
                        "des","DES").addToken("3des","3DES"),
                '/controller:devices/device/dmvpn:crypto-proposals/crypto-proposal/prf': enumtokendecoder.EnumTokenDecoder().addToken(
                    "md5", "MD5").addToken("sha1", "SHA1").addToken("sha256", "SHA256").addToken("sha384",
                                                                                                 "SHA384").addToken(
                    "sha512", "SHA512"),
                '/controller:devices/device/l3features:as-path-acls/as-path-acl/expression': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/l3features:community-lists/community-list/value': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/location': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/contact': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:ntp/ntp-server/ntp-server-address':ntpserverprefertokendecoder.NtpServerPreferTokenDecoder(),
                '/controller:devices/device/l3features:route-maps/route-map/route-map-entries/community-attribute': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/l3features:dhcp-server/dns-server-ip': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/l3features:dhcp-server/dhcp/dns-server-ip': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:snmp/snmp-traps/snmp-trap': greedytokendecoder.GreedyTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/router-id':routerbgprouteridtokendecoder.RouterBgpRouterIdTokenDecoder(),
                '/controller:devices/device/dns:dns-server/name-server/server':nameservertokendecoder.NameServerTokenDecoder(),
                '/controller:devices/device/l3features:ip-nat/address-translation/side':ipnatpooloptionsdecoder.IpNatPoolOptionsDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/source-interface-ip':slasourceiptokendecoder.SlaSourceIpTokenDecoder(),
                '/controller:devices/device/l3features:ip-sla/sla/destination':sladestinationiptokendecoder.SlaDestinationIpTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:local-credentials/enable-secret-password':enablesecretpassworddecoder.EnableSecretPasswordDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/as-number':routerbgpasnumbertokendecoder.RouterBgpAsnumberTokenDecoder(),
                '/controller:devices/device/basicDeviceConfigs:ssh/scp-enable':sshscpenabletokendecoder.SSHSCPenableTokenDecoder(),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/name':dmvpnnametokendecoder.DmvpnNameTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/neighbor/allowas_in_value':routerbgpallowasintokendecoder.RouterBgpAllowasinTokenDecoder(),
                '/controller:devices/device/l3features:vrfs/vrf/router-bgp/peer-group/allowas_in_value':routerbgpallowasintokendecoder.RouterBgpAllowasinTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:efp-service-instances/efp-service-instance/encapsulation-type':efpencapsulationtokendecoder.EfpEncapsulationTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:efp-service-instances/efp-service-instance/service-instance-number':efpserviceinstancetokendecoder.EfpServiceInstanceTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:efp-service-instances/efp-service-instance/vlan-id':efpencapsulationtokendecoder.EfpEncapsulationTokenDecoder(),
                '/controller:devices/device/l3features:ERPS/rings/instance/aps/ports/port-id':erpsapsportidtokendecoder.ErpsApsPortidTokenDecoder(),
                '/controller:devices/device/l3features:ERPS/rings/ring-ports/port-id':erpsapsportidtokendecoder.ErpsApsPortidTokenDecoder(),
                '/controller:devices/device/dmvpn:domain/master-ip':masteriptokendecoder.MasterIpTokenDecoder(),
                '/controller:devices/device/l3features:prefix-sets/prefix-set/match-conditions/match-condition/ip-prefix':prefixsetmatchtokendecoder.PrefixSetMatchTokenDecoder(),
                '/controller:devices/device/interface:interfaces/interface/interface-ext:efp-service-instances/efp-service-instance/description':efpencapsulationtokendecoder.EfpEncapsulationTokenDecoder(),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/tunnel-mpls/traffic-eng':trafficengtokendecoder.TrafficEngTokenDecoder(),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/tunnel-mpls/setup-priority':mplsprioritytokendecoder.MplsPriorityTokenDecoder(),
                '/controller:devices/device/dmvpn:dmvpntunnels/dmvpntunnel/tunnel-mpls/hold-priority':mplsprioritytokendecoder.MplsPriorityTokenDecoder()
                }
            decoderutil.DecoderUtil().initCommanDecoders(self.decoderMap)
        except Exception:
            traceback.print_exc()

    def register(self):
        parser.register_config_provider('ALL|ALL|ALL|ALL|Cisco Systems', self)
        parser.register_config_provider('ALL|ALL|ALL|IOSXE|Cisco Systems', self)
        util.log_info('calling register config provider for cisco')

    def unregister(self):
        parser.unregister_config_provider('ALL|ALL|ALL|ALL|Cisco Systems')
        parser.unregister_config_provider('ALL|ALL|ALL|IOSXE|Cisco Systems')
        util.log_info('calling unregister config provider for cisco')
