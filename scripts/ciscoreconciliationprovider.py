#
# This computer program is the confidential information and proprietary trade
# secret of Anuta Networks, Inc. Possessions and use of this program must
# conform strictly to the license agreement between the user and
# Anuta Networks, Inc., and receipt or possession does not convey any rights
# to divulge, reproduce, or allow others to use this program without specific
# written authorization of Anuta Networks, Inc.
#
# Copyright (c) 2018-2019 Anuta Networks, Inc. All Rights Reserved.

from ncxparser import parser, util
import traceback

try:
    class CiscoReconciliationConfigProvider(parser.AbstractReconciliationPreProcessor):
        def __init__(self):
            pass

        def afterCommandGeneration(self, handle, ctx):
            plat_per_ace = plat_per_filter = 0
            list_present = []
            for i in range(int(handle.getOperationCount(ctx))):
                cmds = str(handle.getCommands(ctx, i))
                util.log_info('OP: %s CMDS: %s' % (i, cmds))
                list_present.append(i)
                if cmds.__contains__('platform qos match-statistics per-ace'):
                    plat_per_ace = i
                elif cmds.__contains__('platform qos match-statistics per-filter'):
                    plat_per_filter = i
            if plat_per_filter > plat_per_ace:
                list_present[plat_per_filter], list_present[plat_per_ace] = list_present[plat_per_ace], list_present[plat_per_filter]
                util.log_info('Modified Order: %s' % (list_present))

            handle.applyOrder(ctx, list_present)

        def register(self, name):
            try:
                parser.register_reconciliation_preprocessor(name, CiscoReconciliationConfigProvider())
                util.log_info('calling register reconciliation config provider for cisco version: %s' %(name))
            except AttributeError:
                pass

        def unregister(self, name):
            try:
                parser.unregister_reconciliation_preprocessor(name)
                util.log_info('calling unregister reconciliation config provider for cisco version: %s' %(name))
            except AttributeError:
                pass

except AttributeError:
    pass