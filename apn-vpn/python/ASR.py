# -*- mode: python; python-indent: 4 -*-
import ncs
from ncs.application import Service

import apn.common
import ipaddress

class ASR_ServiceCallbacks(Service):

    @Service.pre_modification
    def cb_pre_modification(self, tctx, op, kp, root, proplist):
        self.log.info('>>> Service premod(service=', kp, ') <<<')

    @Service.create
    def cb_create(self, tctx, root, service, proplist):
        # ~ is /APN/apn
        self.log.info('>>> Starting APN service create (service=', service._path, ')')

        self.log.info('# Applying templates for service [', service.name, ']')
        vars = ncs.template.Variables()

        # /APN/apn service variables (direct)
        vars.add('VAR_APN', service.name)
        vars.add('VAR_VRF', service.vrf)
        vars.add('VAR_TUNNEL_LOOPBACK_IP', service.tunnel_transport_ip_addr)
        vars.add('VAR_RULEBASE_NAME', service.ac_rulebase)
        vars.add('VAR_APN_NAT_ACL_NAME', 'ACL-' + service.name + '-NAT')

        # /APN/apn service variables (computed)
        vars.add('VAR_TUNNEL_IF_NAME', service.name + '-gre')
        vars.add('VAR_TUNNEL_LOOPBACK_NAME', 'gi-loopback-' + service.name)

        tunnel_prefix = ipaddress.ip_network(service.tunnel_customer_ip_subnet)
        vars.add('VAR_PACKET_NODE_TUNNEL_IP_PREFIX', str(tunnel_prefix[1]) + '/' + str(tunnel_prefix.prefixlen))
        vars.add('VAR_EXT_ROUTER_TUNNEL_IP_ADDR', str(tunnel_prefix[-2]))
        vars.add('VAR_EXT_ROUTER_TUNNEL_IP_MASK', str(tunnel_prefix.netmask))
        
        # Computed
        for tid in range(1001, 3999):
            if tid not in root.devices.device[root.APN__APN.ext_router.node].config.ios__interface.Tunnel:
                self.log.debug('### Tunnel ID search.. found available ', tid)
                vars.add('VAR_EXT_ROUTER_TUNNEL_ID', tid)
                break;

        # /APN/packet-node variables
        packet_node = root.APN__APN.packet_node[service.node]
        vars.add('VAR_GI_CONTEXT_NAME', packet_node.gi_context)
        vars.add('VAR_APN_CONTEXT_NAME', packet_node.apn_context)

        # /APN/ext-router variables
        vars.add('VAR_EXT_ROUTER_BGP_AS', root.APN__APN.ext_router.bgp.as_number)
        ext_router_gi_pfx = ipaddress.ip_interface(root.APN__APN.ext_router.subnets.ipv4_gi)
        vars.add('VAR_EXT_ROUTER_GI_IP_ADDR', str(ext_router_gi_pfx.ip))
        vars.add('VAR_EXT_ROUTER_GI_IP_MASK', str(ext_router_gi_pfx.netmask))
        ext_router_inet_pfx = ipaddress.ip_interface(root.APN__APN.ext_router.subnets.ipv4_internet)        
        vars.add('VAR_EXT_ROUTER_INET_IP_ADDR', str(ext_router_inet_pfx.ip))
        vars.add('VAR_EXT_ROUTER_INET_IP_MASK', str(ext_router_inet_pfx.netmask))
        vars.add('VAR_EXT_ROUTER_INET_GATEWAY', str(ipaddress.ip_interface(root.APN__APN.ext_router.subnets.ipv4_internet).network[-2]))

        # /ncs:devices/ncs:device[service.node]/ncs:config variables
        packet_node_gi_context_config = root.ncs__devices.ncs__device[service.node].ncs__config.context[packet_node.gi_context]
        for bgp in packet_node_gi_context_config.router.bgp:
            vars.add('VAR_PACKET_NODE_BGP_ROUTER_ID', bgp.router_id)
            vars.add('VAR_PACKET_NODE_BGP_AS', bgp.as_num)
        
        for ip in packet_node_gi_context_config.interface[packet_node.gi_interface].ip.address:
            vars.add('VAR_PACKET_NODE_GI_IP_ADDR', ip.address)

        # apply for ASR5k packet node
        vars.add('VAR_DEVICE', service.node)
        template = ncs.template.Template(service)
        self.log.info('## ', apn.common.template_descr('template-packet-node-gi-context'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
        template.apply('template-packet-node-gi-context', vars)    
        self.log.info('## ', apn.common.template_descr('template-packet-node-apn-context'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
        template.apply('template-packet-node-apn-context', vars)

        # for each /APN/apn/ip-pool-group
        for pool_group in service.ip_pool_group:
            vars.add('VAR_IP_GROUP_NAME', pool_group.name)
            # for each /APN/apn/ip-pool-group/ip-pool
            for ip_pool in pool_group.ip_pool:
                vars.add('VAR_IP_POOL_NAME', ip_pool.name)
                pool_pfx = ipaddress.ip_network(ip_pool.pool)
                vars.add('VAR_IP_POOL_NET', pool_pfx.network_address)
                vars.add('VAR_IP_POOL_MASK', pool_pfx.netmask)   
                
                # apply for both ASR5k and ASR1k 
                vars.add('VAR_DEVICE', service.node)             
                self.log.info('## ', apn.common.template_descr('template-packet-node-gi-context-pool'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
                template.apply('template-packet-node-gi-context-pool', vars)
                vars.add('VAR_DEVICE', root.APN__APN.ext_router.node)     
                self.log.info('## ', apn.common.template_descr('template-ext-router-pool'), ' for pool net [', pool_pfx.network_address, '], mask [', pool_pfx.netmask, ']') 
                template.apply('template-ext-router-pool', vars)

                net_wildcard = str(pool_pfx.network_address) + ' ' + str(pool_pfx.hostmask)
                vars.add('VAR_APN_NAT_ACL_ACE', 'permit ip ' + net_wildcard + ' any')
                self.log.info('## ', apn.common.template_descr('template-ext-router-nat-acl')) 
                template.apply('template-ext-router-nat-acl', vars)

        # apply for ASR1k external router
        vars.add('VAR_DEVICE', root.APN__APN.ext_router.node)        
        template = ncs.template.Template(service)
        self.log.info('## ', apn.common.template_descr('template-ext-router'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
        template.apply('template-ext-router', vars)

        # Configure cpe-firewall (if present), along with ext-router connectivity
        cust = root.APN__APN.customers.customer[service.customer_name]
        if str(cust.cpe_firewall.node) != 'None':
            cpe_firewall_device = cust.cpe_firewall.node
            self.log.info('## Applying firewall config for customer [', cust.name, '], device [', cpe_firewall_device, ']')

            vars.add('VAR_DEVICE', root.APN__APN.ext_router.node)

            vars.add('VAR_EXT_ROUTER_FW_VLAN_ID', cust.cpe_firewall.provider.vlan_id)
            fw_pfx = ipaddress.ip_interface(cust.cpe_firewall.provider.ipv4_address) 
            vars.add('VAR_EXT_ROUTER_FW_IP_ADDR', str(fw_pfx.network[1]))
            vars.add('VAR_EXT_ROUTER_FW_IP_MASK', str(fw_pfx.netmask))
            vars.add('VAR_FW_IP_ADDR', str(fw_pfx.ip))          

            vars.add('VAR_FW_CORP_VLAN_ID', cust.cpe_firewall.corp.vlan_id)              
            corp_pfx = ipaddress.ip_interface(cust.cpe_firewall.corp.ipv4_address) 
            vars.add('VAR_FW_CORP_IP_ADDR', str(corp_pfx.ip))
            vars.add('VAR_FW_CORP_IP_MASK', str(corp_pfx.netmask))

            # ASR1k
            self.log.info('## ', apn.common.template_descr('template-ext-router-cpe-firewall'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
            template.apply('template-ext-router-cpe-firewall', vars)
            # ASAv

            #for ace_entry in cust.cpe_firewall.corp.security_policies.entry:
            #    self.log.info('## ACE: [', ace_entry.ace, ']')

            vars.add('VAR_DEVICE', cpe_firewall_device)
            # CHGCTX to /APN/customers/customer/cpe-firewall/corp/security-policies
            # due to ACL ACE iteration
            template = ncs.template.Template(cust.cpe_firewall.corp.security_policies)
            self.log.info('## ', apn.common.template_descr('template-asa'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
            template.apply('template-asa', vars)   

            # apply FW routes to IP pools
            # for each /APN/apn/ip-pool-group
            for pool_group in service.ip_pool_group:
                # for each /APN/apn/ip-pool-group/ip-pool
                for ip_pool in pool_group.ip_pool:
                    pool_pfx = ipaddress.ip_network(ip_pool.pool)
                    vars.add('VAR_IP_POOL_NET', pool_pfx.network_address)
                    vars.add('VAR_IP_POOL_MASK', pool_pfx.netmask)  
                    self.log.info('## ', apn.common.template_descr('template-asa-pool-routing'), ' for APN service [', service.name, '], packet node [', service.node, ']') 
                    template.apply('template-asa-pool-routing', vars) 


        self.log.info('<<< Finished APN service create (service=', service._path, ')')

    #@Service.pre_lock_create
    #def cb_pre_lock_create(self, tctx, root, service, proplist):
    #    self.log.info('Service plcreate(service=', service._path, ')')

    @Service.post_modification
    def cb_post_modification(self, tctx, op, kp, root, proplist):
        self.log.info('>>> Service postmod(service=', kp, ') <<<')
        apn.common.log_service(self, tctx, op, kp, root)


class Main(ncs.application.Application):
    def setup(self):
        # The application class sets up logging for us. It is accessible
        # through 'self.log' and is a ncs.log.Log instance.
        self.log.info('ASR service RUNNING')

        # Service callbacks require a registration for a 'service point',
        # as specified in the corresponding data model.
        #
        self.register_service('ASR-servicepoint', ASR_ServiceCallbacks)

        # If we registered any callback(s) above, the Application class
        # took care of creating a daemon (related to the service/action point).

        # When this setup method is finished, all registrations are
        # considered done and the application is 'started'.

        with ncs.maapi.Maapi() as m:
            m.install_crypto_keys()
            
    def teardown(self):
        # When the application is finished (which would happen if NCS went
        # down, packages were reloaded or some error occurred) this teardown
        # method will be called.

        self.log.info('ASR service FINISHED')
