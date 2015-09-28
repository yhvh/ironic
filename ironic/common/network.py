# Copyright 2014 Rackspace, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from neutronclient.v2_0 import client as clientv20
from oslo_config import cfg
import stevedore

from ironic.common import exception
from ironic.common import keystone


CONF = cfg.CONF
CONF.import_opt('my_ip', 'ironic.netconf')


neutron_opts = [
    cfg.StrOpt('url',
               default='http://$my_ip:9696',
               help='URL for connecting to neutron.'),
    cfg.IntOpt('url_timeout',
               default=30,
               help='Timeout value for connecting to neutron in seconds.'),
    cfg.IntOpt('retries',
               default=3,
               help='Client retries in the case of a failed request.'),
    cfg.StrOpt('auth_strategy',
               default='keystone',
               choices=('keystone', 'noauth'),
               help='Default authentication strategy to use when connecting '
                    'to neutron. Can be either "keystone" or "noauth". '
                    'Running neutron in noauth mode (related to but not '
                    'affected by this setting) is insecure and should only be '
                    'used for testing.'),
    cfg.StrOpt('cleaning_network_uuid',
               help='UUID of the network to create Neutron ports on when '
                    'booting to a ramdisk for cleaning/zapping using '
                    'Neutron DHCP')
]


network_provider_opts = [
    cfg.StrOpt('network_provider',
               default='none',
               choices=('neutron_plugin', 'none'),
               help='Network provider to use for switching to cleaning'
                    '/provisioning/tenant network while provisioning.'
                    '"neutron_plugin" uses Neutron and "none" uses a no-op'
                    'provider.'),
    cfg.StrOpt('provisioning_network_uuid',
               help='UUID of the network to create Neutron ports on when'
                    'booting to a ramdisk for provisioning. This will be'
                    'ignored when neutron_provider is set to none.')
]


CONF.register_opts(neutron_opts, group='neutron')
CONF.register_opts(network_provider_opts)


def get_network_provider(task):
    provider_name = CONF.network_provider
    if task.node.network_provider:
        provider_name = task.node.network_provider

    try:
        _extension_manager = stevedore.driver.DriverManager(
            'ironic.network',
            provider_name,
            invoke_on_load=True)
    except RuntimeError:
        raise exception.NetworkProviderNotFound(provider_name=provider_name)

    _network_provider = _extension_manager.driver

    # TODO(lazy_prince) Need to check for binding extensions loaded in neutron

    return _network_provider


def get_neutron_client(token=None):
    """Utility function to create Neutron client."""
    params = {
        'timeout': CONF.neutron.url_timeout,
        'retries': CONF.neutron.retries,
        'insecure': CONF.keystone_authtoken.insecure,
        'ca_cert': CONF.keystone_authtoken.certfile,
    }

    if CONF.neutron.auth_strategy not in ['noauth', 'keystone']:
        raise exception.ConfigInvalid('Neutron auth_strategy should be '
                                      'either "noauth" or "keystone".')

    if CONF.neutron.auth_strategy == 'noauth':
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = 'noauth'
    elif (CONF.neutron.auth_strategy == 'keystone' and
          token is None):
        params['endpoint_url'] = (CONF.neutron.url or
                                  keystone.get_service_url('neutron'))
        params['username'] = CONF.keystone_authtoken.admin_user
        params['tenant_name'] = CONF.keystone_authtoken.admin_tenant_name
        params['password'] = CONF.keystone_authtoken.admin_password
        params['auth_url'] = (CONF.keystone_authtoken.auth_uri or '')
        if CONF.keystone.region_name:
            params['region_name'] = CONF.keystone.region_name
    else:
        params['token'] = token
        params['endpoint_url'] = CONF.neutron.url
        params['auth_strategy'] = None

    return clientv20.Client(**params)


def get_node_vif_ids(task):
    """Get all VIF ids for a node.

    This function does not handle multi node operations.

    :param task: a TaskManager instance.
    :returns: A dict of the Node's port and portgroup UUIDs and their
              associated VIFs

    """
    port_vifs = {}
    for portgroup in task.portgroups:
        vif = portgroup.extra.get('vif_port_id')
        if vif:
            port_vifs[portgroup.uuid] = vif
    for port in task.ports:
        vif = port.extra.get('vif_port_id')
        if vif:
            port_vifs[port.uuid] = vif
    return port_vifs
