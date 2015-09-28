# Copyright 2015 Rackspace, Inc.
# All Rights Reserved
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


from neutronclient.common import exceptions as neutron_exceptions
from oslo_config import cfg
from oslo_context import context
from oslo_log import log

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LI
from ironic.common import network
from ironic.networks import base
from ironic import objects

LOG = log.getLogger(__name__)
CONF = cfg.CONF


def _get_client():
    admin_ctx = context.get_admin_context()
    return network.get_neutron_client(token=admin_ctx.auth_token)


def _list_ports(task):
    """List all ports for a node.

    :param task: a task containing the Node object.
    :returns: A list of all networks for `node`.
    """
    node = task.node
    client = _get_client()

    params = {'device_id': node.instance_uuid}
    instance_ports = client.list_ports(**params).get('ports')
    params = {'binding:host_id': node.uuid}
    node_ports = client.list_ports(**params).get('ports')

    ports = {}
    for port in node_ports + instance_ports:
        ports[port['id']] = port
    return ports.values()


def _get_node_portmap(task):
    """Extract the switch port information for the node.

    :param task: a task containing the Node object.
    :returns: a list describing the switch ports for the node.
    """
    node = task.node

    ports = objects.Port.list_by_node_id(task.context, node.id)
    portmap = []
    for port in ports:
        portmap.append(port.local_link_connection)
    return portmap
    # TODO(jroll) raise InvalidParameterValue if a port doesn't have the
    # necessary info? (probably)


class NeutronV2NetworkProvider(base.NetworkProvider):
    """Network provider for Neutron with ironic-neutron-plugin"""

    def _add_network(self, task, network_uuid):
        """Create neutron ports for each port on task.node to boot the ramdisk.

        :param task: a TaskManager instance.
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        client = _get_client()
        network_provider = CONF.network_provider
        if task.node.network_provider:
            network_provider = task.node.network_provider

        LOG.info('Using network provider %(net_provider)s for node %(node)s'
                 % {'net_provider': network_provider, 'node': task.node.uuid})
        if network_provider == "neutron_plugin":
            portmap = _get_node_portmap(task)
            body = {
                'port': {
                    'network_id': network_uuid,
                    'admin_state_up': True,
                    'binding:vnic_type': 'baremetal',
                    'device_owner': 'baremetal:none',
                    'binding:host_id': task.node.uuid,
                    'binding:profile': {
                        'local_link_information': portmap,
                    }
                }
            }
        else:
            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'network_id': network_uuid,
                    'admin_state_up': True,
                }
            }

        # Since instance_uuid will not be available during cleaning
        # operations, we need to check that and populate them only when
        # available
        if task.node.instance_uuid:
            body['port']['device_id'] = task.node.instance_uuid

        ports = {}
        for ironic_port in task.ports:
            body['port']['mac_address'] = ironic_port.address
            try:
                port = client.create_port(body)
            except neutron_exceptions.ConnectionFailed as e:
                self._rollback_ports(task, network_uuid)
                msg = (_('Could not create port on given network %(net)s '
                         'from %(node)s. %(exc)s') %
                       {'net': network_uuid, 'node': task.node.uuid, 'exc': e})
                LOG.exception(msg)
                raise exception.NodeCleaningFailure(msg)

            if not port.get('port') or not port['port'].get('id'):
                self._rollback_ports(task, network_uuid)
                msg = (_('Failed to create port on given network %(net)s '
                         'from %(node)s.') %
                       {'net': network_uuid, 'node': task.node.uuid})
                LOG.error(msg)
                raise exception.NodeCleaningFailure(msg)
            # Match return value of get_node_vif_ids()
            ports[ironic_port.uuid] = port['port']['id']
        return ports

    def _remove_network(self, task, network_uuid):
        """Deletes the neutron port created for booting the ramdisk.

        :param task: a TaskManager instance.
        """
        client = _get_client()
        macs = [p.address for p in task.ports]
        params = {
            'network_id': network_uuid
        }
        try:
            ports = client.list_ports(**params)
        except neutron_exceptions.ConnectionFailed as e:
            msg = (_('Could not get given network vif for %(node)s '
                     'from Neutron, possible network issue. %(exc)s') %
                   {'node': task.node.uuid,
                    'exc': e})
            LOG.exception(msg)
            raise exception.NodeCleaningFailure(msg)

        # Iterate the list of Neutron port dicts, remove the ones we added
        for neutron_port in ports.get('ports', []):
            # Only delete ports using the node's mac addresses
            if neutron_port.get('mac_address') in macs:
                try:
                    client.delete_port(neutron_port.get('id'))
                except neutron_exceptions.ConnectionFailed as e:
                    msg = (_('Could not remove ports on given network '
                             '%(net)s from %(node)s, possible network issue. '
                             '%(exc)s') %
                           {'net': network_uuid,
                            'node': task.node.uuid,
                            'exc': e})
                    LOG.exception(msg)
                    raise exception.NodeCleaningFailure(msg)

    def add_provisioning_network(self, task):
        """Add the provisioning network to a node.

        :param task: A TaskManager instance.
        """
        if not CONF.provisioning_network_uuid:
            raise exception.InvalidParameterValue(
                _('Valid provisioning network UUID not provided'))

        LOG.info('Adding provisioning network to node %s', task.node.uuid)
        prov_ports = self._add_network(task, CONF.provisioning_network_uuid)

        for portgroup in task.portgroups:
            extra_dict = portgroup.extra
            # Backup Existing vif.
            vif = extra_dict.pop('vif_port_id', None)
            if vif:
                extra_dict['tenant_vif_port_id'] = vif

            # Setting provisioning port as the vif for the ironic port.
            try:
                extra_dict['vif_port_id'] = prov_ports[portgroup.uuid]
            except KeyError:
                # This is an internal error in Ironic.  All DHCP providers
                # implementing create_cleaning_ports are supposed to
                # return a VIF port ID for all Ironic ports.  But
                # that doesn't seem to be true here.
                error = (_("When creating cleaning ports, DHCP provider "
                           "didn't return VIF port ID for %s")
                         % portgroup.uuid)
                raise exception.NodeCleaningFailure(
                    node=task.node.uuid, reason=error)
            else:
                portgroup.extra = extra_dict
                portgroup.save()

        for port in task.ports:
            extra_dict = port.extra
            # Backup Existing vif.
            vif = extra_dict.pop('vif_port_id', None)
            if vif:
                extra_dict['tenant_vif_port_id'] = vif

            # Setting provisioning port as the vif for the ironic port.
            try:
                extra_dict['vif_port_id'] = prov_ports[port.uuid]
            except KeyError:
                # This is an internal error in Ironic.  All DHCP providers
                # implementing create_cleaning_ports are supposed to
                # return a VIF port ID for all Ironic ports.  But
                # that doesn't seem to be true here.
                error = (_("When creating cleaning ports, DHCP provider "
                           "didn't return VIF port ID for %s") % port.uuid)
                raise exception.NodeCleaningFailure(
                    node=task.node.uuid, reason=error)
            else:
                port.extra = extra_dict
                port.save()

    def remove_provisioning_network(self, task):
        """Remove the provisioning network from a node.

        :param task: A TaskManager instance.
        """
        self._remove_network(task, CONF.provisioning_network_uuid)

        # Restoring the tenant vif to the ironic port.
        for port in task.ports:
            extra_dict = port.extra
            vif = extra_dict.pop('tenant_vif_port_id', None)
            if vif:
                extra_dict['vif_port_id'] = vif
                port.extra = extra_dict
                port.save()

        for portgroup in task.portgroups:
            extra_dict = portgroup.extra
            vif = extra_dict.pop('tenant_vif_port_id', None)
            if vif:
                extra_dict['vif_port_id'] = vif
                portgroup.extra = extra_dict
                portgroup.save()

    def add_cleaning_network(self, task):
        """Create neutron ports for each port on task.node to boot the ramdisk.

        :param task: a TaskManager instance.
        :raises: InvalidParameterValue if the cleaning network is None
        :returns: a dictionary in the form {port.uuid: neutron_port['id']}
        """
        if not CONF.neutron.cleaning_network_uuid:
            raise exception.InvalidParameterValue(_('Valid cleaning network '
                                                    'UUID not provided'))

        LOG.info('Adding cleaning network to node %s', task.node.uuid)
        return self._add_network(task, CONF.neutron.cleaning_network_uuid)

    def remove_cleaning_network(self, task):
        """Deletes the neutron port created for booting the ramdisk.

        :param task: a TaskManager instance.
        """
        self._remove_network(task, CONF.neutron.cleaning_network_uuid)

    def configure_tenant_networks(self, task):
        """Configure tenant networks for a node.

        :param task: A TaskManager instance.
        """
        node = task.node
        client = _get_client()
        LOG.info(_LI('Mapping instance ports to %s'), node.uuid)

        portmap = _get_node_portmap(task)
        if not portmap:
            raise exception.NoValidPortmaps(
                node=node.uuid, vif=CONF.provisioning_network_uuid)

        # TODO(russell_h): this is based on the broken assumption that the
        # number of Neutron ports will match the number of physical ports.
        # Instead, we should probably list ports for this this instance in
        # Neutron and update all of those with the appropriate portmap.
        ports = objects.Port.list_by_node_id(task.context, node.id)
        if not ports:
            raise exception.NetworkError(_LE(
                "No public network ports to activate attached to "
                "node %s") % node.uuid)

        for port in ports:
            vif_port_id = port.extra.get('vif_port_id')

            if not vif_port_id:
                LOG.error('Node %(node)s port has no vif id in extra:'
                          ' %(extra)s',
                          {'extra': port.extra, 'node': node.uuid})
                continue

            LOG.debug('Mapping tenant port %(vif_port_id)s to node '
                      '%(node_id)s',
                      {'vif_port_id': vif_port_id, 'node_id': node.id})
            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'device_id': task.node.instance_uuid,
                    'binding:vnic_type': 'baremetal',
                    'binding:host_id': node.uuid,
                    'binding:profile': {
                        'local_link_information': portmap,
                    },
                }
            }

            try:
                client.update_port(vif_port_id, body)
            except neutron_exceptions.ConnectionFailed:
                raise exception.NetworkError(_(
                    'Could not add public network %(vif)s '
                    'to %(node)s, possible network issue.') %
                    {'vif': vif_port_id,
                     'node': node.uuid})

    def unconfigure_tenant_networks(self, task):
        """Unconfigure tenant networks for a node.

        :param task: A TaskManager instance.
        """
        node = task.node
        LOG.info(_LI('Unmapping instance ports from %s'), node.uuid)

        ports = _list_ports(task)
        portmap = _get_node_portmap(task)
        if not ports:
            LOG.info(_LI('No tenant ports to deconfigure, skipping '
                         'deconfiguration for node %s'), node.uuid)
            return

        for port in ports:
            if not port['id']:
                # TODO(morgabra) client.list_ports() sometimes returns
                # port objects with null ids. It's unclear why this happens.
                LOG.error(_LE("Unmapping port failed, missing 'id'. "
                              "Node: %(node)s Port: %(port)s"), {'node': node,
                                                                 'port': port})
                continue

            if port['network_id'] == CONF.provisioning_network_uuid:
                # Don't delete the provisioning network here
                LOG.debug("Ignoring decom port %(port)s for node %(node)s.",
                          {'port': port['id'], 'node': node.uuid})
                continue

            LOG.debug('Unmapping instance port %(vif_port_id)s from node '
                      '%(node_id)s',
                      {'vif_port_id': port['id'], 'node_id': node.uuid})

            body = {
                'port': {
                    'device_owner': 'baremetal:none',
                    'device_id': task.node.instance_uuid,
                    'binding:host_id': node.uuid,
                    'binding:profile': {
                        'local_link_information': portmap,
                    }
                }
            }
            try:
                client = _get_client()
                client.update_port(port['id'], body)
            except neutron_exceptions.ConnectionFailed:
                raise exception.NetworkError(_LE(
                    'Could not remove public network %(vif)s from %(node)s, '
                    'possible network issue.') %
                    {'vif': port['id'],
                     'node': node.uuid})

    def _rollback_ports(self, task, network_uuid):
        """Attempts to delete any ports created by cleaning

        Purposefully will not raise any exceptions so error handling can
        continue.

        :param task: a TaskManager instance.
        """
        try:
            self._remove_network(task, network_uuid)
        except Exception:
            # Log the error, but let the caller invoke the
            # manager.cleaning_error_handler().
            LOG.exception(_LE('Failed to rollback port '
                              'changes for node %s') % task.node.uuid)
