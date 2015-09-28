#
# Copyright 2014 OpenStack Foundation
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

import mock
from neutronclient.common import exceptions as neutron_client_exc
from neutronclient.v2_0 import client

from ironic.common import exception
from ironic.common import network
from ironic.conductor import task_manager
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.objects import utils as object_utils


class TestNeutronPlugin(db_base.DbTestCase):

    def setUp(self):
        super(TestNeutronPlugin, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake')
        self.config(
            cleaning_network_uuid='00000000-0000-0000-0000-000000000000',
            group='neutron')
        self.config(
            provisioning_network_uuid='11111111-1111-1111-1111-111111111111')
        self.config(enabled_drivers=['fake'])
        self.config(network_provider='neutron_plugin')
        self.config(url='test-url',
                    url_timeout=30,
                    retries=2,
                    group='neutron')
        self.config(insecure=False,
                    certfile='test-file',
                    admin_user='test-admin-user',
                    admin_tenant_name='test-admin-tenant',
                    admin_password='test-admin-password',
                    auth_uri='test-auth-uri',
                    group='keystone_authtoken')
        self.node = object_utils.create_test_node(self.context)
        self.node.instance_uuid = '32f871f1-aece-fed4-4759-d54465e0f000'
        self.ports = [
            object_utils.create_test_port(
                self.context, node_id=self.node.id, id=2,
                uuid='1be26c0b-03f2-4d2e-ae87-c02d7f33c782',
                address='52:54:00:cf:2d:32')]
        # Very simple neutron port representation
        self.neutron_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f00',
                             'mac_address': '52:54:00:cf:2d:32'}

    @mock.patch.object(client.Client, 'create_port')
    def test__add_network_node_noop_network_provider(self, create_mock):
        # Ensure we can create ports
        self.node.network_provider = "none"
        create_mock.return_value = {'port': self.neutron_port}
        expected = {self.ports[0].uuid: self.neutron_port['id']}

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            task.node = self.node
            ports = api._add_network(task,
                                     '00000000-0000-0000-0000-000000000000')
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with({'port': {
                'admin_state_up': True,
                'device_id': self.node.instance_uuid,
                'device_owner': 'baremetal:none',
                'network_id': '00000000-0000-0000-0000-000000000000',
                'mac_address': self.ports[0].address}})

    def _test__add_network(self, create_mock, node):
        # Ensure we can create ports
        create_mock.return_value = {'port': self.neutron_port}
        expected = {self.ports[0].uuid: self.neutron_port['id']}

        with task_manager.acquire(self.context, node.uuid) as task:
            task.node = node
            api = network.get_network_provider(task)
            ports = api._add_network(task,
                                     '00000000-0000-0000-0000-000000000000')
            self.assertEqual(expected, ports)
            create_mock.assert_called_once_with({'port': {
                'admin_state_up': True,
                'binding:host_id': node.uuid,
                'device_id': self.node.instance_uuid,
                'device_owner': 'baremetal:none',
                'binding:profile': {
                    'local_link_information': [
                        self.ports[0]['local_link_connection']
                    ]
                },
                'network_id': '00000000-0000-0000-0000-000000000000',
                'mac_address': self.ports[0].address,
                'binding:vnic_type': 'baremetal'}})

    @mock.patch.object(client.Client, 'create_port')
    def test__add_network_node_none_network_provider(self, create_mock):
        self.node.network_provider = None
        self._test__add_network(create_mock, self.node)

    @mock.patch.object(client.Client, 'create_port')
    def test__add_network_node_neutron_network_provider(self, create_mock):
        self.node.network_provider = "neutron_plugin"
        self._test__add_network(create_mock, self.node)

    @mock.patch('ironic.networks.neutron_plugin.NeutronV2NetworkProvider.'
                '_rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test__add_network_fail(self, create_mock, rollback_mock):
        # Check that if creating a port fails, the ports are cleaned up
        create_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            api = network.get_network_provider(task)
            self.assertRaises(exception.NodeCleaningFailure, api._add_network,
                              task, '00000000-0000-0000-0000-000000000000')
            create_mock.assert_called_once_with({'port': {
                'admin_state_up': True,
                'binding:host_id': self.node.uuid,
                'device_id': self.node.instance_uuid,
                'device_owner': 'baremetal:none',
                'binding:profile': {
                    'local_link_information': [
                        self.ports[0]['local_link_connection']
                    ]
                },
                'network_id': '00000000-0000-0000-0000-000000000000',
                'mac_address': self.ports[0].address,
                'binding:vnic_type': 'baremetal'}})
            rollback_mock.assert_called_once_with(
                task,
                '00000000-0000-0000-0000-000000000000')

    @mock.patch('ironic.networks.neutron_plugin.NeutronV2NetworkProvider.'
                '_rollback_ports')
    @mock.patch.object(client.Client, 'create_port')
    def test_create_cleaning_ports_fail_delayed(self, create_mock,
                                                rollback_mock):
        """Check ports are cleaned up on failure to create them

        This test checks that the port clean-up occurs
        when the port create call was successful,
        but the port in fact was not created.

        """
        # NOTE(pas-ha) this is trying to emulate the complex port object
        # with both methods and dictionary access with methods on elements
        mockport = mock.MagicMock()
        create_mock.return_value = mockport
        # fail only on second 'or' branch to fool lazy eval
        # and actually execute both expressions to assert on both mocks
        mockport.get.return_value = True
        mockitem = mock.Mock()
        mockport.__getitem__.return_value = mockitem
        mockitem.get.return_value = None

        with task_manager.acquire(self.context, self.node.uuid) as task:
            task.node = self.node
            api = network.get_network_provider(task)
            self.assertRaises(exception.NodeCleaningFailure,
                              api._add_network, task,
                              '00000000-0000-0000-0000-000000000000')
            create_mock.assert_called_once_with({'port': {
                'admin_state_up': True,
                'binding:host_id': self.node.uuid,
                'device_id': self.node.instance_uuid,
                'device_owner': 'baremetal:none',
                'binding:profile': {
                    'local_link_information': [
                        self.ports[0]['local_link_connection']
                    ]
                },
                'network_id': '00000000-0000-0000-0000-000000000000',
                'mac_address': self.ports[0].address,
                'binding:vnic_type': 'baremetal'}})
            rollback_mock.assert_called_once_with(
                task,
                '00000000-0000-0000-0000-000000000000')
            mockport.get.assert_called_once_with('port')
            mockitem.get.assert_called_once_with('id')
            mockport.__getitem__.assert_called_once_with('port')

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test__remove_network(self, list_mock, delete_mock):
        # Ensure that we can delete cleaning ports, and that ports with
        # different macs don't get deleted
        other_port = {'id': '132f871f-eaec-4fed-9475-0d54465e0f01',
                      'mac_address': 'aa:bb:cc:dd:ee:ff'}
        list_mock.return_value = {'ports': [self.neutron_port, other_port]}

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            api._remove_network(task,
                                '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    @mock.patch.object(client.Client, 'list_ports')
    def test__remove_network_list_fail(self, list_mock):
        # Check that if listing ports fails, the node goes to cleanfail
        list_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            self.assertRaises(exception.NodeCleaningFailure,
                              api._remove_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')

    @mock.patch.object(client.Client, 'delete_port')
    @mock.patch.object(client.Client, 'list_ports')
    def test__remove_network_delete_fail(self, list_mock, delete_mock):
        # Check that if deleting ports fails, the node goes to cleanfail
        list_mock.return_value = {'ports': [self.neutron_port]}
        delete_mock.side_effect = neutron_client_exc.ConnectionFailed

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            self.assertRaises(exception.NodeCleaningFailure,
                              api._remove_network, task,
                              '00000000-0000-0000-0000-000000000000')
            list_mock.assert_called_once_with(
                network_id='00000000-0000-0000-0000-000000000000')
            delete_mock.assert_called_once_with(self.neutron_port['id'])

    def test_add_cleaning_network_bad_config(self):
        # Check an error is raised if the cleaning network is not set
        self.config(cleaning_network_uuid=None, group='neutron')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            self.assertRaises(exception.InvalidParameterValue,
                              api.add_cleaning_network, task)

    def test_add_provisioning_network_uuid_bad_config(self):
        # Check an error is raised if the cleaning network is not set
        self.config(provisioning_network_uuid=None)

        with task_manager.acquire(self.context, self.node.uuid) as task:
            api = network.get_network_provider(task)
            self.assertRaises(exception.InvalidParameterValue,
                              api.add_provisioning_network, task)
