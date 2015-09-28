# Copyright 2014 Rackspace Inc.
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
import inspect
import mock
from neutronclient.v2_0 import client
from oslo_utils import uuidutils
import stevedore

from ironic.common import exception
from ironic.common import network
from ironic.conductor import task_manager
from ironic.networks import base as base_class
from ironic.networks import neutron_plugin as neutron
from ironic.networks import none
from ironic.tests import base
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as object_utils


class TestNetwork(db_base.DbTestCase):

    def setUp(self):
        super(TestNetwork, self).setUp()
        mgr_utils.mock_the_extension_manager(driver='fake')
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

    def test_default_network_provider(self):
        # network provider should default to neutron
        with task_manager.acquire(self.context, self.node.uuid) as task:
            net_provider = network.get_network_provider(task)
            self.assertIsInstance(net_provider,
                                  neutron.NeutronV2NetworkProvider)

    def test_set_bad_network_provider(self):
        self.config(network_provider='bad_network_plugin')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.NetworkProviderNotFound,
                              network.get_network_provider, task)

    @mock.patch.object(stevedore.driver, 'DriverManager', autospec=True)
    def test_network_provider_some_error(self, mock_drv_mgr):
        mock_drv_mgr.side_effect = exception.NetworkProviderNotFound(
            'No module mymod found.')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            self.assertRaises(exception.NetworkProviderNotFound,
                              network.get_network_provider, task)

    def test_set_none_network_provider(self):
        self.config(network_provider='none')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            net_provider = network.get_network_provider(task)
            self.assertIsInstance(net_provider, none.NoopNetworkProvider)

    def test_set_neutron_network_provider(self):
        self.config(network_provider='neutron_plugin')

        with task_manager.acquire(self.context, self.node.uuid) as task:
            net_provider = network.get_network_provider(task)
            self.assertIsInstance(net_provider,
                                  neutron.NeutronV2NetworkProvider)

    def test_get_neutron_client_invalid_auth_strategy(self):
        self.config(auth_strategy='wrong_config', group='neutron')
        token = 'test-token-123'
        self.assertRaises(exception.ConfigInvalid,
                          network.get_neutron_client,
                          token=token)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_with_token(self, mock_client_init):
        token = 'test-token-123'
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'token': token,
                    'endpoint_url': 'test-url',
                    'auth_strategy': None}

        mock_client_init.return_value = None
        network.get_neutron_client(token=token)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_without_token(self, mock_client_init):
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'endpoint_url': 'test-url',
                    'username': 'test-admin-user',
                    'tenant_name': 'test-admin-tenant',
                    'password': 'test-admin-password',
                    'auth_url': 'test-auth-uri'}

        mock_client_init.return_value = None
        network.get_neutron_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_with_region(self, mock_client_init):
        expected = {'timeout': 30,
                    'retries': 2,
                    'insecure': False,
                    'ca_cert': 'test-file',
                    'endpoint_url': 'test-url',
                    'username': 'test-admin-user',
                    'tenant_name': 'test-admin-tenant',
                    'password': 'test-admin-password',
                    'auth_url': 'test-auth-uri',
                    'region_name': 'test-region'}

        self.config(region_name='test-region',
                    group='keystone')
        mock_client_init.return_value = None
        network.get_neutron_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    @mock.patch.object(client.Client, "__init__")
    def test_get_neutron_client_noauth(self, mock_client_init):
        self.config(auth_strategy='noauth', group='neutron')
        expected = {'ca_cert': 'test-file',
                    'insecure': False,
                    'endpoint_url': 'test-url',
                    'timeout': 30,
                    'retries': 2,
                    'auth_strategy': 'noauth'}

        mock_client_init.return_value = None
        network.get_neutron_client(token=None)
        mock_client_init.assert_called_once_with(**expected)

    def test_get_node_vif_ids_no_ports(self):
        expected = {}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_one_port(self):
        port1 = db_utils.create_test_port(node_id=self.node.id,
                                          address='aa:bb:cc:dd:ee:ff',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-A'},
                                          driver='fake')
        expected = {port1.uuid: 'test-vif-A'}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)

    def test_get_node_vif_ids_two_ports(self):
        port1 = db_utils.create_test_port(node_id=self.node.id,
                                          address='aa:bb:cc:dd:ee:ff',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-A'},
                                          driver='fake')
        port2 = db_utils.create_test_port(node_id=self.node.id,
                                          address='dd:ee:ff:aa:bb:cc',
                                          uuid=uuidutils.generate_uuid(),
                                          extra={'vif_port_id': 'test-vif-B'},
                                          driver='fake')
        expected = {port1.uuid: 'test-vif-A', port2.uuid: 'test-vif-B'}
        with task_manager.acquire(self.context, self.node.uuid) as task:
            result = network.get_node_vif_ids(task)
        self.assertEqual(expected, result)


class CompareBasetoModules(base.TestCase):

    def test_drivers_match_network_provider_base(self):
        def _get_public_apis(inst):
            methods = {}
            for (name, value) in inspect.getmembers(inst, inspect.ismethod):
                if name.startswith("_"):
                    continue
                methods[name] = value
            return methods

        def _compare_classes(baseclass, driverclass):

            basemethods = _get_public_apis(baseclass)
            implmethods = _get_public_apis(driverclass)

            for name in basemethods:
                baseargs = inspect.getargspec(basemethods[name])
                implargs = inspect.getargspec(implmethods[name])
                self.assertEqual(
                    baseargs,
                    implargs,
                    "%s args of %s don't match base %s" % (
                        name,
                        driverclass,
                        baseclass)
                )

        _compare_classes(base_class.NetworkProvider,
                         none.NoopNetworkProvider)
        _compare_classes(base_class.NetworkProvider,
                         neutron.NeutronV2NetworkProvider)
