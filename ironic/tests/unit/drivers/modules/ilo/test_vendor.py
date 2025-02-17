# Copyright 2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
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

"""Test class for common methods used by iLO modules."""

import mock
from oslo_config import cfg
import six

from ironic.common import exception
from ironic.common import states
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import agent
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules.ilo import common as ilo_common
from ironic.drivers.modules.ilo import vendor as ilo_vendor
from ironic.drivers.modules import iscsi_deploy
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils


if six.PY3:
    import io
    file = io.BytesIO

INFO_DICT = db_utils.get_test_ilo_info()
CONF = cfg.CONF


class VendorPassthruTestCase(db_base.DbTestCase):

    def setUp(self):
        super(VendorPassthruTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="iscsi_ilo")
        self.node = obj_utils.create_test_node(self.context,
                                               driver='iscsi_ilo',
                                               driver_info=INFO_DICT)

    @mock.patch.object(manager_utils, 'node_power_action', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'setup_vmedia', spec_set=True,
                       autospec=True)
    def test_boot_into_iso(self, setup_vmedia_mock, power_action_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.vendor.boot_into_iso(task, boot_iso_href='foo')
            setup_vmedia_mock.assert_called_once_with(task, 'foo',
                                                      ramdisk_options=None)
            power_action_mock.assert_called_once_with(task, states.REBOOT)

    @mock.patch.object(ilo_vendor.VendorPassthru, '_validate_boot_into_iso',
                       spec_set=True, autospec=True)
    def test_validate_boot_into_iso(self, validate_boot_into_iso_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            vendor = ilo_vendor.VendorPassthru()
            vendor.validate(task, method='boot_into_iso', foo='bar')
            validate_boot_into_iso_mock.assert_called_once_with(
                vendor, task, {'foo': 'bar'})

    def test__validate_boot_into_iso_invalid_state(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = states.AVAILABLE
            self.assertRaises(
                exception.InvalidStateRequested,
                task.driver.vendor._validate_boot_into_iso,
                task, {})

    def test__validate_boot_into_iso_missing_boot_iso_href(self):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = states.MANAGEABLE
            self.assertRaises(
                exception.MissingParameterValue,
                task.driver.vendor._validate_boot_into_iso,
                task, {})

    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       spec_set=True, autospec=True)
    def test__validate_boot_into_iso_manage(self, validate_image_prop_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            info = {'boot_iso_href': 'foo'}
            task.node.provision_state = states.MANAGEABLE
            task.driver.vendor._validate_boot_into_iso(
                task, info)
            validate_image_prop_mock.assert_called_once_with(
                task.context, {'image_source': 'foo'}, [])

    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       spec_set=True, autospec=True)
    def test__validate_boot_into_iso_maintenance(
            self, validate_image_prop_mock):
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            info = {'boot_iso_href': 'foo'}
            task.node.maintenance = True
            task.driver.vendor._validate_boot_into_iso(
                task, info)
            validate_image_prop_mock.assert_called_once_with(
                task.context, {'image_source': 'foo'}, [])

    @mock.patch.object(iscsi_deploy.VendorPassthru, 'pass_deploy_info',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_common, 'update_secure_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'update_boot_mode', spec_set=True,
                       autospec=True)
    def test_pass_deploy_info(self, func_update_boot_mode,
                              func_update_secure_boot_mode,
                              vendorpassthru_mock):
        kwargs = {'address': '123456'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = states.DEPLOYWAIT
            task.node.target_provision_state = states.ACTIVE
            task.driver.vendor.pass_deploy_info(task, **kwargs)
            func_update_boot_mode.assert_called_once_with(task)
            func_update_secure_boot_mode.assert_called_once_with(task, True)
            vendorpassthru_mock.assert_called_once_with(
                mock.ANY, task, **kwargs)

    @mock.patch.object(iscsi_deploy.VendorPassthru, 'continue_deploy',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_common, 'update_secure_boot_mode', autospec=True)
    @mock.patch.object(ilo_common, 'update_boot_mode', autospec=True)
    def test_continue_deploy(self,
                             func_update_boot_mode,
                             func_update_secure_boot_mode,
                             pxe_vendorpassthru_mock):
        kwargs = {'address': '123456'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.provision_state = states.DEPLOYWAIT
            task.node.target_provision_state = states.ACTIVE
            task.driver.vendor.continue_deploy(task, **kwargs)
            func_update_boot_mode.assert_called_once_with(task)
            func_update_secure_boot_mode.assert_called_once_with(task, True)
            pxe_vendorpassthru_mock.assert_called_once_with(
                mock.ANY, task, **kwargs)


class IloVirtualMediaAgentVendorInterfaceTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IloVirtualMediaAgentVendorInterfaceTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="agent_ilo")
        self.node = obj_utils.create_test_node(
            self.context, driver='agent_ilo', driver_info=INFO_DICT)

    @mock.patch.object(agent.AgentVendorInterface, 'reboot_to_instance',
                       spec_set=True, autospec=True)
    @mock.patch.object(agent.AgentVendorInterface, 'check_deploy_success',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_common, 'update_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'update_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test_reboot_to_instance(self, func_update_secure_boot_mode,
                                func_update_boot_mode,
                                check_deploy_success_mock,
                                agent_reboot_to_instance_mock):
        kwargs = {'address': '123456'}
        check_deploy_success_mock.return_value = None
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.vendor.reboot_to_instance(task, **kwargs)
            check_deploy_success_mock.assert_called_once_with(
                mock.ANY, task.node)
            func_update_boot_mode.assert_called_once_with(task)
            func_update_secure_boot_mode.assert_called_once_with(task, True)
            agent_reboot_to_instance_mock.assert_called_once_with(
                mock.ANY, task, **kwargs)

    @mock.patch.object(agent.AgentVendorInterface, 'reboot_to_instance',
                       spec_set=True, autospec=True)
    @mock.patch.object(agent.AgentVendorInterface, 'check_deploy_success',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_common, 'update_boot_mode', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'update_secure_boot_mode', spec_set=True,
                       autospec=True)
    def test_reboot_to_instance_deploy_fail(self, func_update_secure_boot_mode,
                                            func_update_boot_mode,
                                            check_deploy_success_mock,
                                            agent_reboot_to_instance_mock):
        kwargs = {'address': '123456'}
        check_deploy_success_mock.return_value = "Error"
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.vendor.reboot_to_instance(task, **kwargs)
            check_deploy_success_mock.assert_called_once_with(
                mock.ANY, task.node)
            self.assertFalse(func_update_boot_mode.called)
            self.assertFalse(func_update_secure_boot_mode.called)
            agent_reboot_to_instance_mock.assert_called_once_with(
                mock.ANY, task, **kwargs)

    @mock.patch.object(ilo_common, 'cleanup_vmedia_boot',
                       spec_set=True, autospec=True)
    @mock.patch.object(agent.AgentVendorInterface, 'continue_deploy',
                       spec_set=True, autospec=True)
    def test_continue_deploy(self, agent_continue_deploy_mock,
                             cleanup_mock):
        CONF.ilo.use_web_server_for_images = True
        kwargs = {'address': '123456'}
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.vendor.continue_deploy(task, **kwargs)
            cleanup_mock.assert_called_once_with(task)
            agent_continue_deploy_mock.assert_called_once_with(
                mock.ANY, task, **kwargs)
