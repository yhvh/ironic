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

import tempfile

import mock
from oslo_config import cfg
import six

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common.glance_service import service_utils
from ironic.common import image_service
from ironic.common import images
from ironic.common import swift
from ironic.common import utils
from ironic.conductor import task_manager
from ironic.conductor import utils as manager_utils
from ironic.drivers.modules import deploy_utils
from ironic.drivers.modules.ilo import boot as ilo_boot
from ironic.drivers.modules.ilo import common as ilo_common
from ironic.drivers import utils as driver_utils
from ironic.tests.unit.conductor import mgr_utils
from ironic.tests.unit.db import base as db_base
from ironic.tests.unit.db import utils as db_utils
from ironic.tests.unit.objects import utils as obj_utils


if six.PY3:
    import io
    file = io.BytesIO

INFO_DICT = db_utils.get_test_ilo_info()
CONF = cfg.CONF


class IloBootPrivateMethodsTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IloBootPrivateMethodsTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="iscsi_ilo")
        self.node = obj_utils.create_test_node(
            self.context, driver='iscsi_ilo', driver_info=INFO_DICT)

    def test__get_boot_iso_object_name(self):
        boot_iso_actual = ilo_boot._get_boot_iso_object_name(self.node)
        boot_iso_expected = "boot-%s" % self.node.uuid
        self.assertEqual(boot_iso_expected, boot_iso_actual)

    @mock.patch.object(image_service.HttpImageService, 'validate_href',
                       spec_set=True, autospec=True)
    def test__get_boot_iso_http_url(self, service_mock):
        url = 'http://abc.org/image/qcow2'
        i_info = self.node.instance_info
        i_info['ilo_boot_iso'] = url
        self.node.instance_info = i_info
        self.node.save()

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_iso_actual = ilo_boot._get_boot_iso(task, 'root-uuid')
            service_mock.assert_called_once_with(mock.ANY, url)
            self.assertEqual(url, boot_iso_actual)

    @mock.patch.object(image_service.HttpImageService, 'validate_href',
                       spec_set=True, autospec=True)
    def test__get_boot_iso_unsupported_url(self, validate_href_mock):
        validate_href_mock.side_effect = iter(
            [exception.ImageRefValidationFailed(
                image_href='file://img.qcow2', reason='fail')])
        url = 'file://img.qcow2'
        i_info = self.node.instance_info
        i_info['ilo_boot_iso'] = url
        self.node.instance_info = i_info
        self.node.save()

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            self.assertRaises(exception.ImageRefValidationFailed,
                              ilo_boot._get_boot_iso, task, 'root-uuid')

    @mock.patch.object(images, 'get_image_properties', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_parse_deploy_info', spec_set=True,
                       autospec=True)
    def test__get_boot_iso_glance_image(self, deploy_info_mock,
                                        image_props_mock):
        deploy_info_mock.return_value = {'image_source': 'image-uuid',
                                         'ilo_deploy_iso': 'deploy_iso_uuid'}
        image_props_mock.return_value = {'boot_iso': u'glance://uui\u0111',
                                         'kernel_id': None,
                                         'ramdisk_id': None}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            driver_internal_info = task.node.driver_internal_info
            driver_internal_info['boot_iso_created_in_web_server'] = False
            task.node.driver_internal_info = driver_internal_info
            task.node.save()
            boot_iso_actual = ilo_boot._get_boot_iso(task, 'root-uuid')
            deploy_info_mock.assert_called_once_with(task.node)
            image_props_mock.assert_called_once_with(
                task.context, 'image-uuid',
                ['boot_iso', 'kernel_id', 'ramdisk_id'])
            boot_iso_expected = u'glance://uui\u0111'
            self.assertEqual(boot_iso_expected, boot_iso_actual)

    @mock.patch.object(deploy_utils, 'get_boot_mode_for_deploy',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_boot.LOG, 'error', spec_set=True, autospec=True)
    @mock.patch.object(images, 'get_image_properties', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_parse_deploy_info', spec_set=True,
                       autospec=True)
    def test__get_boot_iso_uefi_no_glance_image(self,
                                                deploy_info_mock,
                                                image_props_mock,
                                                log_mock,
                                                boot_mode_mock):
        deploy_info_mock.return_value = {'image_source': 'image-uuid',
                                         'ilo_deploy_iso': 'deploy_iso_uuid'}
        image_props_mock.return_value = {'boot_iso': None,
                                         'kernel_id': None,
                                         'ramdisk_id': None}
        properties = {'capabilities': 'boot_mode:uefi'}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.node.properties = properties
            boot_iso_result = ilo_boot._get_boot_iso(task, 'root-uuid')
            deploy_info_mock.assert_called_once_with(task.node)
            image_props_mock.assert_called_once_with(
                task.context, 'image-uuid',
                ['boot_iso', 'kernel_id', 'ramdisk_id'])
            self.assertTrue(log_mock.called)
            self.assertFalse(boot_mode_mock.called)
            self.assertIsNone(boot_iso_result)

    @mock.patch.object(tempfile, 'NamedTemporaryFile', spec_set=True,
                       autospec=True)
    @mock.patch.object(images, 'create_boot_iso', spec_set=True, autospec=True)
    @mock.patch.object(swift, 'SwiftAPI', spec_set=True, autospec=True)
    @mock.patch.object(ilo_boot, '_get_boot_iso_object_name', spec_set=True,
                       autospec=True)
    @mock.patch.object(driver_utils, 'get_node_capability', spec_set=True,
                       autospec=True)
    @mock.patch.object(images, 'get_image_properties', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_parse_deploy_info', spec_set=True,
                       autospec=True)
    def test__get_boot_iso_create(self, deploy_info_mock, image_props_mock,
                                  capability_mock, boot_object_name_mock,
                                  swift_api_mock,
                                  create_boot_iso_mock, tempfile_mock):
        CONF.ilo.swift_ilo_container = 'ilo-cont'
        CONF.pxe.pxe_append_params = 'kernel-params'

        swift_obj_mock = swift_api_mock.return_value
        fileobj_mock = mock.MagicMock(spec=file)
        fileobj_mock.name = 'tmpfile'
        mock_file_handle = mock.MagicMock(spec=file)
        mock_file_handle.__enter__.return_value = fileobj_mock
        tempfile_mock.return_value = mock_file_handle

        deploy_info_mock.return_value = {'image_source': 'image-uuid',
                                         'ilo_deploy_iso': 'deploy_iso_uuid'}
        image_props_mock.return_value = {'boot_iso': None,
                                         'kernel_id': 'kernel_uuid',
                                         'ramdisk_id': 'ramdisk_uuid'}
        boot_object_name_mock.return_value = 'abcdef'
        create_boot_iso_mock.return_value = '/path/to/boot-iso'
        capability_mock.return_value = 'uefi'
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_iso_actual = ilo_boot._get_boot_iso(task, 'root-uuid')
            deploy_info_mock.assert_called_once_with(task.node)
            image_props_mock.assert_called_once_with(
                task.context, 'image-uuid',
                ['boot_iso', 'kernel_id', 'ramdisk_id'])
            boot_object_name_mock.assert_called_once_with(task.node)
            create_boot_iso_mock.assert_called_once_with(task.context,
                                                         'tmpfile',
                                                         'kernel_uuid',
                                                         'ramdisk_uuid',
                                                         'deploy_iso_uuid',
                                                         'root-uuid',
                                                         'kernel-params',
                                                         'uefi')
            swift_obj_mock.create_object.assert_called_once_with('ilo-cont',
                                                                 'abcdef',
                                                                 'tmpfile')
            boot_iso_expected = 'swift:abcdef'
            self.assertEqual(boot_iso_expected, boot_iso_actual)

    @mock.patch.object(ilo_common, 'copy_image_to_web_server', spec_set=True,
                       autospec=True)
    @mock.patch.object(tempfile, 'NamedTemporaryFile', spec_set=True,
                       autospec=True)
    @mock.patch.object(images, 'create_boot_iso', spec_set=True, autospec=True)
    @mock.patch.object(ilo_boot, '_get_boot_iso_object_name', spec_set=True,
                       autospec=True)
    @mock.patch.object(driver_utils, 'get_node_capability', spec_set=True,
                       autospec=True)
    @mock.patch.object(images, 'get_image_properties', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_parse_deploy_info', spec_set=True,
                       autospec=True)
    def test__get_boot_iso_create_use_webserver_true_ramdisk_webserver(
            self, deploy_info_mock, image_props_mock,
            capability_mock, boot_object_name_mock,
            create_boot_iso_mock, tempfile_mock,
            copy_file_mock):
        CONF.ilo.swift_ilo_container = 'ilo-cont'
        CONF.ilo.use_web_server_for_images = True
        CONF.deploy.http_url = "http://10.10.1.30/httpboot"
        CONF.deploy.http_root = "/httpboot"
        CONF.pxe.pxe_append_params = 'kernel-params'

        fileobj_mock = mock.MagicMock(spec=file)
        fileobj_mock.name = 'tmpfile'
        mock_file_handle = mock.MagicMock(spec=file)
        mock_file_handle.__enter__.return_value = fileobj_mock
        tempfile_mock.return_value = mock_file_handle

        ramdisk_href = "http://10.10.1.30/httpboot/ramdisk"
        kernel_href = "http://10.10.1.30/httpboot/kernel"
        deploy_info_mock.return_value = {'image_source': 'image-uuid',
                                         'ilo_deploy_iso': 'deploy_iso_uuid'}
        image_props_mock.return_value = {'boot_iso': None,
                                         'kernel_id': kernel_href,
                                         'ramdisk_id': ramdisk_href}
        boot_object_name_mock.return_value = 'abcdef'
        create_boot_iso_mock.return_value = '/path/to/boot-iso'
        capability_mock.return_value = 'uefi'
        copy_file_mock.return_value = "http://10.10.1.30/httpboot/abcdef"

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            boot_iso_actual = ilo_boot._get_boot_iso(task, 'root-uuid')
            deploy_info_mock.assert_called_once_with(task.node)
            image_props_mock.assert_called_once_with(
                task.context, 'image-uuid',
                ['boot_iso', 'kernel_id', 'ramdisk_id'])
            boot_object_name_mock.assert_called_once_with(task.node)
            create_boot_iso_mock.assert_called_once_with(task.context,
                                                         'tmpfile',
                                                         kernel_href,
                                                         ramdisk_href,
                                                         'deploy_iso_uuid',
                                                         'root-uuid',
                                                         'kernel-params',
                                                         'uefi')
            boot_iso_expected = 'http://10.10.1.30/httpboot/abcdef'
            self.assertEqual(boot_iso_expected, boot_iso_actual)
            copy_file_mock.assert_called_once_with(fileobj_mock.name,
                                                   'abcdef')

    @mock.patch.object(ilo_boot, '_get_boot_iso_object_name', spec_set=True,
                       autospec=True)
    @mock.patch.object(swift, 'SwiftAPI', spec_set=True, autospec=True)
    def test__clean_up_boot_iso_for_instance(self, swift_mock,
                                             boot_object_name_mock):
        swift_obj_mock = swift_mock.return_value
        CONF.ilo.swift_ilo_container = 'ilo-cont'
        boot_object_name_mock.return_value = 'boot-object'
        i_info = self.node.instance_info
        i_info['ilo_boot_iso'] = 'swift:bootiso'
        self.node.instance_info = i_info
        self.node.save()
        ilo_boot._clean_up_boot_iso_for_instance(self.node)
        swift_obj_mock.delete_object.assert_called_once_with('ilo-cont',
                                                             'boot-object')

    @mock.patch.object(ilo_boot.LOG, 'exception', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_get_boot_iso_object_name', spec_set=True,
                       autospec=True)
    @mock.patch.object(swift, 'SwiftAPI', spec_set=True, autospec=True)
    def test__clean_up_boot_iso_for_instance_exc(self, swift_mock,
                                                 boot_object_name_mock,
                                                 log_mock):
        swift_obj_mock = swift_mock.return_value
        exc = exception.SwiftObjectNotFoundError('error')
        swift_obj_mock.delete_object.side_effect = exc
        CONF.ilo.swift_ilo_container = 'ilo-cont'
        boot_object_name_mock.return_value = 'boot-object'
        i_info = self.node.instance_info
        i_info['ilo_boot_iso'] = 'swift:bootiso'
        self.node.instance_info = i_info
        self.node.save()
        ilo_boot._clean_up_boot_iso_for_instance(self.node)
        swift_obj_mock.delete_object.assert_called_once_with('ilo-cont',
                                                             'boot-object')
        self.assertTrue(log_mock.called)

    @mock.patch.object(utils, 'unlink_without_raise', spec_set=True,
                       autospec=True)
    def test__clean_up_boot_iso_for_instance_on_webserver(self, unlink_mock):

        CONF.ilo.use_web_server_for_images = True
        CONF.deploy.http_root = "/webserver"
        i_info = self.node.instance_info
        i_info['ilo_boot_iso'] = 'http://x.y.z.a/webserver/boot-object'
        self.node.instance_info = i_info
        self.node.save()
        boot_iso_path = "/webserver/boot-object"
        ilo_boot._clean_up_boot_iso_for_instance(self.node)
        unlink_mock.assert_called_once_with(boot_iso_path)

    @mock.patch.object(ilo_boot, '_get_boot_iso_object_name', spec_set=True,
                       autospec=True)
    def test__clean_up_boot_iso_for_instance_no_boot_iso(
            self, boot_object_name_mock):
        ilo_boot._clean_up_boot_iso_for_instance(self.node)
        self.assertFalse(boot_object_name_mock.called)

    @mock.patch.object(ilo_boot, 'parse_driver_info', spec_set=True,
                       autospec=True)
    @mock.patch.object(deploy_utils, 'get_image_instance_info',
                       spec_set=True, autospec=True)
    def test__parse_deploy_info(self, instance_info_mock, driver_info_mock):
        instance_info_mock.return_value = {'a': 'b'}
        driver_info_mock.return_value = {'c': 'd'}
        expected_info = {'a': 'b', 'c': 'd'}
        actual_info = ilo_boot._parse_deploy_info(self.node)
        self.assertEqual(expected_info, actual_info)


class IloVirtualMediaBootTestCase(db_base.DbTestCase):

    def setUp(self):
        super(IloVirtualMediaBootTestCase, self).setUp()
        mgr_utils.mock_the_extension_manager(driver="iscsi_ilo")
        self.node = obj_utils.create_test_node(
            self.context, driver='iscsi_ilo', driver_info=INFO_DICT)

    @mock.patch.object(deploy_utils, 'validate_image_properties',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_boot, '_parse_deploy_info', spec_set=True,
                       autospec=True)
    def _test_validate(self,
                       deploy_info_mock,
                       validate_prop_mock,
                       props_expected):
        d_info = {'image_source': 'uuid'}
        deploy_info_mock.return_value = d_info
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.validate(task)
            deploy_info_mock.assert_called_once_with(task.node)
            validate_prop_mock.assert_called_once_with(
                task.context, d_info, props_expected)

    @mock.patch.object(service_utils, 'is_glance_image', spec_set=True,
                       autospec=True)
    def test_validate_glance_partition_image(self, is_glance_image_mock):
        is_glance_image_mock.return_value = True
        self._test_validate(props_expected=['kernel_id', 'ramdisk_id'])

    def test_validate_whole_disk_image(self):
        self.node.driver_internal_info = {'is_whole_disk_image': True}
        self.node.save()
        self._test_validate(props_expected=[])

    @mock.patch.object(service_utils, 'is_glance_image', spec_set=True,
                       autospec=True)
    def test_validate_non_glance_partition_image(self, is_glance_image_mock):
        is_glance_image_mock.return_value = False
        self._test_validate(props_expected=['kernel', 'ramdisk'])

    @mock.patch.object(ilo_common, 'eject_vmedia_devices',
                       spec_set=True, autospec=True)
    @mock.patch.object(ilo_common, 'setup_vmedia', spec_set=True,
                       autospec=True)
    @mock.patch.object(deploy_utils, 'get_single_nic_with_vif_port_id',
                       spec_set=True, autospec=True)
    def _test_prepare_ramdisk(self, get_nic_mock, setup_vmedia_mock,
                              eject_mock, ilo_boot_iso, image_source,
                              ramdisk_params={'a': 'b'}):
        instance_info = self.node.instance_info
        instance_info['ilo_boot_iso'] = ilo_boot_iso
        instance_info['image_source'] = image_source
        self.node.instance_info = instance_info
        self.node.save()

        get_nic_mock.return_value = '12:34:56:78:90:ab'
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:

            task.node.driver_info['ilo_deploy_iso'] = 'deploy-iso'

            task.driver.boot.prepare_ramdisk(task, ramdisk_params)

            eject_mock.assert_called_once_with(task)
            expected_ramdisk_opts = {'a': 'b', 'BOOTIF': '12:34:56:78:90:ab'}
            get_nic_mock.assert_called_once_with(task)
            setup_vmedia_mock.assert_called_once_with(task, 'deploy-iso',
                                                      expected_ramdisk_opts)

    def test_prepare_ramdisk_glance_image(self):
        self._test_prepare_ramdisk(
            ilo_boot_iso='swift:abcdef',
            image_source='6b2f0c0c-79e8-4db6-842e-43c9764204af')
        self.node.refresh()
        self.assertNotIn('ilo_boot_iso', self.node.instance_info)

    def test_prepare_ramdisk_not_a_glance_image(self):
        self._test_prepare_ramdisk(
            ilo_boot_iso='http://mybootiso',
            image_source='http://myimage')
        self.node.refresh()
        self.assertEqual('http://mybootiso',
                         self.node.instance_info['ilo_boot_iso'])

    @mock.patch.object(manager_utils, 'node_set_boot_device', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'setup_vmedia_for_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_get_boot_iso', spec_set=True,
                       autospec=True)
    def test__configure_vmedia_boot_with_boot_iso(
            self, get_boot_iso_mock, setup_vmedia_mock, set_boot_device_mock):
        root_uuid = {'root uuid': 'root_uuid'}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            get_boot_iso_mock.return_value = 'boot.iso'

            task.driver.boot._configure_vmedia_boot(
                task, root_uuid)

            get_boot_iso_mock.assert_called_once_with(
                task, root_uuid)
            setup_vmedia_mock.assert_called_once_with(
                task, 'boot.iso')
            set_boot_device_mock.assert_called_once_with(
                task, boot_devices.CDROM, persistent=True)
            self.assertEqual('boot.iso',
                             task.node.instance_info['ilo_boot_iso'])

    @mock.patch.object(manager_utils, 'node_set_boot_device', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'setup_vmedia_for_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_get_boot_iso', spec_set=True,
                       autospec=True)
    def test__configure_vmedia_boot_without_boot_iso(
            self, get_boot_iso_mock, setup_vmedia_mock, set_boot_device_mock):
        root_uuid = {'root uuid': 'root_uuid'}

        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            get_boot_iso_mock.return_value = None

            task.driver.boot._configure_vmedia_boot(
                task, root_uuid)

            get_boot_iso_mock.assert_called_once_with(
                task, root_uuid)
            self.assertFalse(setup_vmedia_mock.called)
            self.assertFalse(set_boot_device_mock.called)

    @mock.patch.object(ilo_common, 'cleanup_vmedia_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_boot, '_clean_up_boot_iso_for_instance',
                       spec_set=True, autospec=True)
    def test_clean_up_instance(self, cleanup_iso_mock,
                               cleanup_vmedia_mock):
        CONF.ilo.use_web_server_for_images = False
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.clean_up_instance(task)
            cleanup_iso_mock.assert_called_once_with(task.node)
            cleanup_vmedia_mock.assert_called_once_with(task)

    @mock.patch.object(ilo_common, 'cleanup_vmedia_boot', spec_set=True,
                       autospec=True)
    def test_clean_up_ramdisk(self, cleanup_vmedia_mock):
        CONF.ilo.use_web_server_for_images = False
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.clean_up_ramdisk(task)
            cleanup_vmedia_mock.assert_called_once_with(task)

    @mock.patch.object(manager_utils, 'node_set_boot_device', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'cleanup_vmedia_boot', spec_set=True,
                       autospec=True)
    def _test_prepare_instance_whole_disk_image(
            self, cleanup_vmedia_boot_mock, set_boot_device_mock):
        self.node.driver_internal_info = {'is_whole_disk_image': True}
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.prepare_instance(task)

            cleanup_vmedia_boot_mock.assert_called_once_with(task)
            set_boot_device_mock.assert_called_once_with(task,
                                                         boot_devices.DISK,
                                                         persistent=True)

    def test_prepare_instance_whole_disk_image_local(self):
        self.node.instance_info = {'capabilities': '{"boot_option": "local"}'}
        self.node.save()
        self._test_prepare_instance_whole_disk_image()

    def test_prepare_instance_whole_disk_image(self):
        self._test_prepare_instance_whole_disk_image()

    @mock.patch.object(ilo_boot.IloVirtualMediaBoot,
                       '_configure_vmedia_boot', spec_set=True,
                       autospec=True)
    @mock.patch.object(ilo_common, 'cleanup_vmedia_boot', spec_set=True,
                       autospec=True)
    def test_prepare_instance_partition_image(
            self, cleanup_vmedia_boot_mock,
            configure_vmedia_mock):
        self.node.driver_internal_info = {'root_uuid_or_disk_id': "some_uuid"}
        self.node.save()
        with task_manager.acquire(self.context, self.node.uuid,
                                  shared=False) as task:
            task.driver.boot.prepare_instance(task)

            cleanup_vmedia_boot_mock.assert_called_once_with(task)
            configure_vmedia_mock.assert_called_once_with(mock.ANY, task,
                                                          "some_uuid")
