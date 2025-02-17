# Copyright 2013 Hewlett-Packard Development Company, L.P.
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
"""Ironic test utilities."""


from oslo_utils import timeutils

from ironic.common import states
from ironic.db import api as db_api


def get_test_ipmi_info():
    return {
        "ipmi_address": "1.2.3.4",
        "ipmi_username": "admin",
        "ipmi_password": "fake"
    }


def get_test_ipmi_bridging_parameters():
    return {
        "ipmi_bridging": "dual",
        "ipmi_local_address": "0x20",
        "ipmi_transit_channel": "0",
        "ipmi_transit_address": "0x82",
        "ipmi_target_channel": "7",
        "ipmi_target_address": "0x72"
    }


def get_test_ssh_info(auth_type='password'):
    result = {
        "ssh_address": "1.2.3.4",
        "ssh_username": "admin",
        "ssh_port": 22,
        "ssh_virt_type": "vbox",
    }
    if 'password' == auth_type:
        result['ssh_password'] = 'fake'
    elif 'file' == auth_type:
        result['ssh_key_filename'] = '/not/real/file'
    elif 'key' == auth_type:
        result['ssh_key_contents'] = '--BEGIN PRIVATE ...blah'
    elif 'too_many' == auth_type:
        result['ssh_password'] = 'fake'
        result['ssh_key_filename'] = '/not/real/file'
    else:
        # No auth details (is invalid)
        pass
    return result


def get_test_pxe_driver_info():
    return {
        "deploy_kernel": "glance://deploy_kernel_uuid",
        "deploy_ramdisk": "glance://deploy_ramdisk_uuid",
    }


def get_test_pxe_driver_internal_info():
    return {
        "is_whole_disk_image": False,
    }


def get_test_pxe_instance_info():
    return {
        "image_source": "glance://image_uuid",
        "root_gb": 100,
    }


def get_test_seamicro_info():
    return {
        "seamicro_api_endpoint": "http://1.2.3.4",
        "seamicro_username": "admin",
        "seamicro_password": "fake",
        "seamicro_server_id": "0/0",
    }


def get_test_ilo_info():
    return {
        "ilo_address": "1.2.3.4",
        "ilo_username": "admin",
        "ilo_password": "fake",
    }


def get_test_drac_info():
    return {
        "drac_host": "1.2.3.4",
        "drac_port": "443",
        "drac_path": "/wsman",
        "drac_protocol": "https",
        "drac_username": "admin",
        "drac_password": "fake",
    }


def get_test_irmc_info():
    return {
        "irmc_address": "1.2.3.4",
        "irmc_username": "admin0",
        "irmc_password": "fake0",
        "irmc_port": 80,
        "irmc_auth_method": "digest",
    }


def get_test_amt_info():
    return {
        "amt_address": "1.2.3.4",
        "amt_protocol": "http",
        "amt_username": "admin",
        "amt_password": "fake",
    }


def get_test_msftocs_info():
    return {
        "msftocs_base_url": "http://fakehost:8000",
        "msftocs_username": "admin",
        "msftocs_password": "fake",
        "msftocs_blade_id": 1,
    }


def get_test_agent_instance_info():
    return {
        'image_source': 'fake-image',
        'image_url': 'http://image',
        'image_checksum': 'checksum',
        'image_disk_format': 'qcow2',
        'image_container_format': 'bare',
    }


def get_test_agent_driver_info():
    return {
        'deploy_kernel': 'glance://deploy_kernel_uuid',
        'deploy_ramdisk': 'glance://deploy_ramdisk_uuid',
    }


def get_test_agent_driver_internal_info():
    return {
        'agent_url': 'http://127.0.0.1/foo',
        'is_whole_disk_image': True,
    }


def get_test_iboot_info():
    return {
        "iboot_address": "1.2.3.4",
        "iboot_username": "admin",
        "iboot_password": "fake",
    }


def get_test_snmp_info(**kw):
    result = {
        "snmp_driver": kw.get("snmp_driver", "teltronix"),
        "snmp_address": kw.get("snmp_address", "1.2.3.4"),
        "snmp_port": kw.get("snmp_port", "161"),
        "snmp_outlet": kw.get("snmp_outlet", "1"),
        "snmp_version": kw.get("snmp_version", "1")
    }
    if result["snmp_version"] in ("1", "2c"):
        result["snmp_community"] = kw.get("snmp_community", "public")
    elif result["snmp_version"] == "3":
        result["snmp_security"] = kw.get("snmp_security", "public")
    return result


def get_test_node(**kw):
    properties = {
        "cpu_arch": "x86_64",
        "cpus": "8",
        "local_gb": "10",
        "memory_mb": "4096",
    }
    fake_info = {"foo": "bar", "fake_password": "fakepass"}
    return {
        'id': kw.get('id', 123),
        'name': kw.get('name', None),
        'uuid': kw.get('uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'),
        'chassis_id': kw.get('chassis_id', None),
        'conductor_affinity': kw.get('conductor_affinity', None),
        'power_state': kw.get('power_state', states.NOSTATE),
        'target_power_state': kw.get('target_power_state', states.NOSTATE),
        'provision_state': kw.get('provision_state', states.NOSTATE),
        'target_provision_state': kw.get('target_provision_state',
                                         states.NOSTATE),
        'provision_updated_at': kw.get('provision_updated_at'),
        'last_error': kw.get('last_error'),
        'instance_uuid': kw.get('instance_uuid'),
        'instance_info': kw.get('instance_info', fake_info),
        'driver': kw.get('driver', 'fake'),
        'driver_info': kw.get('driver_info', fake_info),
        'driver_internal_info': kw.get('driver_internal_info', fake_info),
        'clean_step': kw.get('clean_step'),
        'properties': kw.get('properties', properties),
        'reservation': kw.get('reservation'),
        'maintenance': kw.get('maintenance', False),
        'maintenance_reason': kw.get('maintenance_reason'),
        'console_enabled': kw.get('console_enabled', False),
        'extra': kw.get('extra', {}),
        'updated_at': kw.get('updated_at'),
        'created_at': kw.get('created_at'),
        'inspection_finished_at': kw.get('inspection_finished_at'),
        'inspection_started_at': kw.get('inspection_started_at'),
        'raid_config': kw.get('raid_config'),
        'target_raid_config': kw.get('target_raid_config'),
    }


def create_test_node(**kw):
    """Create test node entry in DB and return Node DB object.

    Function to be used to create test Node objects in the database.

    :param kw: kwargs with overriding values for node's attributes.
    :returns: Test Node DB object.

    """
    node = get_test_node(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del node['id']
    dbapi = db_api.get_instance()
    return dbapi.create_node(node)


def get_test_port(**kw):
    return {
        'id': kw.get('id', 987),
        'uuid': kw.get('uuid', '1be26c0b-03f2-4d2e-ae87-c02d7f33c781'),
        'node_id': kw.get('node_id', 123),
        'address': kw.get('address', '52:54:00:cf:2d:31'),
        'extra': kw.get('extra', {}),
        'created_at': kw.get('created_at'),
        'updated_at': kw.get('updated_at'),
    }


def create_test_port(**kw):
    """Create test port entry in DB and return Port DB object.

    Function to be used to create test Port objects in the database.

    :param kw: kwargs with overriding values for port's attributes.
    :returns: Test Port DB object.

    """
    port = get_test_port(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del port['id']
    dbapi = db_api.get_instance()
    return dbapi.create_port(port)


def get_test_chassis(**kw):
    return {
        'id': kw.get('id', 42),
        'uuid': kw.get('uuid', 'e74c40e0-d825-11e2-a28f-0800200c9a66'),
        'extra': kw.get('extra', {}),
        'description': kw.get('description', 'data-center-1-chassis'),
        'created_at': kw.get('created_at'),
        'updated_at': kw.get('updated_at'),
    }


def create_test_chassis(**kw):
    """Create test chassis entry in DB and return Chassis DB object.

    Function to be used to create test Chassis objects in the database.

    :param kw: kwargs with overriding values for chassis's attributes.
    :returns: Test Chassis DB object.

    """
    chassis = get_test_chassis(**kw)
    # Let DB generate ID if it isn't specified explicitly
    if 'id' not in kw:
        del chassis['id']
    dbapi = db_api.get_instance()
    return dbapi.create_chassis(chassis)


def get_test_conductor(**kw):
    return {
        'id': kw.get('id', 6),
        'hostname': kw.get('hostname', 'test-conductor-node'),
        'drivers': kw.get('drivers', ['fake-driver', 'null-driver']),
        'created_at': kw.get('created_at', timeutils.utcnow()),
        'updated_at': kw.get('updated_at', timeutils.utcnow()),
    }


def get_test_ucs_info():
    return {
        "ucs_username": "admin",
        "ucs_password": "password",
        "ucs_service_profile": "org-root/ls-devstack",
        "ucs_address": "ucs-b",
    }


def get_test_cimc_info():
    return {
        "cimc_username": "admin",
        "cimc_password": "password",
        "cimc_address": "1.2.3.4",
    }


def get_test_oneview_properties():
    return {
        "cpu_arch": "x86_64",
        "cpus": "8",
        "local_gb": "10",
        "memory_mb": "4096",
        "capabilities": "server_hardware_type_uri:fake_sht_uri,"
                        "enclosure_group_uri:fake_eg_uri"
    }


def get_test_oneview_driver_info():
    return {
        'server_hardware_uri': 'fake_uri',
        'server_profile_template_uri': 'fake_spt_uri'
    }
