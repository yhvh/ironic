# -*- encoding: utf-8 -*-
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
Abstract base classes for drivers.
"""

import abc
import collections
import copy
import inspect
import json
import os

import eventlet
from oslo_log import log as logging
from oslo_service import periodic_task
from oslo_utils import excutils
import six

from ironic.common import exception
from ironic.common.i18n import _LE, _LW
from ironic.common import raid

LOG = logging.getLogger(__name__)

RAID_CONFIG_SCHEMA = os.path.join(os.path.dirname(__file__),
                                  'raid_config_schema.json')


@six.add_metaclass(abc.ABCMeta)
class BaseDriver(object):
    """Base class for all drivers.

    Defines the `core`, `standardized`, and `vendor-specific` interfaces for
    drivers. Any loadable driver must implement all `core` interfaces.
    Actual implementation may instantiate one or more classes, as long as
    the interfaces are appropriate.
    """

    core_interfaces = []
    standard_interfaces = []

    power = None
    core_interfaces.append('power')
    """`Core` attribute for managing power state.

    A reference to an instance of :class:PowerInterface.
    """

    deploy = None
    core_interfaces.append('deploy')
    """`Core` attribute for managing deployments.

    A reference to an instance of :class:DeployInterface.
    """

    console = None
    standard_interfaces.append('console')
    """`Standard` attribute for managing console access.

    A reference to an instance of :class:ConsoleInterface.
    May be None, if unsupported by a driver.
    """

    rescue = None
    # NOTE(deva): hide rescue from the interface list in Icehouse
    #             because the API for this has not been created yet.
    # standard_interfaces.append('rescue')
    """`Standard` attribute for accessing rescue features.

    A reference to an instance of :class:RescueInterface.
    May be None, if unsupported by a driver.
    """

    management = None
    """`Standard` attribute for management related features.

    A reference to an instance of :class:ManagementInterface.
    May be None, if unsupported by a driver.
    """
    standard_interfaces.append('management')

    boot = None
    """`Standard` attribute for boot related features.

    A reference to an instance of :class:BootInterface.
    May be None, if unsupported by a driver.
    """
    standard_interfaces.append('boot')

    vendor = None
    """Attribute for accessing any vendor-specific extensions.

    A reference to an instance of :class:VendorInterface.
    May be None, if the driver does not implement any vendor extensions.
    """

    inspect = None
    """`Standard` attribute for inspection related features.

    A reference to an instance of :class:InspectInterface.
    May be None, if unsupported by a driver.
    """
    standard_interfaces.append('inspect')

    raid = None
    """`Standard` attribute for RAID related features.

    A reference to an instance of :class:RaidInterface.
    May be None, if unsupported by a driver.
    """
    standard_interfaces.append('raid')

    @abc.abstractmethod
    def __init__(self):
        pass

    def get_properties(self):
        """Get the properties of the driver.

        :returns: dictionary of <property name>:<property description> entries.
        """

        properties = {}
        for iface_name in (self.core_interfaces +
                           self.standard_interfaces +
                           ['vendor']):
            iface = getattr(self, iface_name, None)
            if iface:
                properties.update(iface.get_properties())
        return properties


class BaseInterface(object):
    """A base interface implementing common functions for Driver Interfaces."""
    interface_type = 'base'

    def __new__(cls, *args, **kwargs):
        # Get the list of clean steps when the interface is initialized by
        # the conductor. We use __new__ instead of __init___
        # to avoid breaking backwards compatibility with all the drivers.
        # We want to return all steps, regardless of priority.

        super_new = super(BaseInterface, cls).__new__
        if super_new is object.__new__:
            instance = super_new(cls)
        else:
            instance = super_new(cls, *args, **kwargs)
        instance.clean_steps = []
        for n, method in inspect.getmembers(instance, inspect.ismethod):
            if getattr(method, '_is_clean_step', False):
                # Create a CleanStep to represent this method
                step = {'step': method.__name__,
                        'priority': method._clean_step_priority,
                        'abortable': method._clean_step_abortable,
                        'interface': instance.interface_type}
                instance.clean_steps.append(step)
        LOG.debug('Found clean steps %(steps)s for interface %(interface)s',
                  {'steps': instance.clean_steps,
                   'interface': instance.interface_type})
        return instance

    def get_clean_steps(self, task):
        """Get a list of (enabled and disabled) clean steps for the interface.

        This function will return all clean steps (both enabled and disabled)
        for the interface, in an unordered list.

        :param task: A TaskManager object, useful for interfaces overriding
            this function
        :returns: A list of clean step dictionaries
        """
        return self.clean_steps

    def execute_clean_step(self, task, step):
        """Execute the clean step on task.node.

        A clean step should take a single argument: a TaskManager object.
        A step can be executed synchronously or asynchronously. A step should
        return None if the method has completed synchronously or
        states.CLEANWAIT if the step will continue to execute asynchronously.
        If the step executes asynchronously, it should issue a call to the
        'continue_node_clean' RPC, so the conductor can begin the next
        clean step.

        :param task: A TaskManager object
        :param step: The clean step dictionary representing the step to execute
        :returns: None if this method has completed synchronously, or
            states.CLEANWAIT if the step will continue to execute
            asynchronously.
        """
        return getattr(self, step['step'])(task)


@six.add_metaclass(abc.ABCMeta)
class DeployInterface(BaseInterface):
    """Interface for deploy-related actions."""
    interface_type = 'deploy'

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific Node deployment info.

        This method validates whether the 'driver_info' property of the
        task's node contains the required information for this driver to
        deploy images to the node. If invalid, raises an exception; otherwise
        returns None.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def deploy(self, task):
        """Perform a deployment to the task's node.

        Perform the necessary work to deploy an image onto the specified node.
        This method will be called after prepare(), which may have already
        performed any preparatory steps, such as pre-caching some data for the
        node.

        :param task: a TaskManager instance containing the node to act on.
        :returns: status of the deploy. One of ironic.common.states.
        """

    @abc.abstractmethod
    def tear_down(self, task):
        """Tear down a previous deployment on the task's node.

        Given a node that has been previously deployed to,
        do all cleanup and tear down necessary to "un-deploy" that node.

        :param task: a TaskManager instance containing the node to act on.
        :returns: status of the deploy. One of ironic.common.states.
        """

    @abc.abstractmethod
    def prepare(self, task):
        """Prepare the deployment environment for the task's node.

        If preparation of the deployment environment ahead of time is possible,
        this method should be implemented by the driver.

        If implemented, this method must be idempotent. It may be called
        multiple times for the same node on the same conductor, and it may be
        called by multiple conductors in parallel. Therefore, it must not
        require an exclusive lock.

        This method is called before `deploy`.

        :param task: a TaskManager instance containing the node to act on.
        """

    @abc.abstractmethod
    def clean_up(self, task):
        """Clean up the deployment environment for the task's node.

        If preparation of the deployment environment ahead of time is possible,
        this method should be implemented by the driver. It should erase
        anything cached by the `prepare` method.

        If implemented, this method must be idempotent. It may be called
        multiple times for the same node on the same conductor, and it may be
        called by multiple conductors in parallel. Therefore, it must not
        require an exclusive lock.

        This method is called before `tear_down`.

        :param task: a TaskManager instance containing the node to act on.
        """

    @abc.abstractmethod
    def take_over(self, task):
        """Take over management of this task's node from a dead conductor.

        If conductors' hosts maintain a static relationship to nodes, this
        method should be implemented by the driver to allow conductors to
        perform the necessary work during the remapping of nodes to conductors
        when a conductor joins or leaves the cluster.

        For example, the PXE driver has an external dependency:
            Neutron must forward DHCP BOOT requests to a conductor which has
            prepared the tftpboot environment for the given node. When a
            conductor goes offline, another conductor must change this setting
            in Neutron as part of remapping that node's control to itself.
            This is performed within the `takeover` method.

        :param task: a TaskManager instance containing the node to act on.
        """

    def prepare_cleaning(self, task):
        """Prepare the node for cleaning or zapping tasks.

        For example, nodes that use the Ironic Python Agent will need to
        boot the ramdisk in order to do in-band cleaning and zapping tasks.

        If the function is asynchronous, the driver will need to handle
        settings node.driver_internal_info['clean_steps'] and node.clean_step,
        as they would be set in ironic.conductor.manager._do_node_clean,
        but cannot be set when this is asynchronous. After, the interface
        should make an RPC call to continue_node_cleaning to start cleaning.

        NOTE(JoshNang) this should be moved to BootInterface when it gets
        implemented.

        :param task: a TaskManager instance containing the node to act on.
        :returns: If this function is going to be asynchronous, should return
            `states.CLEANWAIT`. Otherwise, should return `None`. The interface
            will need to call _get_cleaning_steps and then RPC to
            continue_node_cleaning
        """
        pass

    def tear_down_cleaning(self, task):
        """Tear down after cleaning or zapping is completed.

        Given that cleaning or zapping is complete, do all cleanup and tear
        down necessary to allow the node to be deployed to again.

        NOTE(JoshNang) this should be moved to BootInterface when it gets
        implemented.

        :param task: a TaskManager instance containing the node to act on.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class BootInterface(object):
    """Interface for boot-related actions."""

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific info for booting.

        This method validates the driver-specific info for booting the
        ramdisk and instance on the node.  If invalid, raises an
        exception; otherwise returns None.

        :param task: a task from TaskManager.
        :returns: None
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def prepare_ramdisk(self, task, ramdisk_params):
        """Prepares the boot of Ironic ramdisk.

        This method prepares the boot of the deploy ramdisk after
        reading relevant information from the node's database.

        :param task: a task from TaskManager.
        :param ramdisk_params: the options to be passed to the ironic ramdisk.
            Different implementations might want to boot the ramdisk in
            different ways by passing parameters to them.  For example,

            - When DIB ramdisk is booted to deploy a node, it takes the
              parameters iscsi_target_iqn, deployment_id, ironic_api_url, etc.
            - When Agent ramdisk is booted to deploy a node, it takes the
              parameters ipa-driver-name, ipa-api-url, root_device, etc.

            Other implementations can make use of ramdisk_params to pass such
            information.  Different implementations of boot interface will
            have different ways of passing parameters to the ramdisk.
        :returns: None
        """

    @abc.abstractmethod
    def clean_up_ramdisk(self, task):
        """Cleans up the boot of ironic ramdisk.

        This method cleans up the environment that was setup for booting the
        deploy ramdisk.

        :param task: a task from TaskManager.
        :returns: None
        """

    @abc.abstractmethod
    def prepare_instance(self, task):
        """Prepares the boot of instance.

        This method prepares the boot of the instance after reading
        relevant information from the node's database.

        :param task: a task from TaskManager.
        :returns: None
        """

    @abc.abstractmethod
    def clean_up_instance(self, task):
        """Cleans up the boot of instance.

        This method cleans up the environment that was setup for booting
        the instance.

        :param task: a task from TaskManager.
        :returns: None
        """


@six.add_metaclass(abc.ABCMeta)
class PowerInterface(BaseInterface):
    """Interface for power-related actions."""
    interface_type = 'power'

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific Node power info.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        manage the power state of the node. If invalid, raises an exception;
        otherwise, returns None.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def get_power_state(self, task):
        """Return the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :raises: MissingParameterValue if a required parameter is missing.
        :returns: a power state. One of :mod:`ironic.common.states`.
        """

    @abc.abstractmethod
    def set_power_state(self, task, power_state):
        """Set the power state of the task's node.

        :param task: a TaskManager instance containing the node to act on.
        :param power_state: Any power state from :mod:`ironic.common.states`.
        :raises: MissingParameterValue if a required parameter is missing.
        """

    @abc.abstractmethod
    def reboot(self, task):
        """Perform a hard reboot of the task's node.

        Drivers are expected to properly handle case when node is powered off
        by powering it on.

        :param task: a TaskManager instance containing the node to act on.
        :raises: MissingParameterValue if a required parameter is missing.
        """


@six.add_metaclass(abc.ABCMeta)
class ConsoleInterface(object):
    """Interface for console-related actions."""

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific Node console info.

        This method validates whether the 'driver_info' property of the
        supplied node contains the required information for this driver to
        provide console access to the Node. If invalid, raises an exception;
        otherwise returns None.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def start_console(self, task):
        """Start a remote console for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        """

    @abc.abstractmethod
    def stop_console(self, task):
        """Stop the remote console session for the task's node.

        :param task: a TaskManager instance containing the node to act on.
        """

    @abc.abstractmethod
    def get_console(self, task):
        """Get connection information about the console.

        This method should return the necessary information for the
        client to access the console.

        :param task: a TaskManager instance containing the node to act on.
        :returns: the console connection information.
        """


@six.add_metaclass(abc.ABCMeta)
class RescueInterface(object):
    """Interface for rescue-related actions."""

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the rescue info stored in the node' properties.

        If invalid, raises an exception; otherwise returns None.

        :param task: a TaskManager instance containing the node to act on.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def rescue(self, task):
        """Boot the task's node into a rescue environment.

        :param task: a TaskManager instance containing the node to act on.
        """

    @abc.abstractmethod
    def unrescue(self, task):
        """Tear down the rescue environment, and return to normal.

        :param task: a TaskManager instance containing the node to act on.
        """


# Representation of a single vendor method metadata
VendorMetadata = collections.namedtuple('VendorMetadata', ['method',
                                                           'metadata'])


def _passthru(http_methods, method=None, async=True, driver_passthru=False,
              description=None, attach=False):
    """A decorator for registering a function as a passthru function.

    Decorator ensures function is ready to catch any ironic exceptions
    and reraise them after logging the issue. It also catches non-ironic
    exceptions reraising them as a VendorPassthruException after writing
    a log.

    Logs need to be added because even though the exception is being
    reraised, it won't be handled if it is an async. call.

    :param http_methods: A list of supported HTTP methods by the vendor
                         function.
    :param method: an arbitrary string describing the action to be taken.
    :param async: Boolean value. If True invoke the passthru function
                  asynchronously; if False, synchronously. If a passthru
                  function touches the BMC we strongly recommend it to
                  run asynchronously. Defaults to True.
    :param driver_passthru: Boolean value. True if this is a driver vendor
                            passthru method, and False if it is a node
                            vendor passthru method.
    :param attach: Boolean value. True if the return value should be
                   attached to the response object, and False if the return
                   value should be returned in the response body.
                   Defaults to False.
    :param description: a string shortly describing what the method does.

    """
    def handle_passthru(func):
        api_method = method
        if api_method is None:
            api_method = func.__name__

        supported_ = [i.upper() for i in http_methods]
        description_ = description or ''
        metadata = VendorMetadata(api_method, {'http_methods': supported_,
                                               'async': async,
                                               'description': description_,
                                               'attach': attach})
        if driver_passthru:
            func._driver_metadata = metadata
        else:
            func._vendor_metadata = metadata

        passthru_logmessage = _LE('vendor_passthru failed with method %s')

        @six.wraps(func)
        def passthru_handler(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except exception.IronicException as e:
                with excutils.save_and_reraise_exception():
                    LOG.exception(passthru_logmessage, api_method)
            except Exception as e:
                # catch-all in case something bubbles up here
                LOG.exception(passthru_logmessage, api_method)
                raise exception.VendorPassthruException(message=e)
        return passthru_handler
    return handle_passthru


def passthru(http_methods, method=None, async=True, description=None,
             attach=False):
    return _passthru(http_methods, method, async, driver_passthru=False,
                     description=description, attach=attach)


def driver_passthru(http_methods, method=None, async=True, description=None,
                    attach=False):
    return _passthru(http_methods, method, async, driver_passthru=True,
                     description=description, attach=attach)


@six.add_metaclass(abc.ABCMeta)
class VendorInterface(object):
    """Interface for all vendor passthru functionality.

    Additional vendor- or driver-specific capabilities should be
    implemented as a method in the class inheriting from this class and
    use the @passthru or @driver_passthru decorators.

    Methods decorated with @driver_passthru should be short-lived because
    it is a blocking call.
    """

    def __new__(cls, *args, **kwargs):
        super_new = super(VendorInterface, cls).__new__
        if super_new is object.__new__:
            inst = super_new(cls)
        else:
            inst = super_new(cls, *args, **kwargs)

        inst.vendor_routes = {}
        inst.driver_routes = {}

        for name, ref in inspect.getmembers(inst, predicate=inspect.ismethod):
            vmeta = getattr(ref, '_vendor_metadata', None)
            dmeta = getattr(ref, '_driver_metadata', None)

            if vmeta is not None:
                metadata = copy.deepcopy(vmeta.metadata)
                metadata['func'] = ref
                inst.vendor_routes.update({vmeta.method: metadata})

            if dmeta is not None:
                metadata = copy.deepcopy(dmeta.metadata)
                metadata['func'] = ref
                inst.driver_routes.update({dmeta.method: metadata})

        return inst

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task, method=None, **kwargs):
        """Validate vendor-specific actions.

        If invalid, raises an exception; otherwise returns None.

        :param task: a task from TaskManager.
        :param method: method to be validated
        :param kwargs: info for action.
        :raises: UnsupportedDriverExtension if 'method' can not be mapped to
                 the supported interfaces.
        :raises: InvalidParameterValue if kwargs does not contain 'method'.
        :raises: MissingParameterValue
        """

    def driver_validate(self, method, **kwargs):
        """Validate driver-vendor-passthru actions.

        If invalid, raises an exception; otherwise returns None.

        :param method: method to be validated
        :param kwargs: info for action.
        :raises: MissingParameterValue if kwargs does not contain
                 certain parameter.
        :raises: InvalidParameterValue if parameter does not match.
        """
        pass


@six.add_metaclass(abc.ABCMeta)
class ManagementInterface(BaseInterface):
    """Interface for management related actions."""
    interface_type = 'management'

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific management information.

        If invalid, raises an exception; otherwise returns None.

        :param task: a task from TaskManager.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def get_supported_boot_devices(self, task):
        """Get a list of the supported boot devices.

        :param task: a task from TaskManager.
        :returns: A list with the supported boot devices defined
                  in :mod:`ironic.common.boot_devices`.
        """

    @abc.abstractmethod
    def set_boot_device(self, task, device, persistent=False):
        """Set the boot device for a node.

        Set the boot device to use on next reboot of the node.

        :param task: a task from TaskManager.
        :param device: the boot device, one of
                       :mod:`ironic.common.boot_devices`.
        :param persistent: Boolean value. True if the boot device will
                           persist to all future boots, False if not.
                           Default: False.
        :raises: InvalidParameterValue if an invalid boot device is
                 specified.
        :raises: MissingParameterValue if a required parameter is missing
        """

    @abc.abstractmethod
    def get_boot_device(self, task):
        """Get the current boot device for a node.

        Provides the current boot device of the node. Be aware that not
        all drivers support this.

        :param task: a task from TaskManager.
        :raises: MissingParameterValue if a required parameter is missing
        :returns: a dictionary containing:

            :boot_device:
                the boot device, one of :mod:`ironic.common.boot_devices` or
                None if it is unknown.
            :persistent:
                Whether the boot device will persist to all future boots or
                not, None if it is unknown.

        """

    @abc.abstractmethod
    def get_sensors_data(self, task):
        """Get sensors data method.

        :param task: a TaskManager instance.
        :raises: FailedToGetSensorData when getting the sensor data fails.
        :raises: FailedToParseSensorData when parsing sensor data fails.
        :returns: returns a consistent format dict of sensor data grouped by
                  sensor type, which can be processed by Ceilometer.
                  eg,

                  ::

                      {
                        'Sensor Type 1': {
                          'Sensor ID 1': {
                            'Sensor Reading': 'current value',
                            'key1': 'value1',
                            'key2': 'value2'
                          },
                          'Sensor ID 2': {
                            'Sensor Reading': 'current value',
                            'key1': 'value1',
                            'key2': 'value2'
                          }
                        },
                        'Sensor Type 2': {
                          'Sensor ID 3': {
                            'Sensor Reading': 'current value',
                            'key1': 'value1',
                            'key2': 'value2'
                          },
                          'Sensor ID 4': {
                            'Sensor Reading': 'current value',
                            'key1': 'value1',
                            'key2': 'value2'
                          }
                        }
                      }
        """


@six.add_metaclass(abc.ABCMeta)
class InspectInterface(object):
    """Interface for inspection-related actions."""

    ESSENTIAL_PROPERTIES = {'memory_mb', 'local_gb', 'cpus', 'cpu_arch'}
    """The properties required by scheduler/deploy."""

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    @abc.abstractmethod
    def validate(self, task):
        """Validate the driver-specific inspection information.

        If invalid, raises an exception; otherwise returns None.

        :param task: a task from TaskManager.
        :raises: InvalidParameterValue
        :raises: MissingParameterValue
        """

    @abc.abstractmethod
    def inspect_hardware(self, task):
        """Inspect hardware.

        Inspect hardware to obtain the essential & additional hardware
        properties.

        :param task: a task from TaskManager.
        :raises: HardwareInspectionFailure, if unable to get essential
                 hardware properties.
        :returns: resulting state of the inspection i.e. states.MANAGEABLE
                  or None.
        """


class RAIDInterface(BaseInterface):
    interface_type = 'raid'

    def __init__(self):
        """Constructor for RAIDInterface class."""
        with open(RAID_CONFIG_SCHEMA, 'r') as raid_schema_fobj:
            self.raid_schema = json.load(raid_schema_fobj)

    @abc.abstractmethod
    def get_properties(self):
        """Return the properties of the interface.

        :returns: dictionary of <property name>:<property description> entries.
        """

    def validate(self, task):
        """Validates the RAID Interface.

        This method validates the properties defined by Ironic for RAID
        configuration. Driver implementations of this interface can override
        this method for doing more validations (such as BMC's credentials).

        :param task: a TaskManager instance.
        :raises: InvalidParameterValue, if the RAID configuration is invalid.
        :raises: MissingParameterValue, if some parameters are missing.
        """
        target_raid_config = task.node.target_raid_config
        if not target_raid_config:
            return
        self.validate_raid_config(task, target_raid_config)

    def validate_raid_config(self, task, raid_config):
        """Validates the given RAID configuration.

        This method validates the given RAID configuration.  Driver
        implementations of this interface can override this method to support
        custom parameters for RAID configuration.

        :param task: a TaskManager instance.
        :param raid_config: The RAID configuration to validate.
        :raises: InvalidParameterValue, if the RAID configuration is invalid.
        """
        raid.validate_configuration(raid_config, self.raid_schema)

    @abc.abstractmethod
    def create_configuration(self, task,
                             create_root_volume=True,
                             create_nonroot_volumes=True):
        """Creates RAID configuration on the given node.

        This method creates a RAID configuration on the given node.
        It assumes that the target RAID configuration is already
        available in node.target_raid_config.
        Implementations of this interface are supposed to read the
        RAID configuration from node.target_raid_config. After the
        RAID configuration is done (either in this method OR in a call-back
        method), ironic.common.raid.update_raid_info()
        may be called to sync the node's RAID-related information with the
        RAID configuration applied on the node.

        :param task: a TaskManager instance.
        :param create_root_volume: Setting this to False indicates
            not to create root volume that is specified in the node's
            target_raid_config. Default value is True.
        :param create_nonroot_volumes: Setting this to False indicates
            not to create non-root volumes (all except the root volume) in the
            node's target_raid_config.  Default value is True.
        :returns: states.CLEANWAIT if RAID configuration is in progress
            asynchronously or None if it is complete.
        """

    @abc.abstractmethod
    def delete_configuration(self, task):
        """Deletes RAID configuration on the given node.

        This method deletes the RAID configuration on the give node.
        After RAID configuration is deleted, node.raid_config should be
        cleared by the implementation.

        :param task: a TaskManager instance.
        :returns: states.CLEANWAIT if deletion is in progress
            asynchronously or None if it is complete.
        """

    def get_logical_disk_properties(self):
        """Get the properties that can be specified for logical disks.

        This method returns a dictionary containing the properties that can
        be specified for logical disks and a textual description for them.

        :returns: A dictionary containing properties that can be mentioned for
            logical disks and a textual description for them.
        """
        return raid.get_logical_disk_properties(self.raid_schema)


def clean_step(priority, abortable=False):
    """Decorator for cleaning and zapping steps.

    If priority is greater than 0, the function will be executed as part
    of the CLEANING (sync) or CLEANWAIT (async) state for any node using
    the interface with the decorated clean step. During the cleaning,
    a list of steps will be ordered by priority for all interfaces
    associated with the node, and then execute_clean_step() will be
    called on each step. Steps will be executed based on priority,
    with the highest priority step being called first, the next highest
    priority being call next, and so on.

    Decorated clean steps should take a single argument, a TaskManager object.

    Any step with this decorator will be available for ZAPPING, even if
    priority is set to 0. Zapping steps will be executed in a similar fashion
    to cleaning and with the same TaskManager object, but the priority ordering
    is determined by the user when calling the zapping API.

    Clean steps can be either synchronous or asynchronous. If the step is
    synchronous, it should return `None` when finished, and the conductor will
    continue on to the next step. If the step is asynchronous, the step should
    return `states.CLEANWAIT` to signal to the conductor. When the step is
    complete, the step should make an RPC call to `continue_node_clean` to move
    to the next step in cleaning.

    Example::

        class MyInterface(base.BaseInterface):
            # CONF.example_cleaning_priority should be an int CONF option
            @base.clean_step(priority=CONF.example_cleaning_priority)
            def example_cleaning(self, task):
                # do some cleaning

    :param priority: an integer priority, should be a CONF option
    :param abortable: Boolean value. Whether the clean step is abortable
                      or not; defaults to False.
    """
    def decorator(func):
        func._is_clean_step = True
        func._clean_step_priority = priority
        func._clean_step_abortable = abortable
        return func
    return decorator


def driver_periodic_task(parallel=True, **other):
    """Decorator for a driver-specific periodic task.

    Example::

        class MyDriver(base.BaseDriver):
            @base.driver_periodic_task(spacing=42)
            def task(self, manager, context):
                # do some job

    :param parallel: If True (default), this task is run in a separate thread.
            If False, this task will be run in the conductor's periodic task
            loop, rather than a separate greenthread. This parameter is
            deprecated and will be ignored starting with Mitaka cycle.
    :param other: arguments to pass to @periodic_task.periodic_task
    """
    # TODO(dtantsur): drop all this magic once
    # https://review.openstack.org/#/c/134303/ lands
    semaphore = eventlet.semaphore.BoundedSemaphore()

    def decorator2(func):
        @six.wraps(func)
        def wrapper(*args, **kwargs):
            if parallel:
                def _internal():
                    with semaphore:
                        func(*args, **kwargs)

                eventlet.greenthread.spawn_n(_internal)
            else:
                LOG.warning(_LW(
                    'Using periodic tasks with parallel=False is deprecated, '
                    '"parallel" argument will be ignored starting with '
                    'the Mitaka release'))
                func(*args, **kwargs)

        # NOTE(dtantsur): name should be unique
        other.setdefault('name', '%s.%s' % (func.__module__, func.__name__))
        decorator = periodic_task.periodic_task(**other)
        return decorator(wrapper)

    return decorator2
