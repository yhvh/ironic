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
VirtualBox Driver Modules
"""

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import importutils

from ironic.common import boot_devices
from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common import states
from ironic.conductor import task_manager
from ironic.drivers import base

pyremotevbox = importutils.try_import('pyremotevbox')
if pyremotevbox:
    from pyremotevbox import exception as virtualbox_exc
    from pyremotevbox import vbox as virtualbox

IRONIC_TO_VIRTUALBOX_DEVICE_MAPPING = {
    boot_devices.PXE: 'Network',
    boot_devices.DISK: 'HardDisk',
    boot_devices.CDROM: 'DVD',
}
VIRTUALBOX_TO_IRONIC_DEVICE_MAPPING = {
    v: k for k, v in IRONIC_TO_VIRTUALBOX_DEVICE_MAPPING.items()}

VIRTUALBOX_TO_IRONIC_POWER_MAPPING = {
    'PoweredOff': states.POWER_OFF,
    'Running': states.POWER_ON,
    'Error': states.ERROR
}

opts = [
    cfg.PortOpt('port',
                default=18083,
                help=_('Port on which VirtualBox web service is listening.')),
]
CONF = cfg.CONF
CONF.register_opts(opts, group='virtualbox')

LOG = logging.getLogger(__name__)

REQUIRED_PROPERTIES = {
    'virtualbox_vmname': _("Name of the VM in VirtualBox. Required."),
    'virtualbox_host': _("IP address or hostname of the VirtualBox host. "
                         "Required.")
}

OPTIONAL_PROPERTIES = {
    'virtualbox_username': _("Username for the VirtualBox host. "
                             "Default value is ''. Optional."),
    'virtualbox_password': _("Password for 'virtualbox_username'. "
                             "Default value is ''. Optional."),
    'virtualbox_port': _("Port on which VirtualBox web service is listening. "
                         "Optional."),
}

COMMON_PROPERTIES = REQUIRED_PROPERTIES.copy()
COMMON_PROPERTIES.update(OPTIONAL_PROPERTIES)


def _strip_virtualbox_from_param_name(param_name):

    if param_name.startswith('virtualbox_'):
        return param_name[11:]
    else:
        return param_name


def _parse_driver_info(node):
    """Gets the driver specific node driver info.

    This method validates whether the 'driver_info' property of the
    supplied node contains the required information for this driver.

    :param node: an Ironic Node object.
    :returns: a dict containing information from driver_info (or where
        applicable, config values).
    :raises: MissingParameterValue, if some required parameter(s) are missing
        in the node's driver_info.
    :raises: InvalidParameterValue, if some parameter(s) have invalid value(s)
        in the node's driver_info.
    """
    info = node.driver_info
    d_info = {}

    missing_params = []
    for param in REQUIRED_PROPERTIES:
        try:
            d_info_param_name = _strip_virtualbox_from_param_name(param)
            d_info[d_info_param_name] = info[param]
        except KeyError:
            missing_params.append(param)

    if missing_params:
        msg = (_("The following parameters are missing in driver_info: %s") %
               ', '.join(missing_params))
        raise exception.MissingParameterValue(msg)

    for param in OPTIONAL_PROPERTIES:
        if param in info:
            d_info_param_name = _strip_virtualbox_from_param_name(param)
            d_info[d_info_param_name] = info[param]

    try:
        d_info['port'] = int(d_info.get('port', CONF.virtualbox.port))
    except ValueError:
        msg = _("'virtualbox_port' is not an integer.")
        raise exception.InvalidParameterValue(msg)

    return d_info


def _run_virtualbox_method(node, ironic_method, vm_object_method,
                           *call_args, **call_kwargs):
    """Runs a method of pyremotevbox.vbox.VirtualMachine

    This runs a method from pyremotevbox.vbox.VirtualMachine.
    The VirtualMachine method to be invoked and the argument(s) to be
    passed to it are to be provided.

    :param node: an Ironic Node object.
    :param ironic_method: the Ironic method which called
        '_run_virtualbox_method'. This is used for logging only.
    :param vm_object_method: The method on the VirtualMachine object
        to be called.
    :param call_args: The args to be passed to 'vm_object_method'.
    :param call_kwargs: The kwargs to be passed to the 'vm_object_method'.
    :returns: The value returned by 'vm_object_method'
    :raises: VirtualBoxOperationFailed, if execution of 'vm_object_method'
        failed.
    :raises: InvalidParameterValue,
        - if 'vm_object_method' is not a valid 'VirtualMachine' method.
        - if some parameter(s) have invalid value(s) in the node's driver_info.
    :raises: MissingParameterValue, if some required parameter(s) are missing
        in the node's driver_info.
    :raises: pyremotevbox.exception.VmInWrongPowerState, if operation cannot
        be performed when vm is in the current power state.
    """
    driver_info = _parse_driver_info(node)
    try:
        host = virtualbox.VirtualBoxHost(**driver_info)
        vm_object = host.find_vm(driver_info['vmname'])
    except virtualbox_exc.PyRemoteVBoxException as exc:
        LOG.error(_LE("Failed while creating a VirtualMachine object for "
                      "node %(node_id)s. Error: %(error)s."),
                  {'node_id': node.uuid, 'error': exc})
        raise exception.VirtualBoxOperationFailed(operation=vm_object_method,
                                                  error=exc)

    try:
        func = getattr(vm_object, vm_object_method)
    except AttributeError:
        error_msg = _("Invalid VirtualMachine method '%s' passed "
                      "to '_run_virtualbox_method'.")
        raise exception.InvalidParameterValue(error_msg % vm_object_method)

    try:
        return func(*call_args, **call_kwargs)
    except virtualbox_exc.PyRemoteVBoxException as exc:
        error_msg = _LE("'%(ironic_method)s' failed for node %(node_id)s with "
                        "error: %(error)s.")
        LOG.error(error_msg, {'ironic_method': ironic_method,
                              'node_id': node.uuid,
                              'error': exc})
        raise exception.VirtualBoxOperationFailed(operation=vm_object_method,
                                                  error=exc)


class VirtualBoxPower(base.PowerInterface):

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Check if node.driver_info contains the required credentials.

        :param task: a TaskManager instance.
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        """
        _parse_driver_info(task.node)

    def get_power_state(self, task):
        """Gets the current power state.

        :param task: a TaskManager instance.
        :returns: one of :mod:`ironic.common.states`
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        :raises: VirtualBoxOperationFailed, if error encountered from
            VirtualBox operation.
        """
        power_status = _run_virtualbox_method(task.node, 'get_power_state',
                                              'get_power_status')
        try:
            return VIRTUALBOX_TO_IRONIC_POWER_MAPPING[power_status]
        except KeyError:
            msg = _LE("VirtualBox returned unknown state '%(state)s' for "
                      "node %(node)s")
            LOG.error(msg, {'state': power_status, 'node': task.node.uuid})
            return states.ERROR

    @task_manager.require_exclusive_lock
    def set_power_state(self, task, target_state):
        """Turn the current power state on or off.

        :param task: a TaskManager instance.
        :param target_state: The desired power state POWER_ON,POWER_OFF or
            REBOOT from :mod:`ironic.common.states`.
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info OR if an invalid power state
            was specified.
        :raises: VirtualBoxOperationFailed, if error encountered from
            VirtualBox operation.
        """
        if target_state == states.POWER_OFF:
            _run_virtualbox_method(task.node, 'set_power_state', 'stop')
        elif target_state == states.POWER_ON:
            _run_virtualbox_method(task.node, 'set_power_state', 'start')
        elif target_state == states.REBOOT:
            self.reboot(task)
        else:
            msg = _("'set_power_state' called with invalid power "
                    "state '%s'") % target_state
            raise exception.InvalidParameterValue(msg)

    @task_manager.require_exclusive_lock
    def reboot(self, task):
        """Reboot the node.

        :param task: a TaskManager instance.
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        :raises: VirtualBoxOperationFailed, if error encountered from
            VirtualBox operation.
        """
        _run_virtualbox_method(task.node, 'reboot', 'stop')
        _run_virtualbox_method(task.node, 'reboot', 'start')


class VirtualBoxManagement(base.ManagementInterface):

    def get_properties(self):
        return COMMON_PROPERTIES

    def validate(self, task):
        """Check that 'driver_info' contains required credentials.

        Validates whether the 'driver_info' property of the supplied
        task's node contains the required credentials information.

        :param task: a task from TaskManager.
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        """
        _parse_driver_info(task.node)

    def get_supported_boot_devices(self, task):
        """Get a list of the supported boot devices.

        :param task: a task from TaskManager.
        :returns: A list with the supported boot devices defined
                  in :mod:`ironic.common.boot_devices`.
        """
        return list(IRONIC_TO_VIRTUALBOX_DEVICE_MAPPING.keys())

    def get_boot_device(self, task):
        """Get the current boot device for a node.

        :param task: a task from TaskManager.
        :returns: a dictionary containing:
            'boot_device': one of the ironic.common.boot_devices or None
            'persistent': True if boot device is persistent, False otherwise
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        :raises: VirtualBoxOperationFailed, if error encountered from
            VirtualBox operation.
        """
        boot_dev = _run_virtualbox_method(task.node, 'get_boot_device',
                                          'get_boot_device')
        persistent = True
        ironic_boot_dev = VIRTUALBOX_TO_IRONIC_DEVICE_MAPPING.get(boot_dev,
                                                                  None)
        if not ironic_boot_dev:
            persistent = None
            msg = _LE("VirtualBox returned unknown boot device '%(device)s' "
                      "for node %(node)s")
            LOG.error(msg, {'device': boot_dev, 'node': task.node.uuid})

        return {'boot_device': ironic_boot_dev, 'persistent': persistent}

    @task_manager.require_exclusive_lock
    def set_boot_device(self, task, device, persistent=False):
        """Set the boot device for a node.

        :param task: a task from TaskManager.
        :param device: ironic.common.boot_devices
        :param persistent: This argument is ignored as VirtualBox support only
            persistent boot devices.
        :raises: MissingParameterValue, if some required parameter(s) are
            missing in the node's driver_info.
        :raises: InvalidParameterValue, if some parameter(s) have invalid
            value(s) in the node's driver_info.
        :raises: VirtualBoxOperationFailed, if error encountered from
            VirtualBox operation.
        """
        # NOTE(rameshg87): VirtualBox has only persistent boot devices.
        try:
            boot_dev = IRONIC_TO_VIRTUALBOX_DEVICE_MAPPING[device]
        except KeyError:
            raise exception.InvalidParameterValue(
                _("Invalid boot device %s specified.") % device)

        try:
            _run_virtualbox_method(task.node, 'set_boot_device',
                                   'set_boot_device', boot_dev)
        except virtualbox_exc.VmInWrongPowerState as exc:
            # NOTE(rameshg87): We cannot change the boot device when the vm
            # is powered on. This is a VirtualBox limitation. We just log
            # the error silently and return because throwing error will cause
            # deploys to fail (pxe and agent deploy mechanisms change the boot
            # device after completing the deployment, when node is powered on).
            # Since this is driver that is meant only for developers, this
            # should be okay. Developers will need to set the boot device
            # manually after powering off the vm when deployment is complete.
            # This will be documented.
            LOG.error(_LE("'set_boot_device' failed for node %(node_id)s "
                          "with error: %(error)s"),
                      {'node_id': task.node.uuid, 'error': exc})

    def get_sensors_data(self, task):
        """Get sensors data.

        :param task: a TaskManager instance.
        :raises: FailedToGetSensorData when getting the sensor data fails.
        :raises: FailedToParseSensorData when parsing sensor data fails.
        :returns: returns a consistent format dict of sensor data grouped by
            sensor type, which can be processed by Ceilometer.
        """
        raise NotImplementedError()
