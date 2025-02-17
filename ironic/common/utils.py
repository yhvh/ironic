# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
# Copyright (c) 2012 NTT DOCOMO, INC.
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

"""Utilities and helper functions."""

import contextlib
import datetime
import errno
import hashlib
import os
import random
import re
import shutil
import tempfile

import netaddr
from oslo_concurrency import processutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import excutils
from oslo_utils import timeutils
import paramiko
import pytz
import six

from ironic.common import exception
from ironic.common.i18n import _
from ironic.common.i18n import _LE
from ironic.common.i18n import _LW

utils_opts = [
    cfg.StrOpt('rootwrap_config',
               default="/etc/ironic/rootwrap.conf",
               help=_('Path to the rootwrap configuration file to use for '
                      'running commands as root.')),
    cfg.StrOpt('tempdir',
               default=tempfile.gettempdir(),
               help=_('Temporary working directory, default is Python temp '
                      'dir.')),
]

CONF = cfg.CONF
CONF.register_opts(utils_opts)

LOG = logging.getLogger(__name__)


def _get_root_helper():
    # NOTE(jlvillal): This function has been moved to ironic-lib. And is
    # planned to be deleted here. If need to modify this function, please
    # also do the same modification in ironic-lib
    return 'sudo ironic-rootwrap %s' % CONF.rootwrap_config


def execute(*cmd, **kwargs):
    """Convenience wrapper around oslo's execute() method.

    :param cmd: Passed to processutils.execute.
    :param use_standard_locale: True | False. Defaults to False. If set to
                                True, execute command with standard locale
                                added to environment variables.
    :returns: (stdout, stderr) from process execution
    :raises: UnknownArgumentError
    :raises: ProcessExecutionError
    """

    use_standard_locale = kwargs.pop('use_standard_locale', False)
    if use_standard_locale:
        env = kwargs.pop('env_variables', os.environ.copy())
        env['LC_ALL'] = 'C'
        kwargs['env_variables'] = env
    if kwargs.get('run_as_root') and 'root_helper' not in kwargs:
        kwargs['root_helper'] = _get_root_helper()
    result = processutils.execute(*cmd, **kwargs)
    LOG.debug('Execution completed, command line is "%s"',
              ' '.join(map(str, cmd)))
    LOG.debug('Command stdout is: "%s"' % result[0])
    LOG.debug('Command stderr is: "%s"' % result[1])
    return result


def trycmd(*args, **kwargs):
    """Convenience wrapper around oslo's trycmd() method."""
    if kwargs.get('run_as_root') and 'root_helper' not in kwargs:
        kwargs['root_helper'] = _get_root_helper()
    return processutils.trycmd(*args, **kwargs)


def ssh_connect(connection):
    """Method to connect to a remote system using ssh protocol.

    :param connection: a dict of connection parameters.
    :returns: paramiko.SSHClient -- an active ssh connection.
    :raises: SSHConnectFailed

    """
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        key_contents = connection.get('key_contents')
        if key_contents:
            data = six.moves.StringIO(key_contents)
            if "BEGIN RSA PRIVATE" in key_contents:
                pkey = paramiko.RSAKey.from_private_key(data)
            elif "BEGIN DSA PRIVATE" in key_contents:
                pkey = paramiko.DSSKey.from_private_key(data)
            else:
                # Can't include the key contents - secure material.
                raise ValueError(_("Invalid private key"))
        else:
            pkey = None
        ssh.connect(connection.get('host'),
                    username=connection.get('username'),
                    password=connection.get('password'),
                    port=connection.get('port', 22),
                    pkey=pkey,
                    key_filename=connection.get('key_filename'),
                    timeout=connection.get('timeout', 10))

        # send TCP keepalive packets every 20 seconds
        ssh.get_transport().set_keepalive(20)
    except Exception as e:
        LOG.debug("SSH connect failed: %s" % e)
        raise exception.SSHConnectFailed(host=connection.get('host'))

    return ssh


def generate_uid(topic, size=8):
    characters = '01234567890abcdefghijklmnopqrstuvwxyz'
    choices = [random.choice(characters) for _x in range(size)]
    return '%s-%s' % (topic, ''.join(choices))


def random_alnum(size=32):
    characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(characters) for _ in range(size))


def delete_if_exists(pathname):
    """delete a file, but ignore file not found error."""

    try:
        os.unlink(pathname)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        else:
            raise


def is_valid_boolstr(val):
    """Check if the provided string is a valid bool string or not."""
    boolstrs = ('true', 'false', 'yes', 'no', 'y', 'n', '1', '0')
    return str(val).lower() in boolstrs


def is_valid_mac(address):
    """Verify the format of a MAC address.

    Check if a MAC address is valid and contains six octets. Accepts
    colon-separated format only.

    :param address: MAC address to be validated.
    :returns: True if valid. False if not.

    """
    m = "[0-9a-f]{2}(:[0-9a-f]{2}){5}$"
    return (isinstance(address, six.string_types) and
            re.match(m, address.lower()))


_is_valid_logical_name_re = re.compile(r'^[A-Z0-9-._~]+$', re.I)

# old is_hostname_safe() regex, retained for backwards compat
_is_hostname_safe_re = re.compile(r"""^
[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?  # host
(\.[a-z0-9\-_]{0,62}[a-z0-9])*       # domain
\.?                                  # trailing dot
$""", re.X)


def is_valid_logical_name(hostname):
    """Determine if a logical name is valid.

    The logical name may only consist of RFC3986 unreserved
    characters, to wit:

        ALPHA / DIGIT / "-" / "." / "_" / "~"
    """
    if not isinstance(hostname, six.string_types) or len(hostname) > 255:
        return False

    return _is_valid_logical_name_re.match(hostname) is not None


def is_hostname_safe(hostname):
    """Old check for valid logical node names.

    Retained for compatibility with REST API < 1.10.

    Nominally, checks that the supplied hostname conforms to:
        * http://en.wikipedia.org/wiki/Hostname
        * http://tools.ietf.org/html/rfc952
        * http://tools.ietf.org/html/rfc1123

    In practice, this check has several shortcomings and errors that
    are more thoroughly documented in bug #1468508.

    :param hostname: The hostname to be validated.
    :returns: True if valid. False if not.
    """
    if not isinstance(hostname, six.string_types) or len(hostname) > 255:
        return False

    return _is_hostname_safe_re.match(hostname) is not None


def validate_and_normalize_mac(address):
    """Validate a MAC address and return normalized form.

    Checks whether the supplied MAC address is formally correct and
    normalize it to all lower case.

    :param address: MAC address to be validated and normalized.
    :returns: Normalized and validated MAC address.
    :raises: InvalidMAC If the MAC address is not valid.

    """
    if not is_valid_mac(address):
        raise exception.InvalidMAC(mac=address)
    return address.lower()


def is_valid_ipv6_cidr(address):
    try:
        str(netaddr.IPNetwork(address, version=6).cidr)
        return True
    except Exception:
        return False


def get_shortened_ipv6(address):
    addr = netaddr.IPAddress(address, version=6)
    return str(addr.ipv6())


def get_shortened_ipv6_cidr(address):
    net = netaddr.IPNetwork(address, version=6)
    return str(net.cidr)


def is_valid_cidr(address):
    """Check if the provided ipv4 or ipv6 address is a valid CIDR address."""
    try:
        # Validate the correct CIDR Address
        netaddr.IPNetwork(address)
    except netaddr.core.AddrFormatError:
        return False
    except UnboundLocalError:
        # NOTE(MotoKen): work around bug in netaddr 0.7.5 (see detail in
        # https://github.com/drkjam/netaddr/issues/2)
        return False

    # Prior validation partially verify /xx part
    # Verify it here
    ip_segment = address.split('/')

    if (len(ip_segment) <= 1 or
        ip_segment[1] == ''):
        return False

    return True


def get_ip_version(network):
    """Returns the IP version of a network (IPv4 or IPv6).

    :raises: AddrFormatError if invalid network.
    """
    if netaddr.IPNetwork(network).version == 6:
        return "IPv6"
    elif netaddr.IPNetwork(network).version == 4:
        return "IPv4"


def convert_to_list_dict(lst, label):
    """Convert a value or list into a list of dicts."""
    if not lst:
        return None
    if not isinstance(lst, list):
        lst = [lst]
    return [{label: x} for x in lst]


def sanitize_hostname(hostname):
    """Return a hostname which conforms to RFC-952 and RFC-1123 specs."""
    if isinstance(hostname, six.text_type):
        hostname = hostname.encode('latin-1', 'ignore')

    hostname = re.sub(b'[ _]', b'-', hostname)
    hostname = re.sub(b'[^\w.-]+', b'', hostname)
    hostname = hostname.lower()
    hostname = hostname.strip(b'.-')

    return hostname


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        LOG.debug("Reloading cached file %s" % filename)
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


def file_open(*args, **kwargs):
    """Open file

    see built-in file() documentation for more details

    Note: The reason this is kept in a separate module is to easily
          be able to provide a stub module that doesn't alter system
          state at all (for unit tests)
    """
    return file(*args, **kwargs)


def hash_file(file_like_object):
    """Generate a hash for the contents of a file."""
    checksum = hashlib.sha1()
    for chunk in iter(lambda: file_like_object.read(32768), b''):
        checksum.update(chunk)
    return checksum.hexdigest()


@contextlib.contextmanager
def temporary_mutation(obj, **kwargs):
    """Temporarily change object attribute.

    Temporarily set the attr on a particular object to a given value then
    revert when finished.

    One use of this is to temporarily set the read_deleted flag on a context
    object:

        with temporary_mutation(context, read_deleted="yes"):
            do_something_that_needed_deleted_objects()
    """
    def is_dict_like(thing):
        return hasattr(thing, 'has_key')

    def get(thing, attr, default):
        if is_dict_like(thing):
            return thing.get(attr, default)
        else:
            return getattr(thing, attr, default)

    def set_value(thing, attr, val):
        if is_dict_like(thing):
            thing[attr] = val
        else:
            setattr(thing, attr, val)

    def delete(thing, attr):
        if is_dict_like(thing):
            del thing[attr]
        else:
            delattr(thing, attr)

    NOT_PRESENT = object()

    old_values = {}
    for attr, new_value in kwargs.items():
        old_values[attr] = get(obj, attr, NOT_PRESENT)
        set_value(obj, attr, new_value)

    try:
        yield
    finally:
        for attr, old_value in old_values.items():
            if old_value is NOT_PRESENT:
                delete(obj, attr)
            else:
                set_value(obj, attr, old_value)


@contextlib.contextmanager
def tempdir(**kwargs):
    tempfile.tempdir = CONF.tempdir
    tmpdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            LOG.error(_LE('Could not remove tmpdir: %s'), e)


def mkfs(fs, path, label=None):
    """Format a file or block device

    :param fs: Filesystem type (examples include 'swap', 'ext3', 'ext4'
               'btrfs', etc.)
    :param path: Path to file or block device to format
    :param label: Volume label to use
    """
    # NOTE(jlvillal): This function has been moved to ironic-lib. And is
    # planned to be deleted here. If need to modify this function, please also
    # do the same modification in ironic-lib
    if fs == 'swap':
        args = ['mkswap']
    else:
        args = ['mkfs', '-t', fs]
    # add -F to force no interactive execute on non-block device.
    if fs in ('ext3', 'ext4'):
        args.extend(['-F'])
    if label:
        if fs in ('msdos', 'vfat'):
            label_opt = '-n'
        else:
            label_opt = '-L'
        args.extend([label_opt, label])
    args.append(path)
    try:
        execute(*args, run_as_root=True, use_standard_locale=True)
    except processutils.ProcessExecutionError as e:
        with excutils.save_and_reraise_exception() as ctx:
            if os.strerror(errno.ENOENT) in e.stderr:
                ctx.reraise = False
                LOG.exception(_LE('Failed to make file system. '
                                  'File system %s is not supported.'), fs)
                raise exception.FileSystemNotSupported(fs=fs)
            else:
                LOG.exception(_LE('Failed to create a file system '
                                  'in %(path)s. Error: %(error)s'),
                              {'path': path, 'error': e})


def unlink_without_raise(path):
    # NOTE(jlvillal): This function has been moved to ironic-lib. And is
    # planned to be deleted here. If need to modify this function, please also
    # do the same modification in ironic-lib
    try:
        os.unlink(path)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        else:
            LOG.warning(_LW("Failed to unlink %(path)s, error: %(e)s"),
                        {'path': path, 'e': e})


def rmtree_without_raise(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
    except OSError as e:
        LOG.warning(_LW("Failed to remove dir %(path)s, error: %(e)s"),
                    {'path': path, 'e': e})


def write_to_file(path, contents):
    with open(path, 'w') as f:
        f.write(contents)


def create_link_without_raise(source, link):
    try:
        os.symlink(source, link)
    except OSError as e:
        if e.errno == errno.EEXIST:
            return
        else:
            LOG.warning(
                _LW("Failed to create symlink from %(source)s to %(link)s"
                    ", error: %(e)s"),
                {'source': source, 'link': link, 'e': e})


def safe_rstrip(value, chars=None):
    """Removes trailing characters from a string if that does not make it empty

    :param value: A string value that will be stripped.
    :param chars: Characters to remove.
    :return: Stripped value.

    """
    if not isinstance(value, six.string_types):
        LOG.warning(_LW("Failed to remove trailing character. Returning "
                        "original object. Supplied object is not a string: "
                        "%s,"), value)
        return value

    return value.rstrip(chars) or value


def mount(src, dest, *args):
    """Mounts a device/image file on specified location.

    :param src: the path to the source file for mounting
    :param dest: the path where it needs to be mounted.
    :param args: a tuple containing the arguments to be
        passed to mount command.
    :raises: processutils.ProcessExecutionError if it failed
        to run the process.
    """
    args = ('mount', ) + args + (src, dest)
    execute(*args, run_as_root=True, check_exit_code=[0])


def umount(loc, *args):
    """Umounts a mounted location.

    :param loc: the path to be unmounted.
    :param args: a tuple containing the argumnets to be
        passed to the umount command.
    :raises: processutils.ProcessExecutionError if it failed
        to run the process.
    """
    args = ('umount', ) + args + (loc, )
    execute(*args, run_as_root=True, check_exit_code=[0])


def dd(src, dst, *args):
    """Execute dd from src to dst.

    :param src: the input file for dd command.
    :param dst: the output file for dd command.
    :param args: a tuple containing the arguments to be
        passed to dd command.
    :raises: processutils.ProcessExecutionError if it failed
        to run the process.
    """
    # NOTE(jlvillal): This function has been moved to ironic-lib. And is
    # planned to be deleted here. If need to modify this function, please also
    # do the same modification in ironic-lib
    LOG.debug("Starting dd process.")
    execute('dd', 'if=%s' % src, 'of=%s' % dst, *args,
            use_standard_locale=True, run_as_root=True, check_exit_code=[0])


def is_http_url(url):
    # NOTE(jlvillal): This function has been moved to ironic-lib. And is
    # planned to be deleted here. If need to modify this function, please also
    # do the same modification in ironic-lib
    url = url.lower()
    return url.startswith('http://') or url.startswith('https://')


def check_dir(directory_to_check=None, required_space=1):
    """Check a directory is usable.

    This function can be used by drivers to check that directories
    they need to write to are usable. This should be called from the
    drivers init function. This function checks that the directory
    exists and then calls check_dir_writable and check_dir_free_space.
    If directory_to_check is not provided the default is to use the
    temp directory.

    :param directory_to_check: the directory to check.
    :param required_space: amount of space to check for in MiB.
    :raises: PathNotFound if directory can not be found
    :raises: DirectoryNotWritable if user is unable to write to the
             directory
    :raises InsufficientDiskSpace: if free space is < required space
    """
    # check if directory_to_check is passed in, if not set to tempdir
    if directory_to_check is None:
        directory_to_check = CONF.tempdir

    LOG.debug("checking directory: %s", directory_to_check)

    if not os.path.exists(directory_to_check):
        raise exception.PathNotFound(dir=directory_to_check)

    _check_dir_writable(directory_to_check)
    _check_dir_free_space(directory_to_check, required_space)


def _check_dir_writable(chk_dir):
    """Check that the chk_dir is able to be written to.

    :param chk_dir: Directory to check
    :raises: DirectoryNotWritable if user is unable to write to the
             directory
    """
    is_writable = os.access(chk_dir, os.W_OK)
    if not is_writable:
        raise exception.DirectoryNotWritable(dir=chk_dir)


def _check_dir_free_space(chk_dir, required_space=1):
    """Check that directory has some free space.

    :param chk_dir: Directory to check
    :param required_space: amount of space to check for in MiB.
    :raises InsufficientDiskSpace: if free space is < required space
    """
    # check that we have some free space
    stat = os.statvfs(chk_dir)
    # get dir free space in MiB.
    free_space = float(stat.f_bsize * stat.f_bavail) / 1024 / 1024
    # check for at least required_space MiB free
    if free_space < required_space:
        raise exception.InsufficientDiskSpace(path=chk_dir,
                                              required=required_space,
                                              actual=free_space)


def get_updated_capabilities(current_capabilities, new_capabilities):
    """Returns an updated capability string.

    This method updates the original (or current) capabilities with the new
    capabilities. The original capabilities would typically be from a node's
    properties['capabilities']. From new_capabilities, any new capabilities
    are added, and existing capabilities may have their values updated. This
    updated capabilities string is returned.

    :param current_capabilities: Current capability string
    :param new_capabilities: the dictionary of capabilities to be updated.
    :returns: An updated capability string.
        with new_capabilities.
    :raises: ValueError, if current_capabilities is malformed or
        if new_capabilities is not a dictionary
    """
    if not isinstance(new_capabilities, dict):
        raise ValueError(
            _("Cannot update capabilities. The new capabilities should be in "
              "a dictionary. Provided value is %s") % new_capabilities)

    cap_dict = {}
    if current_capabilities:
        try:
            cap_dict = dict(x.split(':', 1)
                            for x in current_capabilities.split(','))
        except ValueError:
            # Capabilities can be filled by operator.  ValueError can
            # occur in malformed capabilities like:
            # properties/capabilities='boot_mode:bios,boot_option'.
            raise ValueError(
                _("Invalid capabilities string '%s'.") % current_capabilities)

    cap_dict.update(new_capabilities)
    return ','.join('%(key)s:%(value)s' % {'key': key, 'value': value}
                    for key, value in cap_dict.items())


def is_regex_string_in_file(path, string):
    with open(path, 'r') as inf:
        return any(re.search(string, line) for line in inf.readlines())


def unix_file_modification_datetime(file_name):
    return timeutils.normalize_time(
        # normalize time to be UTC without timezone
        datetime.datetime.fromtimestamp(
            # fromtimestamp will return local time by default, make it UTC
            os.path.getmtime(file_name), tz=pytz.utc
        )
    )


def validate_network_port(port):
    """Validates the given port.

    :param port: TCP/UDP port.
    :raises: InvalidParameterValue, if the port is invalid.
    """

    try:
        port = int(port)
    except ValueError:
        raise exception.InvalidParameterValue(_(
            'Port number "%s" is not a valid integer.') % port)
    if port < 1 or port > 65535:
        raise exception.InvalidParameterValue(_(
            'Port number "%s" is out of range. Valid port '
            'numbers must be between 1 and 65535.') % port)
    return port
