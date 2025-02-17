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

from oslo_config import cfg
from oslo_utils import uuidutils
from six.moves.urllib import parse as urlparse
from swiftclient import utils as swift_utils

from ironic.common import exception as exc
from ironic.common.glance_service import base_image_service
from ironic.common.glance_service import service
from ironic.common.glance_service import service_utils
from ironic.common.i18n import _


glance_opts = [
    cfg.ListOpt('allowed_direct_url_schemes',
                default=[],
                help=_('A list of URL schemes that can be downloaded directly '
                       'via the direct_url.  Currently supported schemes: '
                       '[file].')),
    # To upload this key to Swift:
    # swift post -m Temp-Url-Key:secretkey
    # When using radosgw, temp url key could be uploaded via the above swift
    # command, or with:
    # radosgw-admin user modify --uid=user --temp-url-key=secretkey
    cfg.StrOpt('swift_temp_url_key',
               help=_('The secret token given to Swift to allow temporary URL '
                      'downloads. Required for temporary URLs.'),
               secret=True),
    cfg.IntOpt('swift_temp_url_duration',
               default=1200,
               help=_('The length of time in seconds that the temporary URL '
                      'will be valid for. Defaults to 20 minutes. If some '
                      'deploys get a 401 response code when trying to '
                      'download from the temporary URL, try raising this '
                      'duration.')),
    cfg.StrOpt(
        'swift_endpoint_url',
        help=_('The "endpoint" (scheme, hostname, optional port) for '
               'the Swift URL of the form '
               '"endpoint_url/api_version/[account/]container/object_id". '
               'Do not include trailing "/". '
               'For example, use "https://swift.example.com". In case of '
               'using RADOS Gateway, endpoint may also contain /swift path, '
               'if it does not, it will be appended. '
               'Required for temporary URLs.')),
    cfg.StrOpt(
        'swift_api_version',
        default='v1',
        help=_('The Swift API version to create a temporary URL for. '
               'Defaults to "v1". Swift temporary URL format: '
               '"endpoint_url/api_version/[account/]container/object_id"')),
    cfg.StrOpt(
        'swift_account',
        help=_('The account that Glance uses to communicate with '
               'Swift. The format is "AUTH_uuid". "uuid" is the '
               'UUID for the account configured in the glance-api.conf. '
               'Required for temporary URLs when Glance backend is Swift. '
               'For example: "AUTH_a422b2-91f3-2f46-74b7-d7c9e8958f5d30". '
               'Swift temporary URL format: '
               '"endpoint_url/api_version/[account/]container/object_id"')),
    cfg.StrOpt(
        'swift_container',
        default='glance',
        help=_('The Swift container Glance is configured to store its '
               'images in. Defaults to "glance", which is the default '
               'in glance-api.conf. '
               'Swift temporary URL format: '
               '"endpoint_url/api_version/[account/]container/object_id"')),
    cfg.IntOpt('swift_store_multiple_containers_seed',
               default=0,
               help=_('This should match a config by the same name in the '
                      'Glance configuration file. When set to 0, a '
                      'single-tenant store will only use one '
                      'container to store all images. When set to an integer '
                      'value between 1 and 32, a single-tenant store will use '
                      'multiple containers to store images, and this value '
                      'will determine how many containers are created.')),
    cfg.StrOpt('temp_url_endpoint_type',
               default='swift',
               help=_('Type of the endpoint to use for temporary URLs. It '
                      'depends on an actual Glance backend used. Possible '
                      'values are "swift" and "radosgw".'))
]

CONF = cfg.CONF
CONF.register_opts(glance_opts, group='glance')


class GlanceImageService(base_image_service.BaseImageService,
                         service.ImageService):

    def detail(self, **kwargs):
        return self._detail(method='list', **kwargs)

    def show(self, image_id):
        return self._show(image_id, method='get')

    def download(self, image_id, data=None):
        return self._download(image_id, method='data', data=data)

    def create(self, image_meta, data=None):
        image_id = self._create(image_meta, method='create', data=None)['id']
        return self.update(image_id, None, data)

    def update(self, image_id, image_meta, data=None, purge_props=False):
        # NOTE(ghe): purge_props not working until bug 1206472 solved
        return self._update(image_id, image_meta, data, method='update',
                            purge_props=False)

    def delete(self, image_id):
        return self._delete(image_id, method='delete')

    def swift_temp_url(self, image_info):
        """Generate a no-auth Swift temporary URL.

        This function will generate the temporary Swift URL using the image
        id from Glance and the config options: 'swift_endpoint_url',
        'swift_api_version', 'swift_account' and 'swift_container'.
        The temporary URL will be valid for 'swift_temp_url_duration' seconds.
        This allows Ironic to download a Glance image without passing around
        an auth_token.

        :param image_info: The return from a GET request to Glance for a
            certain image_id. Should be a dictionary, with keys like 'name' and
            'checksum'. See
            http://docs.openstack.org/developer/glance/glanceapi.html for
            examples.
        :returns: A signed Swift URL from which an image can be downloaded,
            without authentication.

        :raises: InvalidParameterValue if Swift config options are not set
            correctly.
        :raises: MissingParameterValue if a required parameter is not set.
        :raises: ImageUnacceptable if the image info from Glance does not
            have a image ID.
        """
        self._validate_temp_url_config()

        if ('id' not in image_info or not
                uuidutils.is_uuid_like(image_info['id'])):
            raise exc.ImageUnacceptable(_(
                'The given image info does not have a valid image id: %s')
                % image_info)

        url_fragments = {
            'api_version': CONF.glance.swift_api_version,
            'account': CONF.glance.swift_account,
            'container': self._get_swift_container(image_info['id']),
            'object_id': image_info['id']
        }

        endpoint_url = CONF.glance.swift_endpoint_url
        if CONF.glance.temp_url_endpoint_type == 'radosgw':
            chunks = urlparse.urlsplit(CONF.glance.swift_endpoint_url)
            if not chunks.path:
                endpoint_url = urlparse.urljoin(
                    endpoint_url, 'swift')
            elif chunks.path != '/swift':
                raise exc.InvalidParameterValue(
                    _('Swift endpoint URL should only contain scheme, '
                      'hostname, optional port and optional /swift path '
                      'without trailing slash; provided value is: %s')
                    % endpoint_url)
            template = '/{api_version}/{container}/{object_id}'
        else:
            template = '/{api_version}/{account}/{container}/{object_id}'

        url_path = template.format(**url_fragments)
        path = swift_utils.generate_temp_url(
            path=url_path,
            seconds=CONF.glance.swift_temp_url_duration,
            key=CONF.glance.swift_temp_url_key,
            method='GET')

        return '{endpoint_url}{url_path}'.format(
            endpoint_url=endpoint_url, url_path=path)

    def _validate_temp_url_config(self):
        """Validate the required settings for a temporary URL."""
        if not CONF.glance.swift_temp_url_key:
            raise exc.MissingParameterValue(_(
                'Swift temporary URLs require a shared secret to be created. '
                'You must provide "swift_temp_url_key" as a config option.'))
        if not CONF.glance.swift_endpoint_url:
            raise exc.MissingParameterValue(_(
                'Swift temporary URLs require a Swift endpoint URL. '
                'You must provide "swift_endpoint_url" as a config option.'))
        if (not CONF.glance.swift_account and
                CONF.glance.temp_url_endpoint_type == 'swift'):
            raise exc.MissingParameterValue(_(
                'Swift temporary URLs require a Swift account string. '
                'You must provide "swift_account" as a config option.'))
        if CONF.glance.swift_temp_url_duration < 0:
            raise exc.InvalidParameterValue(_(
                '"swift_temp_url_duration" must be a positive integer.'))
        seed_num_chars = CONF.glance.swift_store_multiple_containers_seed
        if (seed_num_chars is None or seed_num_chars < 0
                or seed_num_chars > 32):
            raise exc.InvalidParameterValue(_(
                "An integer value between 0 and 32 is required for"
                " swift_store_multiple_containers_seed."))

    def _get_swift_container(self, image_id):
        """Get the Swift container the image is stored in.

        Code based on: https://github.com/openstack/glance_store/blob/3cd690b3
        7dc9d935445aca0998e8aec34a3e3530/glance_store/
        _drivers/swift/store.py#L725

        Returns appropriate container name depending upon value of
        ``swift_store_multiple_containers_seed``. In single-container mode,
        which is a seed value of 0, simply returns ``swift_container``.
        In multiple-container mode, returns ``swift_container`` as the
        prefix plus a suffix determined by the multiple container seed

        examples:
            single-container mode:  'glance'
            multiple-container mode: 'glance_3a1' for image uuid 3A1xxxxxxx...

        :param image_id: UUID of image
        :returns: The name of the swift container the image is stored in
        """
        seed_num_chars = CONF.glance.swift_store_multiple_containers_seed

        if seed_num_chars > 0:
            image_id = str(image_id).lower()

            num_dashes = image_id[:seed_num_chars].count('-')
            num_chars = seed_num_chars + num_dashes
            name_suffix = image_id[:num_chars]
            new_container_name = (CONF.glance.swift_container +
                                  '_' + name_suffix)
            return new_container_name
        else:
            return CONF.glance.swift_container

    def _get_location(self, image_id):
        """Get storage URL.

        Returns the direct url representing the backend storage location,
        or None if this attribute is not shown by Glance.
        """
        image_meta = self.call('get', image_id)

        if not service_utils.is_image_available(self.context, image_meta):
            raise exc.ImageNotFound(image_id=image_id)

        return getattr(image_meta, 'direct_url', None)
