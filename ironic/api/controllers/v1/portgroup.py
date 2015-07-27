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

import datetime

from oslo_utils import uuidutils
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes

from ironic.api.controllers import base
from ironic.api.controllers import link
from ironic.api.controllers.v1 import collection
from ironic.api.controllers.v1 import types
from ironic.api.controllers.v1 import utils as api_utils
from ironic.api import expose
from ironic.common import exception
from ironic.common.i18n import _
from ironic import objects


_DEFAULT_RETURN_FIELDS = ('uuid', 'address')


class PortgroupPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/node_uuid']


class Portgroup(base.APIBase):
    """API representation of a portgroup.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a
    portgroup.
    """

    _node_uuid = None

    def _get_node_uuid(self):
        return self._node_uuid

    def _set_node_uuid(self, value):
        if value and self._node_uuid != value:
            try:
                node = objects.Node.get(pecan.request.context, value)
                self._node_uuid = node.uuid
                # NOTE: Create the node_id attribute on-the-fly
                #       to satisfy the api -> rpc object
                #       conversion.
                self.node_id = node.id
            except exception.NodeNotFound as e:
                # Change error code because 404 (NotFound) is inappropriate
                # response for a POST request to create a Port
                e.code = 400  # BadRequest
                raise e
        elif value == wtypes.Unset:
            self._node_uuid = wtypes.Unset

    uuid = types.uuid
    """Unique UUID for this portgroup"""

    address = wsme.wsattr(types.macaddress, mandatory=True)
    """MAC Address for this portgroup"""

    extra = {wtypes.text: types.jsontype}
    """This portgroups meta data"""

    node_uuid = wsme.wsproperty(types.uuid, _get_node_uuid, _set_node_uuid,
                                mandatory=True)
    """The UUID of the node this portgroup belongs to"""

    name = wsme.wsattr(wtypes.text)
    """The logical name for this portgroup"""

    links = wsme.wsattr([link.Link], readonly=True)
    """A list containing a self link and associated portgroup links"""

    def __init__(self, **kwargs):
        self.fields = []
        fields = list(objects.Portgroup.fields)
        # NOTE: node_uuid is not part of objects.Portgroup.fields
        #       because it's an API-only attribute
        fields.append('node_uuid')
        for field in fields:
            # Skip fields we do not expose.
            if not hasattr(self, field):
                continue
            self.fields.append(field)
            setattr(self, field, kwargs.get(field, wtypes.Unset))

        # NOTE: node_id is an attribute created on-the-fly
        # by _set_node_uuid(), it needs to be present in the fields so
        # that as_dict() will contain node_id field when converting it
        # before saving it in the database.
        self.fields.append('node_id')
        setattr(self, 'node_uuid', kwargs.get('node_id', wtypes.Unset))

    @staticmethod
    def _convert_with_links(portgroup, url, fields=None):
        # NOTE(lucasagomes): Since we are able to return a specified set of
        # fields the "uuid" can be unset, so we need to save it in another
        # variable to use when building the links
        portgroup_uuid = portgroup.uuid
        if fields is not None:
            portgroup.unset_fields_except(fields)

        # never expose the node_id attribute
        portgroup.node_id = wtypes.Unset

        portgroup.links = [link.Link.make_link('self', url,
                                               'portgroups', portgroup_uuid),
                           link.Link.make_link('bookmark', url,
                                               'portgroups', portgroup_uuid,
                                               bookmark=True)
                           ]
        return portgroup

    @classmethod
    def convert_with_links(cls, rpc_portgroup, fields=None):
        portgroup = Portgroup(**rpc_portgroup.as_dict())

        if fields is not None:
            api_utils.check_for_invalid_fields(fields, portgroup.as_dict())

        return cls._convert_with_links(portgroup, pecan.request.host_url,
                                       fields=fields)

    @classmethod
    def sample(cls, expand=True):
        sample = cls(uuid='27e3153e-d5bf-4b7e-b517-fb518e17f34c',
                     address='fe:54:00:77:07:d9',
                     extra={'foo': 'bar'},
                     created_at=datetime.datetime.utcnow(),
                     updated_at=datetime.datetime.utcnow())
        # NOTE(lucasagomes): node_uuid getter() method look at the
        # _node_uuid variable
        sample._node_uuid = '7ae81bb3-dec3-4289-8d6c-da80bd8001ae'
        fields = None if expand else _DEFAULT_RETURN_FIELDS
        return cls._convert_with_links(sample, 'http://localhost:6385',
                                       fields=fields)


class PortgroupCollection(collection.Collection):
    """API representation of a collection of portgroups."""

    portgroups = [Portgroup]
    """A list containing portgroup objects"""

    def __init__(self, **kwargs):
        self._type = 'portgroups'

    @staticmethod
    def convert_with_links(rpc_portgroups, limit, url=None, fields=None,
                           **kwargs):
        collection = PortgroupCollection()
        collection.portgroups = [Portgroup.convert_with_links(p, fields=fields)
                                 for p in rpc_portgroups]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection

    @classmethod
    def sample(cls):
        sample = cls()
        sample.portgroups = [Portgroup.sample(expand=False)]
        return sample


class PortgroupsController(rest.RestController):
    """REST controller for portgroups."""

    from_nodes = False
    """A flag to indicate if the requests to this controller are coming
    from the top-level resource Nodes."""

    _custom_actions = {
        'detail': ['GET'],
    }

    invalid_sort_key_list = ['extra']

    def _get_portgroups_collection(self, node_ident, address,
                                   marker, limit, sort_key, sort_dir,
                                   resource_url=None, fields=None):
        if self.from_nodes and not node_ident:
            raise exception.MissingParameterValue(
                _("Node identifier not specified."))

        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.Portgroup.get_by_uuid(pecan.request.context,
                                                       marker)

        if sort_key in self.invalid_sort_key_list:
            raise exception.InvalidParameterValue(
                _("The sort_key value %(key)s is an invalid field for "
                  "sorting") % {'key': sort_key})

        if node_ident:
            # FIXME: Since all we need is the node ID, we can
            #        make this more efficient by only querying
            #        for that column. This will get cleaned up
            #        as we move to the object interface.
            node = api_utils.get_rpc_node(node_ident)
            portgroups = objects.Portgroup.list_by_node_id(
                pecan.request.context, node.id, limit,
                marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        elif address:
            portgroups = self._get_portgroups_by_address(address)
        else:
            portgroups = objects.Portgroup.list(pecan.request.context, limit,
                                                marker_obj, sort_key=sort_key,
                                                sort_dir=sort_dir)

        return PortgroupCollection.convert_with_links(portgroups, limit,
                                                      url=resource_url,
                                                      fields=fields,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    def _get_portgroups_by_address(self, address):
        """Retrieve a portgroup by its address.

        :param address: MAC address of a portgroup, to get the portgroup
                        which has this MAC address.
        :returns: a list with the portgroup, or an empty list if no portgroup
                  is found.

        """
        try:
            portgroup = objects.Portgroup.get_by_address(pecan.request.context,
                                                         address)
            return [portgroup]
        except exception.PortgroupNotFound:
            return []

    @expose.expose(PortgroupCollection, types.uuid_or_name, types.uuid,
                   types.macaddress, types.uuid, int,
                   wtypes.text, wtypes.text, types.listtype)
    def get_all(self, node=None, node_uuid=None, address=None, marker=None,
                limit=None, sort_key='id', sort_dir='asc', fields=None):
        """Retrieve a list of portgroups.

        Note that the 'node_uuid' interface is deprecated in favour
        of the 'node' interface

        :param node: UUID or name of a node, to get only portgroups for that
                     node.
        :param node_uuid: UUID of a node, to get only portgroups for that
                           node.
        :param address: MAC address of a portgroup, to get the portgroup which
                        has this MAC address.
        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        :param fields: Optional, a list with a specified set of fields
                       of the resource to be returned.
        """
        api_utils.check_allow_specify_fields(fields)
        if fields is None:
            fields = _DEFAULT_RETURN_FIELDS

        if not node_uuid and node:
            # We're invoking this interface using positional notation, or
            # explicitly using 'node'.  Try and determine which one.
            # Make sure only one interface, node or node_uuid is used
            if (not api_utils.allow_node_logical_names() and
                not uuidutils.is_uuid_like(node)):
                raise exception.NotAcceptable()

        return self._get_portgroups_collection(node_uuid or node, address,
                                               marker, limit,
                                               sort_key, sort_dir,
                                               fields=fields)

    @expose.expose(PortgroupCollection, types.uuid_or_name, types.uuid,
                   types.macaddress, types.uuid, int, wtypes.text, wtypes.text)
    def detail(self, node=None, node_uuid=None, address=None, marker=None,
               limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of portgroups with detail.

        Note that the 'node_uuid' interface is deprecated in favour
        of the 'node' interface

        :param node: UUID or name of a node, to get only portgroups for that
                     node.
        :param node_uuid: UUID of a node, to get only portgroups for that
                          node.
        :param address: MAC address of a portgroup, to get the portgroup which
                        has this MAC address.
        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        """
        if not node_uuid and node:
            # We're invoking this interface using positional notation, or
            # explicitly using 'node'.  Try and determine which one.
            # Make sure only one interface, node or node_uuid is used
            if (not api_utils.allow_node_logical_names() and
                not uuidutils.is_uuid_like(node)):
                raise exception.NotAcceptable()

        # NOTE: /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "portgroups":
            raise exception.HTTPNotFound

        resource_url = '/'.join(['portgroups', 'detail'])
        return self._get_portgroups_collection(node_uuid or node, address,
                                               marker, limit, sort_key,
                                               sort_dir, resource_url)

    @expose.expose(Portgroup, types.uuid, types.listtype)
    def get_one(self, portgroup_uuid, fields=None):
        """Retrieve information about the given portgroup.

        :param portgroup_uuid: UUID of a port.
        :param fields: Optional, a list with a specified set of fields
                       of the resource to be returned.
        """
        if self.from_nodes:
            raise exception.OperationNotPermitted

        api_utils.check_allow_specify_fields(fields)

        rpc_portgroup = objects.Portgroup.get_by_uuid(pecan.request.context,
                                                      portgroup_uuid)
        return Portgroup.convert_with_links(rpc_portgroup, fields=fields)

    @expose.expose(Portgroup, body=Portgroup, status_code=201)
    def post(self, portgroup):
        """Create a new portgroup.

        :param portgroup: a portgroup within the request body.
        """
        if self.from_nodes:
            raise exception.OperationNotPermitted

        new_portgroup = objects.Portgroup(pecan.request.context,
                                          **portgroup.as_dict())
        new_portgroup.create()
        # Set the HTTP Location Header
        pecan.response.location = link.build_url('portgroups',
                                                 new_portgroup.uuid)
        return Portgroup.convert_with_links(new_portgroup)

    @wsme.validate(types.uuid, [PortgroupPatchType])
    @expose.expose(Portgroup, types.uuid, body=[PortgroupPatchType])
    def patch(self, portgroup_uuid, patch):
        """Update an existing portgroup.

        :param portgroup_uuid: UUID of a portgroup.
        :param patch: a json PATCH document to apply to this portgroup.
        """
        if self.from_nodes:
            raise exception.OperationNotPermitted

        rpc_portgroup = objects.Portgroup.get_by_uuid(pecan.request.context,
                                                      portgroup_uuid)
        try:
            portgroup_dict = rpc_portgroup.as_dict()
            # NOTE:
            # 1) Remove node_id because it's an internal value and
            #    not present in the API object
            # 2) Add node_uuid
            portgroup_dict['node_uuid'] = portgroup_dict.pop('node_id', None)
            portgroup = Portgroup(**api_utils.apply_jsonpatch(portgroup_dict,
                                                              patch))
        except api_utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.Portgroup.fields:
            try:
                patch_val = getattr(portgroup, field)
            except AttributeError:
                # Ignore fields that aren't exposed in the API
                continue
            if patch_val == wtypes.Unset:
                patch_val = None
            if rpc_portgroup[field] != patch_val:
                rpc_portgroup[field] = patch_val

        rpc_node = objects.Node.get_by_id(pecan.request.context,
                                          rpc_portgroup.node_id)
        topic = pecan.request.rpcapi.get_topic_for(rpc_node)

        new_portgroup = pecan.request.rpcapi.update_portgroup(
            pecan.request.context, rpc_portgroup, topic)

        return Portgroup.convert_with_links(new_portgroup)

    @expose.expose(None, types.uuid, status_code=204)
    def delete(self, portgroup_uuid):
        """Delete a portgroup.

        :param portgroup_uuid: UUID of a portgroup.
        """
        if self.from_nodes:
            raise exception.OperationNotPermitted
        rpc_portgroup = objects.Portgroup.get_by_uuid(pecan.request.context,
                                                      portgroup_uuid)
        rpc_node = objects.Node.get_by_id(pecan.request.context,
                                          rpc_portgroup.node_id)
        topic = pecan.request.rpcapi.get_topic_for(rpc_node)
        pecan.request.rpcapi.destroy_portgroup(pecan.request.context,
                                               rpc_portgroup, topic)
