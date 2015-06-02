from n6sdk.pyramid_commons import (
    AnonymousAuthenticationPolicy,
    ConfigHelper,
    HttpResource,
)

from necoma.matatabi import *

matatabi_data_spec = MatatabiDataSpec()

RESOURCES = [
    HttpResource(
        resource_id='/matatabi',
        url_pattern='/matatabi.{renderer}',
        renderers=('json', 'sjson'),

        # an *instance* of our data specification class
        data_spec=matatabi_data_spec,

        # the *name* of a DataBackendAPI's data query method
        data_backend_api_method='select_records',
    ),
]


def main(global_config, **settings):
    helper = ConfigHelper(
        # a dict of settings from the *.ini file
        settings=settings,

        # a data backend API *class*
        data_backend_api_class=MatatabiDataBackendApi,

        # an *instance* of an authentication policy class
        authentication_policy=AnonymousAuthenticationPolicy(),

        # the list of HTTP resources defined above
        resources=RESOURCES,
    )
    return helper.make_wsgi_app()
