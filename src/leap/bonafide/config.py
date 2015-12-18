# -*- coding: utf-8 -*-
# config.py
# Copyright (C) 2015 LEAP
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Configuration for a LEAP provider.
"""
import datetime
import json
import os
import sys

from twisted.internet import reactor
from twisted.internet.ssl import ClientContextFactory
from twisted.python import log
from twisted.web.client import Agent, downloadPage

from leap.bonafide._http import httpRequest
from leap.bonafide.provider import Discovery

from leap.common.check import leap_assert
from leap.common.config import get_path_prefix as common_get_path_prefix
from leap.common.files import check_and_fix_urw_only, get_mtime, mkdir_p


APPNAME = "bonafide"
ENDPOINT = "ipc:///tmp/%s.sock" % APPNAME


def get_path_prefix(standalone=False):
    return common_get_path_prefix(standalone)


def get_provider_path(domain):
    """
    Returns relative path for provider config.

    :param domain: the domain to which this providerconfig belongs to.
    :type domain: str
    :returns: the path
    :rtype: str
    """
    # TODO sanitize domain
    leap_assert(domain is not None, 'get_provider_path: We need a domain')
    return os.path.join('providers', domain, 'provider.json')


def get_ca_cert_path(domain):
    # TODO sanitize domain
    leap_assert(domain is not None, 'get_provider_path: We need a domain')
    return os.path.join('providers', domain, 'keys', 'ca', 'cacert.pem')


def get_modification_ts(path):
    """
    Gets modification time of a file.

    :param path: the path to get ts from
    :type path: str
    :returns: modification time
    :rtype: datetime object
    """
    ts = os.path.getmtime(path)
    return datetime.datetime.fromtimestamp(ts)


def update_modification_ts(path):
    """
    Sets modification time of a file to current time.

    :param path: the path to set ts to.
    :type path: str
    :returns: modification time
    :rtype: datetime object
    """
    os.utime(path, None)
    return get_modification_ts(path)


def is_file(path):
    """
    Returns True if the path exists and is a file.
    """
    return os.path.isfile(path)


def is_empty_file(path):
    """
    Returns True if the file at path is empty.
    """
    return os.stat(path).st_size is 0


def make_address(user, provider):
    """
    Return a full identifier for an user, as a email-like
    identifier.

    :param user: the username
    :type user: basestring
    :param provider: the provider domain
    :type provider: basestring
    """
    return '%s@%s' % (user, provider)


def get_username_and_provider(full_id):
    return full_id.split('@')


class WebClientContextFactory(ClientContextFactory):
    def getContext(self, hostname, port):
        return ClientContextFactory.getContext(self)


class ProviderConfig(object):

    # TODO add validation
    # TODO split this class: ProviderBootstrap, ProviderConfig

    def __init__(self, domain, autoconf=True, basedir='~/.config/leap',
                 check_certificate=True):
        self._domain = domain
        self._basedir = os.path.expanduser(basedir)
        self._disco = Discovery('https://%s' % domain)
        self._provider_config = {}

        if not check_certificate:
            # XXX we should do this only for the FIRST provider download.
            # For the rest, we should pass the ca cert to the agent.
            self.contextFactory = WebClientContextFactory()
        else:
            self.contextFactory = None
        self._agent = Agent(reactor, self.contextFactory)

        self._load_provider_config()
        # TODO if loaded, setup _get_api_uri on the DISCOVERY

        if not self.is_configured() and autoconf:
            print 'provider %s not configured: downloading files...' % domain
            self.bootstrap()

    def is_configured(self):
        provider_json = self._get_provider_json_path()
        # XXX check if all the services are there
        if not is_file(provider_json):
            return False
        if not is_file(self._get_ca_cert_path()):
            return False
        return True

    def bootstrap(self):
        provider_json = self._get_provider_json_path()
        if not is_file(provider_json):
            self.download_provider_info()
        if not is_file(self._get_ca_cert_path()):
            self.download_ca_cert()
            self.validate_ca_cert()
        self.download_services_config()

    def has_valid_certificate(self):
        pass

    def download_provider_info(self, replace=False):
        """
        Download the provider.json info from the main domain.
        This SHOULD only be used once with the DOMAIN url.
        """
        # TODO handle pre-seeded providers?
        # or let client handle that? We could move them to bonafide.
        provider_json = self._get_provider_json_path()
        print 'PROVIDER JSON', provider_json
        if is_file(provider_json) and not replace:
            raise RuntimeError('File already exists')

        folders, f = os.path.split(provider_json)
        mkdir_p(folders)

        uri = self._disco.get_provider_info_uri()
        met = self._disco.get_provider_info_method()

        def print_info(res):
            print "RES:", res

        d = downloadPage(uri, provider_json, method=met)
        d.addCallback(print_info)
        d.addCallback(lambda _: self._load_provider_config())
        d.addErrback(log.err)
        return d

    def update_provider_info(self):
        """
        Get more recent copy of provider.json from the api URL.
        """
        pass

    def download_ca_cert(self):
        uri = self._get_ca_cert_uri()
        path = self._get_ca_cert_path()
        mkdir_p(os.path.split(path)[0])
        d = downloadPage(uri, path)
        d.addErrback(log.err)
        return d

    def validate_ca_cert(self):
        # XXX Need to verify fingerprint against the one in provider.json
        expected =  self._get_expected_ca_cert_fingerprint()
        print "EXPECTED FINGERPRINT:", expected

    def _get_expected_ca_cert_fingerprint(self):
        return self._provider_config.get('ca_cert_fingerprint', None)

    def download_services_config(self):
        pass

    def _get_provider_json_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        provider_json = os.path.join(self._basedir, get_provider_path(domain))
        return provider_json

    def _get_ca_cert_path(self):
        domain = self._domain.encode(sys.getfilesystemencoding())
        cert_path = os.path.join(self._basedir, get_ca_cert_path(domain))
        return cert_path

    def _get_ca_cert_uri(self):
        uri = self._provider_config.get('ca_cert_uri', None)
        if uri:
            uri = str(uri)
        return uri

    def _load_provider_config(self):
        path = self._get_provider_json_path()
        if not is_file(path):
            return
        with open(path, 'r') as config:
            self._provider_config = json.load(config)

    def _http_request(self, *args, **kw):
        # XXX pass if-modified-since header
        return httpRequest(self._agent, *args, **kw)

    def _get_api_uri(self):
        pass


if __name__ == '__main__':
    config = ProviderConfig('cdev.bitmask.net', check_certificate=False)
    reactor.run()
