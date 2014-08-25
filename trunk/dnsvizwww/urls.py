#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains certain
# rights in this software.
# 
# DNSViz is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# DNSViz is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

from django.conf.urls import patterns, url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns

_encoded_slash = r'S'
_dns_label_first_char = r'[_a-z0-9]'
_dns_label_middle_char = r'[_a-z0-9-]|(%s)' % _encoded_slash
_dns_label_last_char = _dns_label_first_char
_dns_label = r'((%s)(%s)*(%s))|(%s)' % \
        (_dns_label_first_char, _dns_label_middle_char, _dns_label_last_char,
            _dns_label_first_char)
dns_name = r'(%s)(\.(%s))*' % (_dns_label, _dns_label)

timestamp = r'[a-zA-Z0-9-_]{6}'

ip_chars = r'[0-9a-fA-F:\.]{,39}'

urlpatterns = patterns('dnsvizwww.views',
        url(r'^d/(?P<name>%s)/(?P<url_subdir>(dnssec|responses|servers)/)?$' % dns_name, 'domain_view'),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>dnssec)/(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % dns_name, 'dnssec_info'),

        url(r'^d/(?P<name>%s)/(?P<url_subdir>analyze/)$' % dns_name, 'analyze'),

        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>(dnssec|responses|servers)/)?$' % (dns_name, timestamp), 'domain_view_cacheable'),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>dnssec/)(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % (dns_name, timestamp), 'dnssec_info_cacheable'),

        url(r'^contact/$', 'contact'),
        url(r'^search/$', 'domain_search'),
)
urlpatterns += patterns('django.views.generic.simple',
        url(r'^$', 'direct_to_template', { 'template': 'main.html' } ),
        url(r'^d/$', 'redirect_to', { 'url': '/'}),
        url(r'^doc/$', 'direct_to_template', { 'template': 'doc.html' } ),
        url(r'^doc/faq/$', 'direct_to_template', { 'template': 'faq.html' } ),
        url(r'^doc/dnssec/$', 'direct_to_template', { 'template': 'dnssec_legend.html' } ),
        url(r'^message_submitted/$', 'direct_to_template', { 'template': 'message_submitted.html' } ),
)

urlpatterns += staticfiles_urlpatterns()
