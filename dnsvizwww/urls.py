#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.  This file (or some portion thereof) is a
# derivative work authored by VeriSign, Inc., and created in 2014, based on
# code originally developed at Sandia National Laboratories.
# Created by Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Sandia Corporation. Under the terms of Contract
# DE-AC04-94AL85000 with Sandia Corporation, the U.S. Government retains
# certain rights in this software.
# 
# Copyright 2014-2015 VeriSign, Inc.
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

from django.conf.urls import url
from django.contrib.staticfiles.urls import staticfiles_urlpatterns
from django.views.decorators.cache import never_cache
from django.views.generic.base import TemplateView, RedirectView

from dnsvizwww import views

_encoded_slash = r'S'
_wildcard_label = r'\*'
_dns_label_first_char = r'[_a-z0-9]'
_dns_label_middle_char = r'[_a-z0-9-]|(%s)' % _encoded_slash
_dns_label_last_char = _dns_label_first_char
_dns_label = r'((%s)(%s)*(%s))|(%s)|(%s)' % \
        (_dns_label_first_char, _dns_label_middle_char, _dns_label_last_char,
            _dns_label_first_char, _wildcard_label)
dns_name = r'(%s)(\.(%s))*' % (_dns_label, _dns_label)

timestamp = r'[a-zA-Z0-9-_]{6}'

ip_chars = r'[0-9a-fA-F:\.]{,39}'

urlpatterns = [
        url(r'^$', TemplateView.as_view(template_name='main.html')),

        url(r'^search/$', views.domain_search),
        url(r'^d/$', RedirectView.as_view(url='/')),

        url(r'^d/(?P<name>%s)/$' % dns_name, never_cache(views.DomainNameDetailView.as_view())),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>dnssec/)$' % dns_name, never_cache(views.DomainNameDNSSECPageView.as_view())),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>servers/)$' % dns_name, never_cache(views.DomainNameServersView.as_view())),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>responses/)$' % dns_name, never_cache(views.DomainNameResponsesView.as_view())),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>dnssec/)(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % dns_name, never_cache(views.DomainNameDNSSECGraphView.as_view())),
        url(r'^d/(?P<name>%s)/(?P<url_subdir>REST/)(?P<rest_dir>(raw|processed|meta)/)$' % dns_name, never_cache(views.DomainNameRESTView.as_view())),

        url(r'^d/(?P<name>%s)/(?P<url_subdir>analyze/)$' % dns_name, never_cache(views.analyze)),

        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/$' % (dns_name, timestamp), views.DomainNameDetailView.as_view()),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>dnssec/)$' % (dns_name, timestamp), views.DomainNameDNSSECPageView.as_view()),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>servers/)$' % (dns_name, timestamp), views.DomainNameServersView.as_view()),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>responses/)$' % (dns_name, timestamp), views.DomainNameResponsesView.as_view()),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>dnssec/)(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % (dns_name, timestamp), views.DomainNameDNSSECGraphView.as_view()),
        url(r'^d/(?P<name>%s)/(?P<timestamp>%s)/(?P<url_subdir>REST/)(?P<rest_dir>(raw|processed|meta)/)$' % (dns_name, timestamp), views.DomainNameRESTView.as_view()),

        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/$' % dns_name, views.DomainNameDetailGroupView.as_view()),
        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/(?P<url_subdir>dnssec/)$' % dns_name, views.DomainNameDNSSECPageGroupView.as_view()),
        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/(?P<url_subdir>servers/)$' % dns_name, views.DomainNameServersGroupView.as_view()),
        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/(?P<url_subdir>responses/)$' % dns_name, views.DomainNameResponsesGroupView.as_view()),
        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/(?P<url_subdir>dnssec/)(?P<url_file>auth_graph)\.(?P<format>png|jpg|svg|dot|js)$' % dns_name, views.DomainNameDNSSECGraphGroupView.as_view()),
        url(r'^d/(?P<name>%s)/(r|e)/(?P<group_id>\d+)/(?P<url_subdir>REST/)(?P<rest_dir>(raw|processed|meta)/)$' % dns_name, views.DomainNameRESTGroupView.as_view()),

        #url(r'^util/dnslookingglass.jnlp$', views.lookingGlassJNLP),

        url(r'^contact/$', views.contact),
        url(r'^message_submitted/$', TemplateView.as_view(template_name='message_submitted.html')),

        url(r'^doc/$', TemplateView.as_view(template_name='doc.html')),
        url(r'^doc/faq/$', TemplateView.as_view(template_name='faq.html')),
        url(r'^doc/dnssec/$', TemplateView.as_view(template_name='dnssec_legend.html')),
]

urlpatterns += staticfiles_urlpatterns()
