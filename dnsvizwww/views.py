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

from cgi import escape
import codecs
import collections
import datetime
import hashlib
import json
import logging
import os
import re
import tempfile
import urllib

import dns.name, dns.rdataclass, dns.rdatatype, dns.rdtypes.ANY.NS, dns.rdtypes.IN.A, dns.rdtypes.IN.AAAA, dns.rrset

from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import View

from dnsviz.analysis import status as Status, Analyst as _Analyst, OfflineDomainNameAnalysis as _OfflineDomainNameAnalysis, DNS_RAW_VERSION
from dnsviz.analysis.online import WILDCARD_EXPLICIT_DELEGATION, ANALYSIS_TYPE_AUTHORITATIVE, ANALYSIS_TYPE_RECURSIVE
from dnsviz.config import DNSVIZ_SHARE_PATH
import dnsviz.format as fmt
import dnsviz.response as Response
from dnsviz import transport
from dnsviz.util import get_trusted_keys
from django.views.decorators.cache import cache_page
from dnsviz.viz.dnssec import DNSAuthGraph

from dnsvizwww.analysis import Analyst, RecursiveAnalyst, OfflineDomainNameAnalysis
from dnsvizwww import log
from dnsvizwww import util

import urls
from forms import *
from notices import get_notices, notices_to_javascript

class DynamicAnalyst(_Analyst):
    analysis_model = _OfflineDomainNameAnalysis

def reset_query_string(request):
    return HttpResponseRedirect(request.path)

class DomainNameView(View):
    def get(self, request, name, timestamp=None, url_subdir='', **kwargs):
        if 'reset_query' in request.GET:
            return reset_query_string(request)

        name = util.name_url_decode(name)
        if 'date_search' in request.GET:
            date_form = domain_date_search_form(name)(request.GET)
            if date_form.is_valid():
                return HttpResponseRedirect('%s%s' % (date_form.name_obj.base_url_with_timestamp(), url_subdir))
        else:
            date_form = None

        if timestamp is None:
            name_obj = OfflineDomainNameAnalysis.objects.latest(name)
        else:
            date = util.datetime_url_decode(timestamp)
            name_obj = OfflineDomainNameAnalysis.objects.get_by_date(name, date)

        if name_obj is None:
            subdir_path_length = len(url_subdir.split('/'))-1
            if timestamp is None:
                return HttpResponseRedirect(('../'*subdir_path_length)+'analyze/')
            else:
                raise Http404

        if date_form is None:
            date_form = domain_date_search_form(name)(initial={'date': fmt.datetime_to_str(name_obj.analysis_end)[:10] })

        return self._get(request, name_obj, timestamp, url_subdir, date_form, **kwargs)

    def _get(self, request, name_obj, timestamp, url_subdir, date_form, **kwargs):
        raise Http404

class DomainNameSimpleView(View):
    def get(self, request, name, timestamp=None, url_subdir='', **kwargs):
        name = util.name_url_decode(name)

        if timestamp is None:
            name_obj = OfflineDomainNameAnalysis.objects.latest(name)
        else:
            date = util.datetime_url_decode(timestamp)
            name_obj = OfflineDomainNameAnalysis.objects.get_by_date(name, date)

        if name_obj is None:
            raise Http404

        return self._get(request, name_obj, timestamp, url_subdir, None, **kwargs)

    def _get(self, request, name_obj, timestamp, url_subdir, date_form, **kwargs):
        raise Http404

class DomainNameGroupView(View):
    def get(self, request, name, group_id, url_subdir='', **kwargs):
        if 'reset_query' in request.GET:
            return reset_query_string(request)

        name = util.name_url_decode(name)
        try:
            group = OfflineDomainNameAnalysis.objects.get(pk=int(group_id))
        except OfflineDomainNameAnalysis.DoesNotExist:
            name_obj = None
        else:
            name_obj = OfflineDomainNameAnalysis.objects.get_by_group(name, group)

        if not url_subdir:
            url_subdir = ''

        if name_obj is None:
            raise Http404

        return self._get(request, name_obj, None, url_subdir, None, **kwargs)

    def _get(self, request, name_obj, timestamp, url_subdir, date_form, **kwargs):
        raise Http404

class DomainNameDetailMixin(object):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form):
        return HttpResponseRedirect('dnssec/')

class DomainNameDetailView(DomainNameDetailMixin, DomainNameView):
    pass

class DomainNameDetailGroupView(DomainNameDetailMixin, DomainNameGroupView):
    pass

class DNSSECMixin(object):
    def _graph_dane_related_name(self, G, name_obj, trusted_keys, rdtypes, denial_of_existence):
        # if DANE, then graph the A/AAAA records for the DANE host
        if len(name_obj.name) > 2 and name_obj.name[1] in ('_tcp', '_udp', '_sctp') and \
                (dns.rdatatype.A in rdtypes or dns.rdatatype.AAAA in rdtypes):
            dane_host_obj = name_obj.get_dane_hostname()
            if dane_host_obj is not None:
                dane_host_obj.retrieve_all()
                dane_host_obj.populate_status(trusted_keys)
                for rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
                    if rdtype in rdtypes and (denial_of_existence or (dane_host_obj.name, rdtype) in dane_host_obj.yxrrset):
                        G.graph_rrset_auth(dane_host_obj, dane_host_obj.name, rdtype)

    def _graph_name(self, name_obj, trusted_keys, rdtypes, denial_of_existence):
        G = DNSAuthGraph()

        if not name_obj.zone.get_responsive_auth_or_designated_servers():
            G.graph_zone_auth(name_obj.zone, False)

        self._graph_dane_related_name(G, name_obj, trusted_keys, rdtypes, denial_of_existence)

        # get names/types queried in conjunction with the analysis, other than
        # DNSSEC-related types and those not explicitly requested in the options
        # form.
        qnamestypes = set(filter(lambda x: x[1] not in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV) and x[1] in rdtypes, name_obj.queries))

        # if no qnames/qtypes resulted, it is possible that this is the result of
        # an NXDOMAIN found by querying for the referral_rdtype, which might not have
        # been among the rdtypes explicitly requested for view.
        if not qnamestypes and name_obj.referral_rdtype is not None and name_obj.queries[(name_obj.name, name_obj.referral_rdtype)].is_nxdomain_all():
            qnamestypes.add((name_obj.name, name_obj.referral_rdtype))

        # if denial of existence was not specified, don't include the explicit
        # nxdomain/nxrrset queries
        if not denial_of_existence:
            qnamestypes.difference_update(
                    [(name_obj.nxdomain_name, name_obj.nxdomain_rdtype),
                        (name_obj.nxrrset_name, name_obj.nxrrset_rdtype)])

        # identify queries with positive responses, negative responses or error responses
        pos_namestypes = name_obj.yxrrset.intersection(qnamestypes)
        neg_namestypes = name_obj.nxrrset.intersection(qnamestypes)
        err_namestypes = set(filter(lambda x: name_obj.queries[x].error_info, qnamestypes))

        # if denial_of_existence is selected, then graph everything
        if denial_of_existence:
            qnamestypes_to_graph = qnamestypes
        else:
            # otherwise graph only positive responses and errors not associated
            # with negative responses
            qnamestypes_to_graph = pos_namestypes.union(err_namestypes.difference(neg_namestypes))
            # if nothing matches, then graph everything
            if not qnamestypes_to_graph:
                qnamestypes_to_graph = qnamestypes

        for qname, rdtype in qnamestypes_to_graph:
            G.graph_rrset_auth(name_obj, qname, rdtype)

        return G

class DomainNameDNSSECPageMixin(DNSSECMixin):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form):
        options_form, values = get_dnssec_options_form_data(request.GET)

        use_js = 'no_js' not in request.GET

        if use_js:
            notices = {}
        else:
            rdtypes = set(values['rr'])
            denial_of_existence = values['doe']
            dnssec_algorithms = set(values['a'])
            ds_algorithms = set(values['ds'])
            trusted_keys_explicit = values['tk']
            trusted_zones = values['ta']
            redundant_edges = values['red']

            # disable IANA root keys, if there is an explicit delegation of the root
            # (i.e., ignore root KSK ta setting)
            if name_obj.group is not None and name_obj.group.name == dns.name.root and \
                    name_obj.group.analysis_type == ANALYSIS_TYPE_AUTHORITATIVE and name_obj.group.explicit_delegation:
                trusted_zones = filter(lambda x: x[0] != dns.name.root, trusted_zones)
                if '.' in options_form.fields['ta'].initial:
                    options_form.fields['ta'].initial.remove('.')

            trusted_keys = trusted_keys_explicit + trusted_zones

            G = DNSAuthGraph()

            name_obj.retrieve_all()
            name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)
            G = self._graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence)
            G.add_trust(trusted_keys, supported_algs=dnssec_algorithms)
            #G.remove_extra_edges(redundant_edges)
            notices = get_notices(G.node_info)

        analyzed_name_obj = name_obj
        template = 'dnssec.html'

        return render_to_response(template,
                { 'name_obj': name_obj, 'analyzed_name_obj': analyzed_name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                    'options_form': options_form, 'date_form': date_form,
                    'notices': notices, 'use_js': use_js, 'query_string': request.META['QUERY_STRING'] },
                context_instance=RequestContext(request))

class DomainNameDNSSECPageView(DomainNameDNSSECPageMixin, DomainNameView):
    pass

class DomainNameDNSSECPageGroupView(DomainNameDNSSECPageMixin, DomainNameGroupView):
    pass

class DomainNameDNSSECGraphMixin(DNSSECMixin):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form, url_file=None, format=None, **kwargs):
        options_form, values = get_dnssec_options_form_data(request.GET)

        rdtypes = set(values['rr'])
        denial_of_existence = values['doe']
        dnssec_algorithms = set(values['a'])
        ds_algorithms = set(values['ds'])
        trusted_keys_explicit = values['tk']
        trusted_zones = values['ta']
        redundant_edges = values['red']

        # disable IANA root keys, if there is an explicit delegation of the root
        # (i.e., ignore root KSK ta setting)
        if name_obj.group is not None and name_obj.group.name == dns.name.root and \
                name_obj.group.analysis_type == ANALYSIS_TYPE_AUTHORITATIVE and name_obj.group.explicit_delegation:
            trusted_zones = filter(lambda x: x[0] != dns.name.root, trusted_zones)
            if '.' in options_form.fields['ta'].initial:
                options_form.fields['ta'].initial.remove('.')

        trusted_keys = trusted_keys_explicit + trusted_zones

        name_obj.retrieve_all()
        name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)
        G = self._graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence)
        G.add_trust(trusted_keys, supported_algs=dnssec_algorithms)
        G.remove_extra_edges(redundant_edges)

        if url_file == 'auth_graph':
            return self.dnssec_auth_graph(request, name_obj, G, format)
        else:
            raise Http404

    def dnssec_auth_graph(self, request, name_obj, G, format):
        img = G.draw(format)
        #XXX currently, graphviz only supports local files, so the
        #XXX following two lines are necessary
        if format not in ('png', 'jpg'):
            img = codecs.decode(img, 'utf-8')
            img = img.replace(os.path.join(DNSVIZ_SHARE_PATH, 'icons'), os.path.join(settings.STATIC_URL, 'images', 'dnssec_legend'))
            img = codecs.encode(img, 'utf-8')
        if format == 'dot':
            content_type = 'text/plain'
        elif format == 'jpg':
            content_type = 'image/jpeg'
        elif format == 'png':
            content_type = 'image/png'
        elif format == 'svg':
            content_type = 'image/svg+xml'
        elif format == 'js':
            content_type = 'application/javascript'
            img += notices_to_javascript(get_notices(G.node_info))
        else:
            raise Exception('Unknown file type!')

        response = HttpResponse(img, content_type=content_type)
        if 'download' in request.GET:
            filename_base = name_obj.name.canonicalize().to_text().rstrip('.')
            if not filename_base:
                filename_base = 'root'
            response['Content-Disposition'] = 'attachment; filename=%s-%s.%s' % (filename_base, fmt.datetime_to_str(name_obj.analysis_end).replace(' ', '-'), format)

        if 'err' in request.GET:
            logger = logging.getLogger('django.request')
            logger.error('Graph load errors\n  Path: %s\n  User-agent: %s\n  Referer: %s\n  Remote host: %s\n  Error: %s\n' % \
                    (request.path, request.META.get('HTTP_USER_AGENT', ''), request.META.get('HTTP_REFERER', ''),
                    request.META.get('REMOTE_ADDR', ''), request.GET['err']))

        return response

class DomainNameDNSSECGraphView(DomainNameDNSSECGraphMixin, DomainNameSimpleView):
    pass

class DomainNameDNSSECGraphGroupView(DomainNameDNSSECGraphMixin, DomainNameGroupView):
    pass

class DynamicDomainNameDNSSECPage(View):
    def get(self, request, name, url_subdir='', **kwargs):
        name = util.name_url_decode(name)
        options_form, values = get_dnssec_options_form_data(request.GET)

        name_obj = _OfflineDomainNameAnalysis(name)
        name_obj.analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)
        name_obj.base_url_with_timestamp = '../'
        name_obj.previous = OfflineDomainNameAnalysis.objects.latest(name)
        template = 'dnssec.html'

        analyzed_name_obj = name_obj

        date_form = domain_date_search_form(name)(initial={'date': fmt.datetime_to_str(name_obj.analysis_end)[:10] })

        return render_to_response(template,
                { 'name_obj': name_obj, 'analyzed_name_obj': analyzed_name_obj, 'url_subdir': url_subdir, 'title': name_obj,
                    'options_form': options_form, 'date_form': date_form,
                    'use_js': True, 'query_string': request.META['QUERY_STRING'] },
                context_instance=RequestContext(request))

class DynamicDomainNameDNSSECGraphView(DomainNameDNSSECGraphMixin, View):
    def get(self, request, name, url_subdir='', url_file=None, format=None, **kwargs):
        name = util.name_url_decode(name)
        options_form, values = get_dnssec_options_form_data(request.GET)

        rdtypes = set(values['rr'])
        denial_of_existence = values['doe']
        dnssec_algorithms = set(values['a'])
        ds_algorithms = set(values['ds'])
        trusted_keys_explicit = values['tk']
        trusted_zones = values['ta']
        redundant_edges = values['red']

        trusted_keys = trusted_keys_explicit + trusted_zones

        a = DynamicAnalyst(name)
        name_obj = a.analyze()
        name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)

        G = self._graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence)
        G.add_trust(trusted_keys, supported_algs=dnssec_algorithms)
        G.remove_extra_edges(redundant_edges)

        if url_file == 'auth_graph':
            return self.dnssec_auth_graph(request, name_obj, G, format)
        else:
            raise Http404

class DomainNameResponsesMixin(object):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form):
        options_form, values = get_dnssec_options_form_data({})

        trusted_keys_explicit = values['tk']
        trusted_zones = values['ta']
        trusted_keys = trusted_keys_explicit + trusted_zones

        name_obj.retrieve_all()
        name_obj.populate_status(trusted_keys)

        zone_obj = name_obj.zone

        rdtypes = options_form.cleaned_data['rr']
        qrrsets = [(name_obj, name, rdtype) for (name,rdtype) in name_obj.queries if rdtype in rdtypes]

        # if DANE, then add the A/AAAA records for the DANE host
        if len(name_obj.name) > 2 and name_obj.name[1] in ('_tcp', '_udp', '_sctp'):
            dane_host_obj = name_obj.get_dane_hostname()
            if dane_host_obj is not None:
                dane_host_obj.retrieve_all()
                dane_host_obj.populate_status(trusted_keys)
                if dane_host_obj.zone.name == name_obj.zone.name:
                    if dns.rdatatype.A in rdtypes:
                        qrrsets.append((dane_host_obj, dane_host_obj.name, dns.rdatatype.A))
                    if dns.rdatatype.AAAA in rdtypes:
                        qrrsets.append((dane_host_obj, dane_host_obj.name, dns.rdatatype.AAAA))

        qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.NS))
        qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.DNSKEY))
        if zone_obj.parent is not None:
            qrrsets.insert(0, (zone_obj, zone_obj.name, dns.rdatatype.DS))
            parent_all_auth_servers = zone_obj.parent.get_auth_or_designated_servers()
            parent_server_list = [(ip, zone_obj.parent.get_ns_name_for_ip(ip)[0]) for ip in parent_all_auth_servers]
            parent_server_list.sort(cmp=util.ip_name_cmp)

        all_auth_servers = zone_obj.get_auth_or_designated_servers()
        server_list = [(ip, zone_obj.get_ns_name_for_ip(ip)[0]) for ip in all_auth_servers]
        server_list.sort(cmp=util.ip_name_cmp)
        response_consistency = []

        for my_name_obj, name, rdtype in qrrsets:
            if rdtype == dns.rdatatype.DS:
                slist = parent_server_list
                zone_name = my_name_obj.parent_name()
            else:
                slist = server_list
                zone_name = my_name_obj.zone.name

            pos_matrix = []

            # if all servers are unresponsive, some of the queries enumerated above
            # might not have been asked
            if (name, rdtype) not in my_name_obj.queries:
                continue

            query = my_name_obj.queries[(name, rdtype)]

            servers_pos_responses = set()
            #servers_neg_responses = set()
            servers_error_responses = set()
            for rrset_info in query.answer_info:
                servers_pos_responses.update([s[0] for s in rrset_info.servers_clients])
            #if (name, rdtype) in name_obj.nxdomain_servers_clients:
            #    servers_neg_responses.update([s[0] for s in name_obj.nxdomain_servers_clients[(name, rdtype)]])
            #if (name, rdtype) in name_obj.noanswer_servers_clients:
            #    servers_neg_responses.update([s[0] for s in name_obj.noanswer_servers_clients[(name, rdtype)]])
            #TODO error responses
            #TODO NSEC responses

            for rrset_info in query.answer_info:
                rrset_servers = set([s[0] for s in rrset_info.servers_clients])
                row_grouping = []
                row = []
                row.append((fmt.humanize_name(rrset_info.rrset.name, True), 'not-styled'))
                row.append((rrset_info.rrset.ttl, 'not-styled'))
                row.append((dns.rdatatype.to_text(rrset_info.rrset.rdtype), 'not-styled'))
                rrset_str = ''
                rrset_list = [Response.RdataWrapper(x) for x in rrset_info.rrset]
                rrset_list.sort()
                for rrw in rrset_list:
                    rr = rrw._rdata
                    rr_str = escape(rr.to_text(), quote=True)
                    if rrset_info.rrset.rdtype == dns.rdatatype.DNSKEY:
                        rr_str += ' ; <b>key tag = %d</b>' % Response.DNSKEYMeta.calc_key_tag(rr)
                    rrset_str += '\n<div class="rr">%s</div>' % rr_str
                row.append((rrset_str, 'not-styled'))

                status = ('OK', 'valid')
                row.append(status)

                for server, names in slist:
                    if server in rrset_servers:
                        row.append(('Y', 'valid', ))
                    else:
                        server_queried = False
                        for q in query.queries.values():
                            if server in q.responses:
                                server_queried = True
                        if server_queried:
                            row.append(('', 'not-styled'))
                        else:
                            row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                row_grouping.append(row)

                for rrsig in my_name_obj.rrsig_status[rrset_info]:
                    rrsig_servers = set([s[0] for s in rrset_info.rrsig_info[rrsig].servers_clients])
                    row = []
                    row.append(('', 'not-styled'))
                    row.append((rrset_info.rrsig_info[rrsig].ttl, 'not-styled'))
                    row.append(('RRSIG', 'not-styled'))
                    row.append(('<div class="rr">%s</div>' % rrsig.to_text(), 'not-styled'))

                    try:
                        status = filter(lambda x: x.signature_valid == True, my_name_obj.rrsig_status[rrset_info][rrsig].values())[0]
                    except IndexError:
                        status = my_name_obj.rrsig_status[rrset_info][rrsig].values()[0]

                    style = Status.rrsig_status_mapping[status.validation_status]
                    row.append((Status.rrsig_status_mapping[status.validation_status], style))

                    for server, names in slist:
                        if server in rrsig_servers:
                            row.append(('Y', style))
                        elif server not in rrset_servers:
                            row.append(('', 'not-queried'))
                        else:
                            row.append(('', 'not-styled'))
                    row_grouping.append(row)
                pos_matrix.append(row_grouping)

            row_grouping = []
            row = []
            row.append(('RR count (Answer/Authority/Additional)', 'not-styled', None, None, 4))
            row.append(('OK', 'valid'))
            for server, names in slist:
                server_queried = False
                response = None
                for q in query.queries.values():
                    if server in q.responses:
                        server_queried = True
                        r = q.responses[server].values()[0]
                        if r.is_complete_response():
                            response = r
                            break
                if server_queried and response is not None:
                    answer_ct = 0
                    for i in response.message.answer: answer_ct += len(i)
                    authority_ct = 0
                    for i in response.message.authority: authority_ct += len(i)
                    additional_ct = 0
                    for i in response.message.additional: additional_ct += len(i)
                    if response.message.edns >= 0:
                        additional_ct += 1
                    row.append(('%d/%d/%d' % (answer_ct, authority_ct, additional_ct), 'valid'))
                elif not server_queried:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)
            pos_matrix.append(row_grouping)

            row_grouping = []
            row = []
            row.append(('Response size (bytes)', 'not-styled', None, None, 4))
            row.append(('OK', 'valid'))
            for server, names in slist:
                server_queried = False
                response = None
                for q in query.queries.values():
                    if server in q.responses:
                        server_queried = True
                        r = q.responses[server].values()[0]
                        if r.is_complete_response():
                            response = r
                            break
                if server_queried and response is not None:
                    row.append((response.msg_size, 'valid'))
                elif not server_queried:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)
            pos_matrix.append(row_grouping)

            row_grouping = []
            row = []
            row.append(('Response time (ms)', 'not-styled', None, None, 4))
            row.append(('OK', 'valid'))
            for server, names in slist:
                server_queried = False
                response = None
                for q in query.queries.values():
                    if server in q.responses:
                        server_queried = True
                        r = q.responses[server].values()[0]
                        if r.is_complete_response():
                            response = r
                            break
                if server_queried and response is not None:
                    row.append((int(response.response_time*1e3), 'valid'))
                elif not server_queried:
                    row.append(('', 'not-queried', None, 'Server %s not queried for %s/%s.' % (server, fmt.humanize_name(name), dns.rdatatype.to_text(rdtype))))
                elif server:
                    row.append(('', 'not-styled'))
            row_grouping.append(row)
            pos_matrix.append(row_grouping)

            if pos_matrix:
                response_consistency.append(('Responses for %s/%s' % (fmt.humanize_name(name, True), dns.rdatatype.to_text(rdtype)), slist, pos_matrix))

        return render_to_response('responses.html',
                { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                    'date_form': date_form, 'response_consistency': response_consistency },
                context_instance=RequestContext(request))

class DomainNameResponsesView(DomainNameResponsesMixin, DomainNameView):
    pass

class DomainNameResponsesGroupView(DomainNameResponsesMixin, DomainNameGroupView):
    pass

class DomainNameServersMixin(object):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form):
        options_form, values = get_dnssec_options_form_data({})

        trusted_keys_explicit = values['tk']
        trusted_zones = values['ta']
        trusted_keys = trusted_keys_explicit + trusted_zones

        name_obj.retrieve_all()
        name_obj.populate_status(trusted_keys)

        zone_obj = name_obj.zone

        delegation_matrix = []

        def stealth_cmp(x, y):
            return cmp((y[0], x[1], x[2]), (x[0], y[1], y[2]))

        all_names_list = list(zone_obj.get_ns_names())
        if not all_names_list:
            all_names_list = list(zone_obj.get_auth_ns_ip_mapping())

        all_names_list.sort()

        if zone_obj.parent is not None and not zone_obj.get_auth_or_designated_servers().difference(zone_obj.parent.get_auth_or_designated_servers()):
            no_non_auth_parent_msg = 'All %s servers are also authoritative for %s' % (fmt.humanize_name(zone_obj.parent_name()), fmt.humanize_name(zone_obj.name))
        else:
            no_non_auth_parent_msg = None
        #XXX need something equivalent here for lack of authoritative response for NS
        show_msg = False

        ips_from_child = zone_obj.get_servers_in_child()
        ips_from_parent = zone_obj.get_servers_in_parent()

        for name in all_names_list:
            if zone_obj.parent is not None:
                in_bailiwick = name.is_subdomain(zone_obj.parent_name())
                glue_required = name.is_subdomain(zone_obj.name)
            else:
                in_bailiwick = None
                glue_required = None
            parent_status = { 'in_bailiwick': in_bailiwick, 'glue_required': glue_required }

            row = []
            row.append(fmt.humanize_name(name))
            # (t/f in parent), (glue IPs (or error, if missing)), (real IPs)
            if zone_obj.get_ns_names_in_parent():
                glue_mapping = zone_obj.get_glue_ip_mapping()
                parent_status['in_parent'] = name in glue_mapping
                glue_ips_v4 = filter(lambda x: x.version == 4, glue_mapping.get(name, set()))
                glue_ips_v4.sort()
                glue_ips_v6 = filter(lambda x: x.version == 6, glue_mapping.get(name, set()))
                glue_ips_v6.sort()
            else:
                glue_ips_v4 = []
                glue_ips_v6 = []
                if zone_obj.delegation_status == Status.DELEGATION_STATUS_INCOMPLETE:
                    parent_status['in_parent'] = False
                else:
                    parent_status['in_parent'] = None
                    show_msg = True

            row.append({ 'parent_status': parent_status, 'glue_ips_v4': glue_ips_v4, 'glue_ips_v6': glue_ips_v6 })

            # (t/f in parent), (glue IPs (or error, if missing)), (real IPs)
            names_in_child = zone_obj.get_ns_names_in_child()
            if names_in_child:
                in_child = name in zone_obj.get_ns_names_in_child()
            #XXX
            #elif zone_obj.get_servers_authoritative_for_query(zone_obj.name, dns.rdatatype.NS):
            #    in_child = None
            else:
                in_child = False

            auth_mapping = zone_obj.get_auth_ns_ip_mapping()
            auth_ips_v4 = filter(lambda x: x.version == 4, auth_mapping.get(name, set()))
            auth_ips_v4.sort()
            auth_ips_v6 = filter(lambda x: x.version == 6, auth_mapping.get(name, set()))
            auth_ips_v6.sort()

            row.append({ 'in_child': in_child, 'auth_ips_v4': auth_ips_v4, 'auth_ips_v6': auth_ips_v6 })
            delegation_matrix.append(row)

        stealth_matrix = []
        stealth_rows = []
        for server in zone_obj.get_stealth_servers():
            names, ancestor_zone = zone_obj.get_ns_name_for_ip(server)
            stealth_rows.append((ancestor_zone, names, server))
        stealth_rows.sort(cmp=stealth_cmp)

        for ancestor_zone, names, server in stealth_rows:
            names = map(fmt.humanize_name, names)
            if ancestor_zone is not None:
                ancestor_zone = fmt.humanize_name(ancestor_zone)
            row = (names, ancestor_zone, server)
            stealth_matrix.append(row)

        return render_to_response('servers.html',
                { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                    'date_form': date_form, 'zone_obj': zone_obj, 'delegation': delegation_matrix, 'stealth': stealth_matrix, 'no_non_auth_parent_msg': no_non_auth_parent_msg, 'show_msg': show_msg,
                    'ips_from_parent': ips_from_parent, 'ips_from_child': ips_from_child },
                context_instance=RequestContext(request))

class DomainNameServersView(DomainNameServersMixin, DomainNameView):
    pass

class DomainNameServersGroupView(DomainNameServersMixin, DomainNameGroupView):
    pass

class DomainNameRESTMixin(object):
    def _get(self, request, name_obj, timestamp, url_subdir, date_form, rest_dir=None):
        options_form, values = get_dnssec_options_form_data({})

        trusted_keys_explicit = values['tk']
        trusted_zones = values['ta']
        trusted_keys = trusted_keys_explicit + trusted_zones

        loglevel = request.GET.get('l', '')
        if loglevel == 'error':
            loglevel = logging.ERROR
        elif loglevel == 'warning':
            loglevel = logging.WARNING
        elif loglevel == 'info':
            loglevel = logging.INFO
        else:
            loglevel = logging.DEBUG

        if request.GET.get('p', False):
            kwargs = { 'indent': 4, 'separators': (',', ': ') }
        else:
            kwargs = {}

        name_obj.retrieve_all()

        d = collections.OrderedDict()
        if rest_dir == 'processed/':
            name_obj.populate_status(trusted_keys)
            name_obj.serialize_status(d, loglevel=loglevel)
        elif rest_dir == 'raw/':
            name_obj.serialize(d)
        else:
            raise Http404

        d['_meta._dnsviz.'] = { 'version': DNS_RAW_VERSION, 'names': [name_obj.name.to_text()] }

        return HttpResponse(json.dumps(d, **kwargs), content_type='application/json')

class DomainNameRESTView(DomainNameRESTMixin, DomainNameView):
    pass

class DomainNameRESTGroupView(DomainNameRESTMixin, DomainNameGroupView):
    pass

def domain_search(request):
    name = request.GET.get('d', '')

    url_re = re.compile(r'^\s*(https?://)?(%s)/?\s*$' % urls.dns_name)
    name = url_re.sub(r'\2', name)

    ipv4_re = re.compile(r'^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$')
    if ipv4_re.match(name):
        octets = name.split('.')
        octets.reverse()
        name = '.'.join(octets) + '.in-addr.arpa'
    #TODO similarly detect IPv6 address

    name_valid = True
    try:
        name = dns.name.from_unicode(name)
        name = util.name_url_encode(name)
    except:
        name_valid = False

    # even an valid name might not fit our (current) URL criteria
    name_re = re.compile(r'^(%s)$' % urls.dns_name)
    if name_re.match(urllib.unquote(name)) is None:
        name_valid = False

    if not name_valid:
        return render_to_response('search.html',
                { 'domain_name': name, 'title': 'Search' },
                context_instance=RequestContext(request))

    return HttpResponseRedirect('../d/%s/' % name)

def _set_mappings(domain, mappings):
    explicit_delegation = {}
    if not mappings:
        return explicit_delegation
    explicit_delegation[(domain, dns.rdatatype.NS)] = dns.rrset.RRset(domain, dns.rdataclass.IN, dns.rdatatype.NS)
    for (n, addr) in mappings:
        explicit_delegation[(domain, dns.rdatatype.NS)].add(dns.rdtypes.ANY.NS.NS(dns.rdataclass.IN, dns.rdatatype.NS, n))
        if addr.version == 6:
            a_rdtype = dns.rdatatype.AAAA
            rdtype_cls = dns.rdtypes.IN.AAAA.AAAA
        else:
            a_rdtype = dns.rdatatype.A
            rdtype_cls = dns.rdtypes.IN.A.A
        if (n, a_rdtype) not in explicit_delegation:
            explicit_delegation[(n, a_rdtype)] = dns.rrset.RRset(n, dns.rdataclass.IN, a_rdtype)
        explicit_delegation[(n, a_rdtype)].add(rdtype_cls(dns.rdataclass.IN, a_rdtype, str(addr)))
    return explicit_delegation

@csrf_exempt
def analyze(request, name, url_subdir=None):
    name = util.name_url_decode(name)
    name_obj = OfflineDomainNameAnalysis.objects.latest(name)

    if not url_subdir:
        url_subdir = ''

    if name_obj is None:
        name_obj = OfflineDomainNameAnalysis(name)
    else:
        name_obj.retrieve_ancestry(name_obj.RDTYPES_DELEGATION)
        name_obj.retrieve_related(name_obj.RDTYPES_DELEGATION)
    form_class = domain_analysis_form(name_obj.name)

    error_msg = None
    if request.POST:
        request_logger = logging.getLogger('django.request')
        analysis_logger = log.IsolatedLogger(logging.DEBUG)

        def success_callback(name_obj):
            analysis_logger.logger.info('Success!')
            if name_obj.group is not None:
                next_url = name_obj.base_url_with_timestamp()
            else:
                next_url = '../'
            analysis_logger.handler.queue.put('{"type":"next-location","url":"%s"}\r\n' % escape(next_url))
            analysis_logger.close()

        def exc_callback(exc_info):
            analysis_logger.logger.error('Error analyzing %s' % name_obj)
            request_logger.error('Error analyzing %s' % name_obj, exc_info=exc_info)
            analysis_logger.handler.queue.put('{"type":"next-location","url":"./"}\r\n')
            analysis_logger.close()

        # instantiate a bound form
        analyze_form = form_class(request.POST)
        if analyze_form.is_valid():
            extra_rdtypes = analyze_form.cleaned_data['extra_types']
            if analyze_form.cleaned_data['analysis_type'] == ANALYSIS_TYPE_AUTHORITATIVE:
                analyst_cls = Analyst
                force_ancestor = analyze_form.cleaned_data['force_ancestor']
                explicit_delegations = _set_mappings(force_ancestor, analyze_form.cleaned_data['explicit_delegation'])
            else:
                analyst_cls = RecursiveAnalyst
                force_ancestor = dns.name.root
                explicit_delegations = _set_mappings(WILDCARD_EXPLICIT_DELEGATION, analyze_form.cleaned_data['explicit_delegation'])
            if analyze_form.cleaned_data['perspective'] == 'client':
                sockname = os.path.join(tempfile.gettempdir(), hashlib.sha1(analyze_form.cleaned_data['sockname']).hexdigest())
                th_factories = (transport.DNSQueryTransportHandlerWebSocketFactory(sockname),)
                force_ancestor = dns.name.root
                force_group = True
            elif analyze_form.cleaned_data['perspective'] == 'other':
                th_factories = (transport.DNSQueryTransportHandlerHTTPFactory(analyze_form.cleaned_data['looking_glass']),)
                force_group = False
            else:
                th_factories = None
                force_group = False

            opt = analyze_form.cleaned_data['ecs']
            if opt is not None:
                class Foo(object):
                    edns_options = [opt]
                query_class_mixin = Foo
                force_group = True
            else:
                query_class_mixin = None
            edns_diagnostics = analyze_form.cleaned_data['edns_diagnostics']
            stop_at_explicit = { force_ancestor: True }
            start_time = datetime.datetime.now(fmt.utc).replace(microsecond=0)

            # for ajax requests, analyze asynchronously, using a logger with
            # callbacks and streaming output to the browser.  If there is an
            # error with the analysis, it will be handled by the javascript.
            if request.is_ajax():
                a = analyst_cls(name_obj.name, logger=analysis_logger.logger, query_class_mixin=query_class_mixin, edns_diagnostics=edns_diagnostics, stop_at_explicit=stop_at_explicit, explicit_delegations=explicit_delegations, extra_rdtypes=extra_rdtypes, th_factories=th_factories, start_time=start_time, force_ancestor=force_ancestor, force_group=force_group)
                a.analyze_async(success_callback, exc_callback)
                #TODO set alarm here for too long waits
                return StreamingHttpResponse(analysis_logger.handler)

            # for non-ajax requests analyze synchronously
            else:
                a = analyst_cls(name_obj.name, query_class_mixin=query_class_mixin, edns_diagnostics=edns_diagnostics, stop_at_explicit=stop_at_explicit, explicit_delegations=explicit_delegations, extra_rdtypes=extra_rdtypes, th_factories=th_factories, start_time=start_time, force_ancestor=force_ancestor, force_group=force_group)
                try:
                    name_obj = a.analyze()

                # if there is an error with the analysis, then return the bound form,
                # so the errors will be rendered with the form.
                except:
                    request_logger.exception('Error analyzing %s' % name_obj)
                    error_msg = u'There was an error analyzing %s.  We\'ve been notified of the problem and will look into fixing it.  Please try again later.' % name_obj

                # if there were no errors, then return a redirect
                else:
                    if name_obj.group is not None:
                        next_url = name_obj.base_url_with_timestamp()
                    else:
                        next_url = '../'
                    return HttpResponseRedirect(next_url)

        # if the form contents were invalid in an ajax request, then send a
        # critical-level error, which will prompt the browser to re-issue a
        # POST, so the errors are seen.
        elif request.is_ajax():
            analysis_logger.logger.critical('Form error')
            analysis_logger.close()
            return StreamingHttpResponse(analysis_logger.handler, content_type='application/json')

    # instantiate an unbound form
    else:
        analyze_form = form_class()

    return render_to_response('analyze.html',
            { 'name_obj': name_obj, 'url_subdir': url_subdir, 'title': name_obj,
                'error_msg': error_msg, 'analyze_form': analyze_form },
            context_instance=RequestContext(request))

def contact(request):
    if request.method == 'POST':
        form = ContactForm(request.POST)
        if form.is_valid():
            form.submit_message()
            return HttpResponseRedirect('/message_submitted/')
    else:
        form = ContactForm()

    return render_to_response('contact.html', { 'form': form },
            context_instance=RequestContext(request))
