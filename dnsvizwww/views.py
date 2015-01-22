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
import collections
import datetime
import json
import logging
import os
import re

import dns.name, dns.rdatatype

from django.conf import settings
from django.http import HttpResponse, StreamingHttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt

from dnsviz.config import DNSVIZ_SHARE_PATH
import dnsviz.format as fmt
import dnsviz.status as Status
import dnsviz.response as Response
from dnsviz.util import get_trusted_keys
from django.views.decorators.cache import cache_page
from dnsviz.viz.dnssec import DNSAuthGraph

from dnsvizwww.analysis import Analyst, OfflineDomainNameAnalysis
from dnsvizwww import log
from dnsvizwww import util

import urls
from forms import *
from notices import get_notices, notices_to_javascript

def reset_query_string(request):
    return HttpResponseRedirect(request.path)

def domain_view(request, name, timestamp=None, url_subdir='', **kwargs):
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
        name_obj = OfflineDomainNameAnalysis.objects.get(name, date)

    if not url_subdir:
        url_subdir = ''

    if name_obj is None:
        subdir_path_length = len(url_subdir.split('/'))-1
        if timestamp is None:
            return HttpResponseRedirect(('../'*subdir_path_length)+'analyze/')
        else:
            raise Http404

    if date_form is None:
        date_form = domain_date_search_form(name)(initial={'date': fmt.datetime_to_str(name_obj.analysis_end)[:10] })

    if not url_subdir:
        return detail_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'dnssec/':
        return dnssec_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'responses/':
        return responses_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'servers/':
        return servers_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    elif url_subdir == 'REST/':
        return rest_view(request, name_obj, timestamp, url_subdir, date_form, **kwargs)
    #XXX
    else:
        raise Http404

def detail_view(request, name_obj, timestamp, url_subdir, date_form):
    return HttpResponseRedirect('dnssec/')

def _graph_dane_related_name(G, name_obj, trusted_keys, rdtypes, denial_of_existence):
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

def _graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence):
    G = DNSAuthGraph()

    if not name_obj.zone.get_auth_or_designated_servers():
        G.graph_zone_auth(name_obj.zone, False)

    _graph_dane_related_name(G, name_obj, trusted_keys, rdtypes, denial_of_existence)

    # get all the names/types associated with the analysis
    qnamestypes = set(filter(lambda x: x[1] not in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV), name_obj.queries))

    # if denial of existence was not specified, don't include the
    # explicit nxdomain/nxrrset queries
    if not denial_of_existence:
        qnamestypes.difference_update(
                [(name_obj.nxdomain_name, name_obj.nxdomain_rdtype),
                    (name_obj.nxrrset_name, name_obj.nxrrset_rdtype)])

    # queries with positive responses or error responses (yxrrset)
    yxnamestypes = name_obj.yxrrset.intersection(qnamestypes)
    errnamestypes = set(filter(lambda x: name_obj.queries[x].error_info, qnamestypes))

    # if no rrsets exist, and there were no response errors, then force denial_of_existence 
    if not yxnamestypes and not errnamestypes:
        denial_of_existence = True

    for qname, rdtype in qnamestypes:
        if rdtype not in rdtypes:
            continue
        if not denial_of_existence:
            has_pos_response = qname in name_obj.yxdomain and (qname, rdtype) in name_obj.yxrrset
            has_cname_response = (qname, dns.rdatatype.CNAME) in name_obj.yxrrset
            has_neg_response = bool(filter(lambda x: x.qname == qname and x.rdtype == rdtype, name_obj.nodata_status) or \
                    filter(lambda x: x.qname == qname and x.rdtype == rdtype, name_obj.nxdomain_status))
            # If there is no positive response, but there is a negative
            # response or CNAME response for the qname/qtype in question, then
            # don't show it.  This way the default display (i.e., when
            # denial_of_existence is
            if not has_pos_response and (has_neg_response or has_cname_response):
                continue

        G.graph_rrset_auth(name_obj, qname, rdtype)
    return G

def dnssec_view(request, name_obj, timestamp, url_subdir, date_form):
    options_form, values = get_dnssec_options_form_data(request.GET)
    rdtypes = set(values['rr'])
    denial_of_existence = values['doe']
    dnssec_algorithms = set(values['a'])
    ds_algorithms = set(values['ds'])
    trusted_keys_explicit = values['tk']
    trusted_zones = values['ta']
    redundant_edges = values['red']

    trusted_keys = trusted_keys_explicit + trusted_zones

    use_js = 'no_js' not in request.GET

    G = DNSAuthGraph()
        
    if use_js:
        notices = {}
    else:
        name_obj.retrieve_all()
        name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)
        G = _graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence)
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

def dnssec_info(request, name, timestamp=None, url_subdir=None, url_file=None, format=None, **kwargs):
    name = util.name_url_decode(name)
    if timestamp is None:
        name_obj = OfflineDomainNameAnalysis.objects.latest(name)
    else:
        date = util.datetime_url_decode(timestamp)
        name_obj = OfflineDomainNameAnalysis.objects.get(name, date)

    if name_obj is None:
        raise Http404

    options_form, values = get_dnssec_options_form_data(request.GET)

    rdtypes = set(values['rr'])
    denial_of_existence = values['doe']
    dnssec_algorithms = set(values['a'])
    ds_algorithms = set(values['ds'])
    trusted_keys_explicit = values['tk']
    trusted_zones = values['ta']
    redundant_edges = values['red']

    trusted_keys = trusted_keys_explicit + trusted_zones

    name_obj.retrieve_all()
    name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)
    G = _graph_name(name_obj, trusted_keys, rdtypes, denial_of_existence)
    G.add_trust(trusted_keys, supported_algs=dnssec_algorithms)
    G.remove_extra_edges(redundant_edges)

    if url_file == 'auth_graph':
        return dnssec_auth_graph(request, name_obj, G, format)
    else:
        raise Http404

def dnssec_auth_graph(request, name_obj, G, format):
    img = G.draw(format)
    #XXX currently, graphviz only supports local files, so the
    #XXX following two lines are necessary
    if format not in ('png', 'jpg'):
        img = img.replace(os.path.join(DNSVIZ_SHARE_PATH, 'icons'), os.path.join(settings.STATIC_URL, 'images', 'dnssec_legend'))
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

def responses_view(request, name_obj, timestamp, url_subdir, date_form):
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
            rrset_list = list(rrset_info.rrset)
            rrset_list.sort(cmp=Response._rr_cmp)
            for rr in rrset_list:
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

        if pos_matrix:
            response_consistency.append(('Responses for %s/%s' % (fmt.humanize_name(name, True), dns.rdatatype.to_text(rdtype)), slist, pos_matrix))

    return render_to_response('responses.html',
            { 'name_obj': name_obj, 'timestamp': timestamp, 'url_subdir': url_subdir, 'title': name_obj,
                'date_form': date_form, 'response_consistency': response_consistency },
            context_instance=RequestContext(request))

def servers_view(request, name_obj, timestamp, url_subdir, date_form):
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
            if zone_obj.delegation_status == Status.DELEGATION_ERROR_NO_NS_IN_PARENT:
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

def rest_view(request, name_obj, timestamp, url_subdir, date_form, rest_dir=None):
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
    if rest_dir == 'analysis/':
        name_obj.populate_status(trusted_keys)
        name_obj.serialize_status(d, loglevel=loglevel)
    elif rest_dir == 'raw/':
        name_obj.serialize(d)
    else:
        raise Http404

    return HttpResponse(json.dumps(d, **kwargs), content_type='application/json')

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
    if name_re.match(name) is None:
        name_valid = False

    if not name_valid:
        return render_to_response('search.html',
                { 'domain_name': name, 'title': 'Search' },
                context_instance=RequestContext(request))

    return HttpResponseRedirect('../d/%s/' % name)

@csrf_exempt
def analyze(request, name, url_subdir=None):
    name = util.name_url_decode(name)
    name_obj = OfflineDomainNameAnalysis.objects.latest(name)

    if not url_subdir:
        url_subdir = ''

    if name_obj is None:
        name_obj = OfflineDomainNameAnalysis(name)
        form_class = DomainNameAnalysisInitialForm
    else:
        form_class = DomainNameAnalysisForm

    error_msg = None
    if request.POST:
        force_ancestry = False
        if request.POST:
            analyze_form = form_class(request.POST)
            if analyze_form.is_valid():
                if analyze_form.cleaned_data['analysis_depth'] == 2:
                    force_ancestry = True
        else:
            analyze_form = form_class()

        request_logger = logging.getLogger('django.request')

        start_time = datetime.datetime.now(fmt.utc).replace(microsecond=0)
        if request.is_ajax():
            analysis_logger = log.IsolatedLogger(logging.DEBUG, request_logger, 'Error analyzing %s' % name_obj)
            a = Analyst(name_obj.name, dlv_domain=dns.name.from_text('dlv.isc.org'), logger=analysis_logger.logger, start_time=start_time, force_ancestry=force_ancestry)
            a.analyze_async(analysis_logger.success_callback, analysis_logger.exc_callback)
            #TODO set alarm here for too long waits
            return StreamingHttpResponse(analysis_logger.handler)
        else:
            a = Analyst(name_obj.name, dlv_domain=dns.name.from_text('dlv.isc.org'), start_time=start_time, force_ancestry=force_ancestry)
            try:
                a.analyze()
                return HttpResponseRedirect('../')
            except:
                request_logger.exception('Error analyzing %s' % name_obj)
                error_msg = u'There was an error analyzing %s.  We\'ve been notified of the problem and will look into fixing it.  Please try again later.' % name_obj

    return render_to_response('analyze.html',
            { 'name_obj': name_obj, 'url_subdir': url_subdir, 'title': name_obj,
                'error_msg': error_msg, 'analyze_form': form_class() },
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
