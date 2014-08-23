#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (ctdecci@sandia.gov)
#
# Copyright 2012-2013 Sandia Corporation. Under the terms of Contract
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

import datetime
import json
import logging
import os
import re
import urllib

import dns.name, dns.rdatatype

from django.conf import settings
from django.db import transaction
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import condition

from dnsviz.config import DNSVIZ_SHARE_PATH
import dnsviz.format as fmt
import dnsviz.status as Status
from dnsviz.util import get_trusted_keys
from django.views.decorators.cache import cache_page
from dnsviz.viz.dnssec import DNSAuthGraph

from dnsvizwww.analysis import Analyst, DomainNameAnalysis
from dnsvizwww import log
from dnsvizwww import util

import urls
from forms import *
from notices import get_notices, notices_to_javascript

def domain_last_modified(request, name, *args, **kwargs): 
    timestamp = kwargs.get('timestamp', None)

    if settings.DEBUG:
        return None

    # only use last-modified if a timestamp was specified
    if timestamp is None:
        return None

    name = util.name_url_decode(name)
    date = util.datetime_url_decode(timestamp)
    name_obj = DomainNameAnalysis.objects.get(name, date)
    if name_obj is None:
        return None

    return name_obj.analysis_end

def reset_query_string(request):
    return HttpResponseRedirect(request.path)

@cache_page(600)
#XXX don't cache this page for 2 weeks until prev/next links are figured out
#@cache_page(1209600, cache='page_cache')
#@condition(last_modified_func=domain_last_modified)
def domain_view_cacheable(request, name, timestamp, url_subdir='', **kwargs):
    return domain_view(request, name, timestamp, url_subdir, **kwargs)

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
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

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
    #XXX
    else:
        raise Http404

def detail_view(request, name_obj, timestamp, url_subdir, date_form):
    return HttpResponseRedirect('dnssec/')

def dnssec_view(request, name_obj, timestamp, url_subdir, date_form):
    dlv_name = name_obj.dlv_parent_name()
    options_form, values = get_dnssec_options_form_data(request)
    rdtypes = set(values['rr'])
    show_dlv = dlv_name in values['ta']
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

        G = DNSAuthGraph()
        for qname, rdtype in name_obj.queries:
            if rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
                continue
            if rdtype not in rdtypes:
                continue
            if qname not in name_obj.yxdomain and not denial_of_existence:
                continue
            if (qname,rdtype) not in name_obj.yxrrset and not denial_of_existence:
                continue
            G.graph_rrset_auth(name_obj, qname, rdtype)

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
        name_obj = DomainNameAnalysis.objects.latest(name)
    else:
        date = util.datetime_url_decode(timestamp)
        name_obj = DomainNameAnalysis.objects.get(name, date)

    if name_obj is None:
        raise Http404

    dlv_name = name_obj.dlv_parent_name()
    options_form, values = get_dnssec_options_form_data(request)

    rdtypes = set(values['rr'])
    show_dlv = dlv_name in values['ta']
    denial_of_existence = values['doe']
    dnssec_algorithms = set(values['a'])
    ds_algorithms = set(values['ds'])
    trusted_keys_explicit = values['tk']
    trusted_zones = values['ta']
    redundant_edges = values['red']

    trusted_keys = trusted_keys_explicit + trusted_zones

    name_obj.retrieve_all()
    name_obj.populate_status(trusted_keys, supported_algs=dnssec_algorithms, supported_digest_algs=ds_algorithms)

    G = DNSAuthGraph()
    for qname, rdtype in name_obj.queries:
        if rdtype in (dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.DLV):
            continue
        if rdtype not in rdtypes:
            continue
        if qname not in name_obj.yxdomain and not denial_of_existence:
            continue
        if (qname,rdtype) not in name_obj.yxrrset and not denial_of_existence:
            continue
        G.graph_rrset_auth(name_obj, qname, rdtype)

    G.add_trust(trusted_keys, supported_algs=dnssec_algorithms)
    G.remove_extra_edges(redundant_edges)

    if url_file == 'auth_graph':
        return dnssec_auth_graph(request, name_obj, G, format)
    else:
        raise Http404

@cache_page(600)
@cache_page(1209600, cache='page_cache')
#@condition(last_modified_func=domain_last_modified)
def dnssec_info_cacheable(request, name, timestamp, url_subdir=None, url_file=None, format=None, **kwargs):
    return dnssec_info(request, name, timestamp, url_subdir, url_file, format, **kwargs)

def dnssec_auth_graph(request, name_obj, G, format):
    img = G.draw(format)
    #XXX currently, graphviz only supports local files, so the
    #XXX following two lines are necessary
    if format not in ('png', 'jpg'):
        img = img.replace(os.path.join(DNSVIZ_SHARE_PATH, 'icons'), os.path.join(settings.STATIC_URL, 'images', 'dnssec_legend'))
    if format == 'dot':
        mimetype = 'text/plain'
    elif format == 'jpg':
        mimetype = 'image/jpeg'
    elif format == 'png':
        mimetype = 'image/png'
    elif format == 'svg':
        mimetype = 'image/svg+xml'
    elif format == 'js':
        mimetype = 'application/javascript'
        img += notices_to_javascript(get_notices(G.node_info))
    else:
        raise Exception('Unknown file type!')

    response = HttpResponse(img, mimetype=mimetype)
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
@transaction.autocommit
def analyze(request, name, url_subdir=None):
    name = util.name_url_decode(name)
    name_obj = DomainNameAnalysis.objects.latest(name)

    if not url_subdir:
        url_subdir = ''

    if name_obj is None:
        name_obj = DomainNameAnalysis(name)
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
            return HttpResponse(analysis_logger.handler)
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
