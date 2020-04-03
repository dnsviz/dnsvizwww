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

import datetime
import StringIO
import struct

import dns.edns, dns.exception, dns.flags, dns.message, dns.name, dns.rcode, dns.rdataclass, dns.rdata, dns.rdatatype, dns.resolver, dns.rrset

from django.conf import settings
from django.core.cache import cache as Cache
from django.core.validators import validate_comma_separated_integer_list
from django.db import models
from django.db.models import Q
from django.utils.html import escape
from django.utils.timezone import now, utc

import dnsviz.analysis
import dnsviz.format as fmt
from dnsviz.ipaddr import IPAddr
import dnsviz.query as Query
import dnsviz.resolver as Resolver
import dnsviz.response as Response

import fields
import util

MAX_TTL = 100000000

class DomainNameManager(models.Manager):
    def offset_for_interval(self, interval):
        if interval > 604800:
            #XXX log this
            interval = 604800
        dt_now = datetime.datetime.now(fmt.utc).replace(microsecond=0)
        last_sunday = dt_now.date() - datetime.timedelta(days=dt_now.isoweekday())
        last_sunday_midnight = datetime.datetime(year=last_sunday.year, month=last_sunday.month, day=last_sunday.day, tzinfo=fmt.utc)
        diff = dt_now - last_sunday_midnight
        return diff.total_seconds() % interval

    def names_to_refresh(self, interval, offset, last_offset):
        if offset > last_offset:
            f = Q(refresh_interval=interval, refresh_offset__gt=last_offset, refresh_offset__lte=offset)
        else:
            f = Q(refresh_interval=interval) & ( Q(refresh_offset__gt=last_offset) | Q(refresh_offset__lte=offset) )
        return self.filter(f)

class DomainName(models.Model):

    name = fields.DomainNameField(max_length=2048, primary_key=True)
    analysis_start = models.DateTimeField(blank=True, null=True)
    refresh_interval = models.PositiveIntegerField(blank=True, null=True)
    refresh_offset = models.PositiveIntegerField(blank=True, null=True)

    objects = DomainNameManager()

    def __unicode__(self):
        return fmt.humanize_name(self.name, True)

    def __str__(self):
        return fmt.humanize_name(self.name)

    def latest_analysis(self, date=None):
        return OfflineDomainNameAnalysis.objects.latest(self.name, date)

    def clear_refresh(self):
        if (self.refresh_interval, self.refresh_offset) != (None, None):
            self.refresh_interval = None
            self.refresh_offset = None
            self.save()

    def set_refresh(self, refresh_interval, refresh_offset):
        if (self.refresh_interval, self.refresh_offset) != (refresh_interval, refresh_offset):
            self.refresh_interval = refresh_interval
            self.refresh_offset = refresh_offset
            self.save()

class DNSServer(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __unicode__(self):
        return self.ip_address

class NSMapping(models.Model):
    name = fields.DomainNameField(max_length=2048)
    server = models.ForeignKey(DNSServer)

    class Meta:
        unique_together = (('name', 'server'),)

    def __unicode__(self):
        return '%s -> %s' % (self.name.to_unicode(), self.server)

    def __str__(self):
        return '%s -> %s' % (self.name.to_text(), self.server)

class NSNameNegativeResponse(models.Model):
    name = fields.DomainNameField(max_length=2048, unique=True)

    def __unicode__(self):
        return '%s' % (self.name.to_unicode(), self.server)

    def __str__(self):
        return '%s' % (self.name.to_text(), self.server)

class DomainNameAnalysisManager(models.Manager):
    def get_by_group(self, name, group):
        try:
            return OfflineDomainNameAnalysis.objects.get(name=name, group=group)
        except OfflineDomainNameAnalysis.DoesNotExist:
            return None

    def latest(self, name, date=None, stub=False):
        if date is None:
            key = 'dnsvizwww.models.OnlineDomainNameAnalysis.name.%s.latest.pk' % (util.uuid_for_name(name).hex)
            pk = Cache.get(key)
            if pk is not None:
                util.touch_cache(Cache, key)
                try:
                    obj = self.get(pk=pk)
                except OnlineDomainNameAnalysis.DoesNotExist:
                    # sometimes the cache has a view of it before the database
                    # does
                    pass
                else:
                    if obj.name == name:
                        return obj

        f = Q(name=name, group=None)
        if date is not None:
            f &= Q(analysis_end__lte=date)
        if stub is not None:
            f &= Q(stub=stub)

        try:
            return self.filter(f).latest()
        except self.model.DoesNotExist:
            return None

    def latest_or_group(self, name, date=None, stub=False, group=None):
        if group is not None:
            obj = self.get_by_group(name, group)
            # if there was no object, but there was a date, it might be that
            # this is a name on which another name, with explicit delegation,
            # is dependent, and this name had no explicit delegation.
            if obj is None and date is not None:
                obj = self.latest(name, date=date, stub=stub)
                if obj is not None:
                    # if this object exists, then mark the instance (won't be
                    # saved to database), so further dependencies can be
                    # tracked.
                    obj.group = group
            return obj
        else:
            return self.latest(name, date=date, stub=stub)

    def earliest(self, name, date=None):
        f = Q(name=name, stub=False, group=None)
        if date is not None:
            f &= Q(analysis_end__gte=date)

        try:
            return self.filter(f).order_by('analysis_end')[0]
        except IndexError:
            return None

    def get_by_date(self, name, date):
        try:
            return self.get(name=name, analysis_end=date, stub=False, group=None)
        except self.model.DoesNotExist:
            return None

class OnlineDomainNameAnalysis(dnsviz.analysis.OfflineDomainNameAnalysis, models.Model):
    name = fields.DomainNameField(max_length=2048)
    stub = models.BooleanField(default=False)
    analysis_type = fields.UnsignedSmallIntegerField(default=0)
    explicit_delegation = models.BooleanField(default=False)
    follow_ns = models.BooleanField(default=False)
    follow_mx = models.BooleanField(default=False)

    analysis_start = models.DateTimeField()
    analysis_end = models.DateTimeField(db_index=True)
    dep_analysis_end = models.DateTimeField()

    version = models.PositiveSmallIntegerField(default=26)

    parent_name_db = fields.DomainNameField(max_length=2048, blank=True, null=True)
    dlv_parent_name_db = fields.DomainNameField(max_length=2048, blank=True, null=True)
    nxdomain_ancestor_name_db = fields.DomainNameField(max_length=2048, blank=True, null=True)

    referral_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)
    auth_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)
    cookie_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)
    group = models.ForeignKey('self', blank=True, null=True)

    nxdomain_name = fields.DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxdomain_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)
    nxrrset_name = fields.DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxrrset_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)

    auth_ns_ip_mapping_db = models.ManyToManyField(NSMapping, related_name='s+')
    auth_ns_negative_response_db = models.ManyToManyField(NSNameNegativeResponse, related_name='s+')

    objects = DomainNameAnalysisManager()

    QUERY_CLASS = Query.MultiQuery

    def __init__(self, *args, **kwargs):
        if args:
            if kwargs:
                # since both args and kwargs were supplied this was intended
                # for dnsviz.analysis.OfflineDomainNameAnalysis.__init__()

                # 1. strip arguments that aren't necessary for this
                kwargs.pop('cookie_standin')

                # 2. call
                # dnsviz.analysis.OfflineDomainNameAnalysis.__init__() with
                # arguments that were passed...
                dnsviz.analysis.OfflineDomainNameAnalysis.__init__(self, *args, **kwargs)

                # 3. call models.Model.__init__() with kwargs
                kwargs['name'] = args[0]
                # add stub to kwargs if it was specified as an arg
                if len(args) > 1: kwargs['stub'] = args[1]
                models.Model.__init__(self, **kwargs)

            else:
                # If only args were supplied, then this could match __init__()
                # for either parent.
                if isinstance(args[0], (int, long)):
                    # In the case of models.Model, the first argument would be int,
                    # for the 'id' field.

                    # First call
                    # dnsviz.analysis.OfflineDomainNameAnalysis.__init__() with
                    # at most the first two arguments
                    dnsviz.analysis.OfflineDomainNameAnalysis.__init__(self, *args[1:3])

                    # Now call models.Model.__init__() with arguments that were
                    # passed
                    models.Model.__init__(self, *args)

                else:
                    # Otherwise, this matches
                    # dnsviz.analysis.OfflineDomainNameAnalysis.__init__()

                    # First call
                    # dnsviz.analysis.OfflineDomainNameAnalysis.__init__() with
                    # only the args passed
                    dnsviz.analysis.OfflineDomainNameAnalysis.__init__(self, *args)

                    # Now call models.Model.__init__() with modified kwargs
                    kwargs['name'] = args[0]
                    if len(args) > 1: kwargs['stub'] = args[1]
                    models.Model.__init__(self, **kwargs)

        else:
            # Only kwargs were passed, so this was intended only for models.Model.__init__().

            # First call dnsviz.analysis.OfflineDomainNameAnalysis.__init__()
            # with derived kwargs
            kwargs2 = {}
            if 'stub' in kwargs:
                kwargs2['stub'] = kwargs['stub']
            dnsviz.analysis.OfflineDomainNameAnalysis.__init__(self, kwargs['name'], **kwargs2)

            # Now call
            # models.Model.__init__() with only the kwargs passed
            models.Model.__init__(self, **kwargs)

        self.ttl_mapping = {}
        self.rrsig_expiration_mapping = {}
        self.dnskey_algs_ids = set()

    def __eq__(self, other):
        return self.name == other.name and self.pk == other.pk

    def __unicode__(self):
        return fmt.humanize_name(self.name, True)

    class Meta:
        unique_together = (('name', 'analysis_end'), ('name', 'group'))
        get_latest_by = 'analysis_end'

    def _handle_dnskey_response(self, rrset):
        for dnskey in rrset:
            self.dnssec_algorithms_in_dnskey.add(dnskey.algorithm)
            self.dnskey_algs_ids.add((dnskey.algorithm, Response.DNSKEYMeta.calc_key_tag(dnskey)))

    def _add_glue_ip_mapping(self, response):
        super(OnlineDomainNameAnalysis, self)._add_glue_ip_mapping(response)
        rrset = response.message.find_rrset(response.message.authority, self.name, dns.rdataclass.IN, dns.rdatatype.NS)
        self.ttl_mapping[-dns.rdatatype.NS] = min(self.ttl_mapping.get(-dns.rdatatype.NS, MAX_TTL), rrset.ttl)

    def _process_response_answer_rrset(self, rrset, query, response):
        super(OnlineDomainNameAnalysis, self)._process_response_answer_rrset(rrset, query, response)
        if query.qname in (self.name, self.dlv_name):
            try:
                rrsig_rrset = response.message.find_rrset(response.message.answer, query.qname, query.rdclass, dns.rdatatype.RRSIG, rrset.rdtype)
            except KeyError:
                pass
            else:
                for rrsig in rrsig_rrset:
                    if rrset.rdtype not in self.rrsig_expiration_mapping or rrsig.expiration < self.rrsig_expiration_mapping[rrset.rdtype]:
                        self.rrsig_expiration_mapping[rrset.rdtype] = rrsig.expiration
            self.ttl_mapping[rrset.rdtype] = min(self.ttl_mapping.get(rrset.rdtype, MAX_TTL), rrset.ttl)

    def to_text(self):
        return fmt.humanize_name(self.name)

    def timestamp_url_encoded(self):
        return util.datetime_url_encode(self.analysis_end)

    def updated_ago_str(self):
        updated_ago = datetime.datetime.now(fmt.utc).replace(microsecond=0) - self.analysis_end
        return fmt.humanize_time(updated_ago.seconds, updated_ago.days)

    def base_url(self):
        name = util.name_url_encode(self.name)
        return '/d/%s/' % name

    def base_url_with_timestamp(self):
        if self.group is not None:
            return '%se/%d/' % (self.base_url(), self.group.pk)
        else:
            return '%s%s/' % (self.base_url(), self.timestamp_url_encoded())

    def _get_previous(self, stub=False):
        if not hasattr(self, '_previous') or self._previous is None:
            self._previous = self.__class__.objects.latest(self.name, self.analysis_end - datetime.timedelta(microseconds=1))
        return self._previous

    previous = property(_get_previous)

    def _get_next(self):
        if not hasattr(self, '_next') or self._next is None:
            self._next = self.__class__.objects.earliest(self.name, self.analysis_end + datetime.timedelta(microseconds=1))
        return self._next

    next = property(_get_next)

    def _get_latest(self):
        return self.__class__.objects.latest(self.name)

    latest = property(_get_latest)

    def _get_first(self):
        return self.__class__.objects.earliest(self.name)

    first = property(_get_first)

    def get_dane_hostname(self):
        # If the current name is not DANE-like, then return None
        if not (len(self.name) > 2 and self.name[1] in ('_tcp', '_udp', '_sctp')):
            return None

        if self.analysis_type == dnsviz.analysis.online.ANALYSIS_TYPE_AUTHORITATIVE:
            date = self.dep_analysis_end
        else:
            date = None

        # Find the most recent version of the DANE host name
        dane_host_name = dns.name.Name(self.name.labels[2:])
        dane_host_obj = self.__class__.objects.latest_or_group(dane_host_name, date, group=self.group)

        #XXX not sure if this check (i.e., the rest of this method) is necessary for versions >= 19
        if dane_host_obj is None:
            return None

        # find the most recent version of the zone to which the dane host name pertains
        parent_obj = self.zone
        while not dane_host_name.is_subdomain(parent_obj.name):
            parent_obj = parent_obj.parent

        if dane_host_obj.analysis_end >= parent_obj.analysis_end:
            return dane_host_obj

        return None

    def min_ttl(self, *rdtypes):
        min_ttl = None
        for rdtype in rdtypes:
            if rdtype in self.ttl_mapping:
                if min_ttl is None or self.ttl_mapping[rdtype] < min_ttl:
                    min_ttl = self.ttl_mapping[rdtype]
            else:
                #TODO handle negative TTL
                pass

        return min_ttl

    def has_rrsig_expirations_between(self, start, end, rdtypes):
        for rdtype in rdtypes:
            if rdtype in self.rrsig_expiration_mapping:
                expires = fmt.timestamp_to_datetime(self.rrsig_expiration_mapping[rdtype])
                if start <= expires <= end:
                    return True
                try:
                    ttl = self.ttl_mapping[rdtype]
                except KeyError:
                    continue
                expires_in_cache = expires - datetime.timedelta(seconds=ttl)
                if start <= expires_in_cache <= end:
                    return True
        return False

    def rdtypes_queried(self):
        return set(self.queries_db.filter(qname=self.name).values_list('rdtype', flat=True))

    def save_all(self, group):
        if self.pk is not None:
            return

        # set the parent name, and save this object
        self.parent_name_db = self.parent_name()
        self.dlv_parent_name_db = self.dlv_parent_name()
        self.nxdomain_ancestor_name_db = self.nxdomain_ancestor_name()

        # if the parent belongs to a group, then match it
        if self.parent is not None and self.parent.group is not None:
            self.group = self.parent.group

        self.save()

        # if this analysis was marked as being part of a group, then add that group
        if self.parent is None and group:
            self.group = self

        self.schedule_refresh()

        # now store the name/IP mapping, query/response, and other information
        self.store_related()

        # recursively save the dependent names
        self.save_dependencies()

        # explicit_delegation_group might not be set to its "end" value (it
        # will be eventually set to the name which was the first name in the
        # dependency chain utilizing explicit delegations), but it will at this
        # point be set to something (i.e., not None) if there was an explicit
        # delegation used in this analysis.
        if self.group is None:
            # store the latest pk associated with the name
            Cache.set('dnsvizwww.models.OnlineDomainNameAnalysis.name.%s.latest.pk' % (util.uuid_for_name(self.name).hex), self.pk)

    def _store_related_cache(self, level):
        d = {}
        self._serialize_related(d, False)
        Cache.add('dnsvizwww.models.OnlineDomainNameAnalysis.pk.%d.related.%d' % (self.pk, level), d)

    def store_related(self):
        self._store_related_cache(self.RDTYPES_ALL)

        # add the auth NS to IP mapping
        for name in self._auth_ns_ip_mapping:
            if self._auth_ns_ip_mapping[name]:
                for ip in self._auth_ns_ip_mapping[name]:
                    self.auth_ns_ip_mapping_db.add(NSMapping.objects.get_or_create(name=name, server=DNSServer.objects.get_or_create(ip_address=str(ip))[0])[0])
            else:
                self.auth_ns_negative_response_db.add(NSNameNegativeResponse.objects.get_or_create(name=name)[0])

        # add the queries
        for (qname, rdtype) in self.queries:
            for query in self.queries[(qname, rdtype)].queries.values():
                if query.edns >= 0:
                    edns_max_udp_payload = query.edns_max_udp_payload
                    edns_flags = query.edns_flags
                    edns_options = b''
                    for opt in query.edns_options:
                        s = StringIO.StringIO()
                        opt.to_wire(s)
                        data = s.getvalue()
                        edns_options += struct.pack('!HH', opt.otype, len(data)) + data
                else:
                    edns_max_udp_payload = None
                    edns_flags = None
                    edns_options = None

                query_options = DNSQueryOptions.objects.get_or_create(flags=query.flags, edns_max_udp_payload=edns_max_udp_payload,
                        edns_flags=edns_flags, edns_options=edns_options, tcp_first=query.tcp)[0]

                query_obj = DNSQuery.objects.create(qname=query.qname, rdtype=query.rdtype, rdclass=query.rdclass,
                        options=query_options, analysis=self)

                # add the responses
                for server in query.responses:
                    for client in query.responses[server]:
                        history = []
                        for retry in query.responses[server][client].history:
                            response_time = int(retry.response_time*1000)
                            cause = retry.cause
                            cause_arg = retry.cause_arg
                            action = retry.action
                            action_arg = retry.action_arg
                            if cause_arg is None:
                                cause_arg = -1
                            if action_arg is None:
                                action_arg = -1
                            history.extend([response_time, cause, cause_arg, action, action_arg])
                        history_str = ','.join(map(str, history))
                        response_obj = DNSResponse(query=query_obj, server=str(server), client=str(client),
                                error=query.responses[server][client].error, errno=query.responses[server][client].errno,
                                msg_size=query.responses[server][client].msg_size,
                                response_time=int(query.responses[server][client].response_time*1000),
                                history_serialized=history_str)
                        response_obj.save()
                        response_obj.message = query.responses[server][client].message
                        response_obj.save()

    def retrieve_all(self, cache=None):
        if cache is None:
            cache = {}
        self.retrieve_ancestry(self.RDTYPES_SECURE_DELEGATION, cache=cache)
        self.retrieve_related(self.RDTYPES_ALL)
        self.retrieve_dependencies(cache=cache)

    def _retrieve_related_cache(self, level):
        for i in range(level+1):
            key = 'dnsvizwww.models.OnlineDomainNameAnalysis.pk.%d.related.%d' % (self.pk, i)
            d = Cache.get(key)
            if d is not None:
                util.touch_cache(Cache, key)
                self._deserialize_related(d)
                return True
        return False

    def _retrieve_auth_ns_ip_mapping(self):
        # add the auth NS to IP mapping
        for name, ip in self.auth_ns_ip_mapping_db.values_list('name', 'server__ip_address'):
            self.add_auth_ns_ip_mappings((name, IPAddr(ip)))
        for name in self.auth_ns_negative_response_db.values_list('name', flat=True):
            self.add_auth_ns_ip_mappings((name, None))

    def _retrieve_query(self, query, bailiwick_map, default_bailiwick, cookie_jar_map, default_cookie_jar):
        # this query might have already been imported.  If so, don't
        # re-import.
        if (query.qname, query.rdtype) in self.queries:
            return None
        if query.options.edns_max_udp_payload is not None:
            edns = query.options.edns_flags>>16
            edns_max_udp_payload = query.options.edns_max_udp_payload
            edns_flags = query.options.edns_flags
            edns_options = []
            index = 0
            while index < len(query.options.edns_options):
                (otype, olen) = struct.unpack('!HH', query.options.edns_options[index:index + 4])
                index += 4
                opt = dns.edns.option_from_wire(otype, query.options.edns_options, index, olen)
                edns_options.append(opt)
                index += olen
        else:
            edns = -1
            edns_max_udp_payload = None
            edns_flags = None
            edns_options = []

        query1 = Query.DNSQuery(query.qname, query.rdtype, query.rdclass, query.options.flags, edns, edns_max_udp_payload, edns_flags, edns_options, query.options.tcp_first)

        server_cookie = None
        server_cookie_status = Query.DNS_COOKIE_NO_COOKIE
        if edns >= 0:
            try:
                cookie_opt = [o for o in edns_options if o.otype == 10][0]
            except IndexError:
                pass
            else:
                if len(cookie_opt.data) == 8:
                    server_cookie_status = Query.DNS_COOKIE_CLIENT_COOKIE_ONLY
                elif len(cookie_opt.data) >= 16 and len(cookie_opt.data) <= 40:
                    if cookie_opt.data[8:] == dnsviz.analysis.online.COOKIE_STANDIN:
                        # initially assume that there is a cookie for the server;
                        # change the value later if there isn't
                        server_cookie_status = Query.DNS_COOKIE_SERVER_COOKIE_FRESH
                    elif cookie_opt.data[8:] == dnsviz.analysis.online.COOKIE_BAD:
                        server_cookie_status = Query.DNS_COOKIE_SERVER_COOKIE_BAD
                    else:
                        server_cookie_status = Query.DNS_COOKIE_SERVER_COOKIE_STATIC
                else:
                    server_cookie_status = Query.DNS_COOKIE_IMPROPER_LENGTH

        # add the responses
        for response in query.responses.all():
            history = []
            if response.history_serialized:
                history_vals = map(int, response.history_serialized.split(','))

                for i in range(0, len(history_vals), 5):
                    response_time = history_vals[i]/1000.0
                    cause = history_vals[i+1]
                    cause_arg = history_vals[i+2]
                    action = history_vals[i+3]
                    action_arg = history_vals[i+4]
                    if cause_arg < 0:
                        cause_arg = None
                    if action_arg < 0:
                        action_arg = None
                    history.append(Query.DNSQueryRetryAttempt(response_time, cause, cause_arg, action, action_arg))

            server = IPAddr(response.server)
            client = IPAddr(response.client)
            cookie_jar = cookie_jar_map.get(server, default_cookie_jar)
            server_cookie = cookie_jar.get(server, None)
            status = server_cookie_status
            if status == Query.DNS_COOKIE_SERVER_COOKIE_FRESH and server_cookie is None:
                status = Query.DNS_COOKIE_CLIENT_COOKIE_ONLY
            response1 = Response.DNSResponse(response.message, response.msg_size, response.error, response.errno, history, response.response_time/1000.0, query1, server_cookie, status)
            bailiwick = bailiwick_map.get(server, default_bailiwick)
            query1.add_response(server, client, response1, bailiwick)

        return query1

    def retrieve_related(self, level):
        if not self.stub and self._retrieve_related_cache(level):
            return

        rdtypes = self._rdtypes_for_analysis_level(level)

        self._retrieve_auth_ns_ip_mapping()

        if self.stub:
            return

        # import delegation NS queries first
        delegation_types = set([dns.rdatatype.NS])
        if self.referral_rdtype is not None:
            delegation_types.add(self.referral_rdtype)
        if self.auth_rdtype is not None:
            delegation_types.add(self.auth_rdtype)
        if self.cookie_rdtype is not None:
            delegation_types.add(self.cookie_rdtype)

        delegation_queries = []
        auth_queries = []
        cookie_queries = []
        other_queries = []

        bailiwick_map, default_bailiwick = self.get_bailiwick_mapping()
        cookie_jar_map, default_cookie_jar = self.get_cookie_jar_mapping()

        # create a filter for the queries, based on rdtypes and name
        f = Q()
        if rdtypes is not None:
            rdtypes = rdtypes.union(delegation_types)
            f &= Q(rdtype__in=rdtypes)
        if level >= self.RDTYPES_ALL_SAME_NAME:
            if self.dlv_name is not None:
                names = (self.name, self.dlv_name)
            else:
                names = (self.name,)
            f &= Q(qname__in=names)
        for query in self.queries_db.filter(f):
            query1 = self._retrieve_query(query, bailiwick_map, default_bailiwick, cookie_jar_map, default_cookie_jar)
            if query1 is None:
                continue
            elif query1.rdtype == self.referral_rdtype:
                delegation_queries.append(query1)
            elif query1.rdtype == self.auth_rdtype:
                auth_queries.append(query1)
            elif query1.rdtype == self.cookie_rdtype:
                cookie_queries.append(query1)
            else:
                other_queries.append(query1)

        for query in delegation_queries + auth_queries + cookie_queries:
            detect_ns = query.rdtype in (dns.rdatatype.NS, self.referral_rdtype, self.auth_rdtype)
            detect_cookies = query.rdtype == self.cookie_rdtype
            self.add_query(query, detect_ns, detect_cookies)

        # set the NS dependencies for the name
        if self.is_zone():
            self.set_ns_dependencies()

        for query in other_queries:
            self.add_query(query, False, False)

        self._store_related_cache(level)

    def retrieve_ancestry(self, level, follow_dependencies=False, force_stub=False, cache=None):
        if cache is None:
            cache = {}

        if self.analysis_type == dnsviz.analysis.online.ANALYSIS_TYPE_AUTHORITATIVE:
            date = self.analysis_end
        else:
            date = None

        if self.parent_name_db is not None:
            # if force_stub, then we don't care if the previous one was stub or
            # not; otherwise, we care.
            if force_stub:
                f_stub = None
            else:
                f_stub = False
            parent = self.__class__.objects.latest_or_group(self.parent_name_db, date, stub=f_stub, group=self.group)
            # if force_stub, make it a stub (even if it isn't a stub in the
            # database) and don't cache it
            if force_stub:
                parent.stub = True
                parent.retrieve_related(level)
            else:
                if parent.pk in cache:
                    parent, code = cache[parent.pk]
                if parent.pk not in cache or code > level:
                    cache[parent.pk] = parent, level
                    parent.retrieve_ancestry(level, follow_dependencies=follow_dependencies, cache=cache)
                    parent.retrieve_related(level)
                    if follow_dependencies:
                        parent.retrieve_dependencies(cache=cache)
        else:
            parent = None

        if self.nxdomain_ancestor_name_db is not None:
            nxdomain_ancestor = self.__class__.objects.latest_or_group(self.nxdomain_ancestor_name_db, date, group=self.group)
            if nxdomain_ancestor.pk in cache:
                nxdomain_ancestor, code = cache[nxdomain_ancestor.pk]
            if nxdomain_ancestor.pk not in cache or code > level:
                cache[nxdomain_ancestor.pk] = nxdomain_ancestor, level
                nxdomain_ancestor.retrieve_ancestry(level, follow_dependencies=False, cache=cache)
                nxdomain_ancestor.retrieve_related(level)
        else:
            nxdomain_ancestor = None

        if level > self.RDTYPES_SECURE_DELEGATION:
            dlv_parent = None
        elif self.name != dns.name.root and self.dlv_parent_name_db is not None:
            dlv_parent = self.__class__.objects.latest(self.dlv_parent_name_db, self.analysis_end)
            if dlv_parent.pk in cache:
                dlv_parent, code = cache[dlv_parent.pk]
            if dlv_parent.pk not in cache or code > level:
                cache[dlv_parent.pk] = dlv_parent, level
                dlv_parent.retrieve_ancestry(level, follow_dependencies=False, force_stub=True, cache=cache)
                dlv_parent.retrieve_related(self.RDTYPES_SECURE_DELEGATION)
        else:
            dlv_parent = None

        self.parent = parent
        if dlv_parent is not None:
            self.dlv_parent = dlv_parent
        if nxdomain_ancestor is not None:
            self.nxdomain_ancestor = nxdomain_ancestor

    def retrieve_dependencies(self, cache=None):
        if cache is None:
            cache = {}

        if self.analysis_type == dnsviz.analysis.online.ANALYSIS_TYPE_AUTHORITATIVE:
            date = self.dep_analysis_end
        else:
            date = None

        for cname in self.cname_targets:
            for target in self.cname_targets[cname]:
                if target == self.name:
                    self.cname_targets[cname][target] = self
                    continue
                self.cname_targets[cname][target] = self.__class__.objects.latest_or_group(target, date, group=self.group)
                if self.cname_targets[cname][target].pk in cache:
                    self.cname_targets[cname][target], code = cache[self.cname_targets[cname][target].pk]
                if self.cname_targets[cname][target].pk not in cache or code > self.RDTYPES_ALL_SAME_NAME:
                    cache[self.cname_targets[cname][target].pk] = self.cname_targets[cname][target], self.RDTYPES_ALL_SAME_NAME
                    self.cname_targets[cname][target].retrieve_ancestry(self.RDTYPES_SECURE_DELEGATION, follow_dependencies=True, cache=cache)
                    self.cname_targets[cname][target].retrieve_related(self.RDTYPES_ALL_SAME_NAME)
                    self.cname_targets[cname][target].retrieve_dependencies(cache=cache)
        for signer in self.external_signers:
            if signer == self.name:
                self.external_signers[signer] = self
                continue
            self.external_signers[signer] = self.__class__.objects.latest_or_group(signer, date, group=self.group)
            if self.external_signers[signer].pk in cache:
                self.external_signers[signer], code = cache[self.external_signers[signer].pk]
            if self.external_signers[signer].pk not in cache or code > self.RDTYPES_SECURE_DELEGATION:
                cache[self.external_signers[signer].pk] = self.external_signers[signer], self.RDTYPES_SECURE_DELEGATION
                self.external_signers[signer].retrieve_ancestry(self.RDTYPES_SECURE_DELEGATION, follow_dependencies=True, cache=cache)
                self.external_signers[signer].retrieve_related(self.RDTYPES_SECURE_DELEGATION)
                self.external_signers[signer].retrieve_dependencies(cache=cache)
        #TODO figure a robust solution for this--perhaps with persistent follow_ns boolean or by checking freshess, or...
        #for target in self.ns_dependencies:
        #    if target == self.name:
        #        self.ns_dependencies[target] = self
        #        continue
        #    self.ns_dependencies[target] = self.__class__.objects.latest_or_group(target, date, group=self.group)
        #    #TODO also check freshness of retrieved object
        #    if self.ns_dependencies[target] is not None:
        #        if self.ns_dependencies[target].pk in cache:
        #            self.ns_dependencies[target], code = cache[self.ns_dependencies[target].pk]
        #        if self.ns_dependencies[target].pk not in cache or code > self.RDTYPES_NS_TARGET:
        #            cache[self.ns_dependencies[target].pk] = self.ns_dependencies[target], self.RDTYPES_NS_TARGET
        #            self.ns_dependencies[target].retrieve_ancestry(self.RDTYPES_SECURE_DELEGATION, follow_dependencies=True, cache=cache)
        #            self.ns_dependencies[target].retrieve_related(self.RDTYPES_NS_TARGET)
        #            self.ns_dependencies[target].retrieve_dependencies(cache=cache)

    def analyses_for_group(self, force_group, explicit_delegations, trace=None):
        if trace is None:
            trace = []

        result = []
        if self in trace:
            return result

        # add all analyses in ancestry with explicit delegations to result
        obj = self
        while obj is not None and \
                (force_group or \
                filter(lambda x: obj.name.is_subdomain(x), [n for n, t in explicit_delegations if t == dns.rdatatype.NS])):
            result.append(obj)
            obj = obj.parent
        if self.nxdomain_ancestor is not None:
            result.append(self.nxdomain_ancestor)
        for cname in self.cname_targets:
            for cname_obj in self.cname_targets[cname].values():
                result.extend(cname_obj.analyses_for_group(force_group, explicit_delegations, trace + [self]))
        for signer_obj in self.external_signers.values():
            obj = signer_obj
            result.extend(signer_obj.analyses_for_group(force_group, explicit_delegations, trace + [self]))
        for ns_obj in self.ns_dependencies.values():
            if ns_obj is not None:
                result.extend(ns_obj.analyses_for_group(force_group, explicit_delegations, trace + [self]))
        return result

    def set_group(self, force_group, explicit_delegations):
        if self.group is not None:
            group_objs = self.analyses_for_group(force_group, explicit_delegations)
            if group_objs:
                OnlineDomainNameAnalysis.objects.filter(pk__in=[a.pk for a in group_objs]).update(group=self.group)

    def save_dependencies(self):
        for cname in self.cname_targets:
            for cname_obj in self.cname_targets[cname].values():
                cname_obj.save_all(False)
        for signer_obj in self.external_signers.values():
            signer_obj.save_all(False)
        for ns_obj in self.ns_dependencies.values():
            if ns_obj is not None:
                ns_obj.save_all(False)

    def schedule_refresh(self):
        dname_obj = DomainName.objects.get(name=self.name)

        # only schedule refresh for zones
        if not (self.name == dns.name.root or self.is_zone()):
            dname_obj.clear_refresh()
            return

        # check against refresh blacklist
        if hasattr(settings, 'BLACKLIST_FROM_REFRESH'):
            for black in settings.BLACKLIST_FROM_REFRESH:
                if self.name.is_subdomain(black):
                    dname_obj.clear_refresh()
                    return

        # analyze root every hour
        if self.name == dns.name.root:
            refresh_interval = 3600

        # if we are a TLD, then re-analyze every eight hours
        elif len(self.name) <= 2:
            refresh_interval = 28800

        # if we are a signed zone, then re-analyze every two days
        elif self.signed:
            refresh_interval = 172800

        # if we are an unsigned zone, then don't re-analyze
        else:
            return

        refresh_offset = util.uuid_for_name(self.name).int % refresh_interval
        dname_obj.set_refresh(refresh_interval, refresh_offset)

class OfflineDomainNameAnalysis(OnlineDomainNameAnalysis):
    QUERY_CLASS = Query.MultiQueryAggregateDNSResponse

    class Meta:
        proxy = True

class ResourceRecord(models.Model):
    name = fields.DomainNameField(max_length=2048)
    rdtype = fields.UnsignedSmallIntegerField()
    rdclass = fields.UnsignedSmallIntegerField()
    rdata_wire = models.BinaryField()

    rdata_name = fields.DomainNameField(max_length=2048, blank=True, null=True, db_index=True)
    rdata_address = models.GenericIPAddressField(blank=True, null=True, db_index=True)

    class Meta:
        unique_together = (('name', 'rdtype', 'rdclass', 'rdata_wire'),)

    def __unicode__(self):
        return '%s %s %s %s' % (self.name.to_unicode(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype), self.rdata)

    def __str__(self):
        return '%s %s %s %s' % (self.name.to_text(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype), self.rdata)

    def _set_rdata(self, rdata):
        self._rdata = rdata
        wire = StringIO.StringIO()
        rdata.to_wire(wire)
        self.rdata_wire = wire.getvalue()
        for name, value in self.rdata_extra_field_params(rdata).items():
            setattr(self, name, value)

    def _get_rdata(self):
        if not hasattr(self, '_rdata') or self._rdata is None:
            if not self.rdata_wire:
                return None
            self._rdata = dns.rdata.from_wire(self.rdclass, self.rdtype, bytes(self.rdata_wire), 0, len(self.rdata_wire))
        return self._rdata

    rdata = property(_get_rdata, _set_rdata)

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        return { 'rdata_name': None, 'rdata_address': None }

class ResourceRecordWithNameInRdata(ResourceRecord):
    _rdata_name_field = None

    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordWithNameInRdata, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'rdata_name': getattr(rdata, cls._rdata_name_field) })
        return params

class ResourceRecordWithAddressInRdata(ResourceRecord):
    _rdata_address_field = None

    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordWithAddressInRdata, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'rdata_address': getattr(rdata, cls._rdata_address_field) })
        return params

class ResourceRecordA(ResourceRecordWithAddressInRdata):
    class Meta:
        proxy = True

    _rdata_address_field = 'address'

class ResourceRecordSOA(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'mname'

class ResourceRecordNS(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'target'

class ResourceRecordMX(ResourceRecordWithNameInRdata):
    class Meta:
        proxy = True

    _rdata_name_field = 'exchange'

class ResourceRecordDNSKEYRelated(ResourceRecord):
    algorithm = models.PositiveSmallIntegerField()
    key_tag = fields.UnsignedSmallIntegerField(db_index=True)
    expiration = models.DateTimeField(blank=True, null=True)
    inception = models.DateTimeField(blank=True, null=True)

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDNSKEYRelated, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'algorithm': rdata.algorithm,
                    'key_tag': None,
                    'expiration': None,
                    'inception': None
            })
        return params

class ResourceRecordDNSKEY(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDNSKEY, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'key_tag': Response.DNSKEYMeta.calc_key_tag(rdata) })
        return params

class ResourceRecordDS(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordDS, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'key_tag': rdata.key_tag })
        return params

class ResourceRecordRRSIG(ResourceRecordDNSKEYRelated):
    class Meta:
        proxy = True

    @classmethod
    def rdata_extra_field_params(cls, rdata):
        params = super(ResourceRecordRRSIG, cls).rdata_extra_field_params(rdata)
        if params:
            params.update({ 'key_tag': rdata.key_tag,
                    'expiration': fmt.timestamp_to_datetime(rdata.expiration),
                    'inception': fmt.timestamp_to_datetime(rdata.inception)
            })
        return params

class ResourceRecordManager(models.Manager):
    _rdtype_model_map = {
            dns.rdatatype.SOA: ResourceRecordSOA,
            dns.rdatatype.A: ResourceRecordA,
            dns.rdatatype.AAAA: ResourceRecordA,
            dns.rdatatype.NS: ResourceRecordNS,
            dns.rdatatype.MX: ResourceRecordMX,
            dns.rdatatype.PTR: ResourceRecordNS,
            dns.rdatatype.CNAME: ResourceRecordNS,
            dns.rdatatype.DNAME: ResourceRecordNS,
            dns.rdatatype.SRV: ResourceRecordNS,
            dns.rdatatype.DNSKEY: ResourceRecordDNSKEY,
            dns.rdatatype.RRSIG: ResourceRecordRRSIG,
            dns.rdatatype.DS: ResourceRecordDS,
    }

    def model_for_rdtype(self, rdtype):
        return self._rdtype_model_map.get(rdtype, ResourceRecord)

ResourceRecord.add_to_class('rr_mapper', ResourceRecordManager())

class DNSQueryOptions(models.Model):
    flags = fields.UnsignedSmallIntegerField()
    edns_max_udp_payload = fields.UnsignedSmallIntegerField(blank=True, null=True)
    edns_flags = fields.UnsignedIntegerField(blank=True, null=True)
    edns_options = models.BinaryField(blank=True, null=True)
    tcp_first = models.BooleanField(default=False)

    class Meta:
        unique_together = (('flags', 'edns_max_udp_payload', 'edns_flags', 'edns_options', 'tcp_first'),)

class DNSQuery(models.Model):
    qname = fields.DomainNameField(max_length=2048, canonicalize=False)
    rdtype = fields.UnsignedSmallIntegerField()
    rdclass = fields.UnsignedSmallIntegerField()
    response_options = fields.UnsignedSmallIntegerField(default=0)

    options = models.ForeignKey(DNSQueryOptions, related_name='queries')
    analysis = models.ForeignKey(OnlineDomainNameAnalysis, related_name='queries_db')

    version = models.PositiveSmallIntegerField(default=3)

class DNSResponse(models.Model):
    SECTIONS = { 'QUESTION': 0, 'ANSWER': 1, 'AUTHORITY': 2, 'ADDITIONAL': 3 }

    query = models.ForeignKey(DNSQuery, related_name='responses')

    # network parameters
    server = models.GenericIPAddressField()
    client = models.GenericIPAddressField()

    # response attributes
    flags = fields.UnsignedSmallIntegerField(blank=True, null=True)

    has_question = models.BooleanField(default=True)
    question_name = fields.DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    question_rdtype = fields.UnsignedSmallIntegerField(blank=True, null=True)
    question_rdclass = fields.UnsignedSmallIntegerField(blank=True, null=True)

    edns_max_udp_payload = fields.UnsignedSmallIntegerField(blank=True, null=True)
    edns_flags = fields.UnsignedIntegerField(blank=True, null=True)
    edns_options = models.BinaryField(blank=True, null=True)

    error = models.PositiveSmallIntegerField(blank=True, null=True)
    errno = models.PositiveSmallIntegerField(blank=True, null=True)
    response_time = models.PositiveSmallIntegerField()
    history_serialized = models.CharField(max_length=4096, validators=[validate_comma_separated_integer_list], blank=True)

    msg_size = fields.UnsignedSmallIntegerField(blank=True, null=True)

    def __init__(self, *args, **kwargs):
        super(DNSResponse, self).__init__(*args, **kwargs)
        self._message = None

    def __unicode__(self):
        return u'query: %s %s %s server: %s' % \
                (self.qname.to_unicode(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype),
                        self.server)

    def __str__(self):
        return 'query: %s %s %s server: %s' % \
                (self.qname.to_text(), dns.rdataclass.to_text(self.rdclass), dns.rdatatype.to_text(self.rdtype),
                        self.server)

    def _import_sections(self, message):
        rr_map_list = []
        rr_map_list.extend(self._import_section(message.answer, self.SECTIONS['ANSWER']))
        rr_map_list.extend(self._import_section(message.authority, self.SECTIONS['AUTHORITY']))
        rr_map_list.extend(self._import_section(message.additional, self.SECTIONS['ADDITIONAL']))
        ResourceRecordMapper.objects.bulk_create(rr_map_list)

    def _import_section(self, section, number):
        rr_map_list = []
        for index, rrset in enumerate(section):
            rr_cls = ResourceRecord.rr_mapper.model_for_rdtype(rrset.rdtype)
            for rr in rrset:
                sio = StringIO.StringIO()
                rr.to_wire(sio)
                rdata_wire = sio.getvalue()
                params = dict(rr_cls.rdata_extra_field_params(rr).items())
                rr_obj, created = rr_cls.objects.get_or_create(name=rrset.name, rdtype=rrset.rdtype, \
                        rdclass=rrset.rdclass, rdata_wire=rdata_wire, defaults=params)
                if rrset.name.to_text() != rrset.name.canonicalize().to_text():
                    raw_name = rrset.name
                else:
                    raw_name = ''
                rr_map_list.append(ResourceRecordMapper(message=self, section=number, rdata=rr_obj, \
                        ttl=rrset.ttl, order=index, raw_name=raw_name))
        return rr_map_list

    def _export_sections(self, message):
        all_rr_maps = self.rr_mappings.select_related('rdata').order_by('section', 'order')

        prev_section = None
        prev_order = None
        for rr_map in all_rr_maps:
            if rr_map.section != prev_section:
                if rr_map.section == self.SECTIONS['ANSWER']:
                    section = message.answer
                elif rr_map.section == self.SECTIONS['AUTHORITY']:
                    section = message.authority
                elif rr_map.section == self.SECTIONS['ADDITIONAL']:
                    section = message.additional
                prev_section = rr_map.section
                prev_order = None

            if prev_order != rr_map.order:
                if rr_map.rdata.rdtype == dns.rdatatype.RRSIG:
                    covers = rr_map.rdata.rdata.covers()
                else:
                    covers = dns.rdatatype.NONE
                rrset = dns.rrset.RRset(rr_map.rdata.name, rr_map.rdata.rdclass, rr_map.rdata.rdtype, covers)
                section.append(rrset)
                message.index[(message.section_number(section),
                        rrset.name, rrset.rdclass, rrset.rdtype, rrset.covers, None)] = rrset
                prev_order = rr_map.order

            rrset.add(rr_map.rdata.rdata, rr_map.ttl)

    def _set_message(self, message):
        assert self.pk is not None, 'Response object must be saved before response data can be associated with it'

        self._message = message

        if message is None:
            return

        self.flags = message.flags

        if message.edns >= 0:
            self.edns_max_udp_payload = message.payload
            self.edns_flags = message.ednsflags
            self.edns_options = b''
            for opt in message.options:
                s = StringIO.StringIO()
                opt.to_wire(s)
                data = s.getvalue()
                self.edns_options += struct.pack('!HH', opt.otype, len(data)) + data

        if message.question:
            self.has_question = True
            if message.question[0].name.to_text() != self.query.qname.to_text():
                self.question_name = message.question[0].name
            if message.question[0].rdtype != self.query.rdtype:
                self.question_rdtype = message.question[0].rdtype
            if message.question[0].rdclass != self.query.rdclass:
                self.question_rdclass = message.question[0].rdclass
        else:
            self.has_question = False

        self._import_sections(self._message)

    def _get_message(self):
        if not hasattr(self, '_message') or self._message is None:
            # response has not been set yet or is invalid
            if self.flags is None:
                return None
            #XXX generate a queryid, rather than using 0
            self._message = dns.message.Message(0)
            self._message.flags = self.flags

            if self.has_question:
                qname, qrdclass, qrdtype = self.query.qname, self.query.rdclass, self.query.rdtype
                if self.question_name is not None:
                    qname = self.question_name
                if self.question_rdclass is not None:
                    qrdclass = self.question_rdclass
                if self.question_rdtype is not None:
                    qrdtype = self.question_rdtype
                self._message.question.append(dns.rrset.RRset(qname, qrdclass, qrdtype))

            if self.edns_max_udp_payload is not None:
                self._message.use_edns(self.edns_flags>>16, self.edns_flags, self.edns_max_udp_payload, 65536)
                index = 0
                while index < len(self.edns_options):
                    (otype, olen) = struct.unpack('!HH', self.edns_options[index:index + 4])
                    index += 4
                    opt = dns.edns.option_from_wire(otype, self.edns_options, index, olen)
                    self._message.options.append(opt)
                    index += olen

            self._export_sections(self._message)

        return self._message

    message = property(_get_message, _set_message)

class ResourceRecordMapper(models.Model):
    message = models.ForeignKey(DNSResponse, related_name='rr_mappings')
    section = models.PositiveSmallIntegerField()

    order = models.PositiveSmallIntegerField()
    raw_name = fields.DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    rdata = models.ForeignKey(ResourceRecord)
    ttl = fields.UnsignedIntegerField()

    class Meta:
        unique_together = (('message', 'rdata', 'section'),)

    def __unicode__(self):
        return unicode(self.rdata)

    def __str__(self):
        return str(self.rdata)
