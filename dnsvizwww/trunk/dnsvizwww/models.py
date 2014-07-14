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
import StringIO
import struct
import urllib

import dns.edns, dns.exception, dns.flags, dns.message, dns.name, dns.rcode, dns.rdataclass, dns.rdata, dns.rdatatype, dns.rrset

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import models, transaction
from django.db.models import Q
from django.utils.html import escape
from django.utils.timezone import now, utc
from django.utils.translation import ugettext_lazy as _

import dnsviz.analysis
import dnsviz.format as fmt
import dnsviz.query as Query
import dnsviz.response as Response

MIN_ANALYSIS_INTERVAL = 14400

class UnsignedSmallIntegerField(models.SmallIntegerField):
    __metaclass__ = models.SubfieldBase
    def to_python(self, value):
        value = super(UnsignedSmallIntegerField, self).to_python(value)
        if value is None:
            return None
        if value < 0:
            value = 0x7FFF - value
        return value

    def get_prep_value(self, value):
        value = super(UnsignedSmallIntegerField, self).get_prep_value(value)
        if value is None:
            return None
        if value > 0x7FFF:
            value = -(value - 0x7FFF)
        return value

class UnsignedIntegerField(models.IntegerField):
    __metaclass__ = models.SubfieldBase
    def to_python(self, value):
        value = super(UnsignedIntegerField, self).to_python(value)
        if value is None:
            return None
        if value < 0:
            value = 0x7FFFFFFF - value
        return value

    def get_prep_value(self, value):
        value = super(UnsignedIntegerField, self).get_prep_value(value)
        if value is None:
            return None
        if value > 0x7FFFFFFF:
            value = -(value - 0x7FFFFFFF)
        return value

class DomainNameField(models.CharField):
    description = _("Domain name (with maximum length of %(max_length)s characters)")

    __metaclass__ = models.SubfieldBase

    def __init__(self, *args, **kwargs):
        self.canonicalize = kwargs.pop('canonicalize', True)
        super(DomainNameField, self).__init__(*args, **kwargs)

    def to_python(self, value):
        if value is None:
            return None
        if isinstance(value, dns.name.Name):
            name = value
        else:
            try:
                name = dns.name.from_text(value)
            except Exception, e:
                raise ValidationError('%s: %s is of type %s' % (e, value, type(value)))
        if self.canonicalize:
            name = name.canonicalize()
        return name

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, dns.name.Name):
            name = value
        else:
            name = dns.name.from_text(value)
        if self.canonicalize:
            name = name.canonicalize()
        return name.to_text()

class BinaryField(models.Field):
    #XXX no longer needed as of django 1.6
    __metaclass__ = models.SubfieldBase

    def db_type(self, connection):
        if connection.settings_dict['ENGINE'] in ('django.db.backends.postgresql_psycopg2', 'django.db.backends.postgresql'):
            return 'bytea'
        elif connection.settings_dict['ENGINE'] == 'django.db.backends.mysql':
            return 'blob'
        elif connection.settings_dict['ENGINE'] == 'django.db.backends.sqlite3':
            return 'BLOB'
        raise Exception('Binary data type not known for %s db backend' % connection.settings_dict['ENGINE'])

    def to_python(self, value):
        if value is None:
            return None
        if isinstance(value, basestring):
            return value
        return str(value)

    def get_prep_value(self, value):
        if value is None:
            return None
        if isinstance(value, bytearray):
            return value
        return bytearray(value)

class DomainName(models.Model):

    name = DomainNameField(max_length=2048, primary_key=True)
    analysis_start = models.DateTimeField(blank=True, null=True)

    def __unicode__(self):
        return fmt.humanize_name(self.name, True)

    def __str__(self):
        return fmt.humanize_name(self.name)

    def latest_analysis(self, date=None):
        return DomainNameAnalysis.objects.latest(self.name, date)

class DNSServer(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __unicode__(self):
        return self.ip_address

class NSMapping(models.Model):
    name = DomainNameField(max_length=2048)
    server = models.ForeignKey(DNSServer)

    class Meta:
        unique_together = (('name', 'server'),)

    def __unicode__(self):
        return '%s -> %s' % (self.name.to_unicode(), self.server)

    def __str__(self):
        return '%s -> %s' % (self.name.to_text(), self.server)

class DomainNameAnalysisManager(models.Manager):
    def latest(self, name, date=None):
        f = Q(name=name)
        if date is not None:
            f &= Q(analysis_end__lte=date)

        try:
            return self.filter(f).latest()
        except self.model.DoesNotExist:
            return None

    def earliest(self, name, date=None):
        f = Q(name=name)
        if date is not None:
            f &= Q(analysis_end__gte=date)

        try:
            return self.filter(f).order_by('analysis_end')[0]
        except IndexError:
            return None

    def get(self, name, date):
        try:
            return self.filter(name=name, analysis_end=date).get()
        except self.model.DoesNotExist:
            return None

class DomainNameAnalysis(dnsviz.analysis.DomainNameAnalysis, models.Model):
    name = DomainNameField(max_length=2048)
    dlv_domain = DomainNameField(max_length=2048, blank=True, null=True)
    stub = models.BooleanField()

    analysis_start = models.DateTimeField()
    analysis_end = models.DateTimeField(db_index=True)
    dep_analysis_end = models.DateTimeField()

    version = models.PositiveSmallIntegerField(default=17)

    parent_name_db = DomainNameField(max_length=2048, blank=True, null=True)

    referral_rdtype = UnsignedSmallIntegerField(blank=True, null=True)

    nxdomain_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxdomain_rdtype = UnsignedSmallIntegerField(blank=True, null=True)
    nxrrset_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    nxrrset_rdtype = UnsignedSmallIntegerField(blank=True, null=True)

    auth_ns_ip_mapping_db = models.ManyToManyField(NSMapping, related_name='s+')

    objects = DomainNameAnalysisManager()

    def __init__(self, *args, **kwargs):
        if args:
            if kwargs:
                # since args and kwargs were both supplied to __init__, this was
                # intended for dnsviz.analysis.DomainNameAnalysis, so we need to
                # convert the args to kwargs for models.Model.__init__.
                dnsviz.analysis.DomainNameAnalysis.__init__(self, *args[:3], **kwargs)
                kwargs['name'] = args[0]
                if len(args) > 1: kwargs['dlv_domain'] = args[1]
                if len(args) > 2: kwargs['stub'] = args[2]
                args = ()
            else:
                # If only args, then this could suit either parent __init__.
                # In the case of models.Model, the first argument would be int,
                # for the 'id' field.  In this case, we convert the args to
                # kwargs for models.Model.__init__.
                if isinstance(args[0], (int, long)):
                    args_modified = args[1:4]
                else:
                    args_modified = args[:3]
                    kwargs['name'] = args[0]
                    if len(args) > 1: kwargs['dlv_domain'] = args[1]
                    if len(args) > 2: kwargs['stub'] = args[2]
                    args = ()
                dnsviz.analysis.DomainNameAnalysis.__init__(self, *args_modified)
        else:
            # only kwargs, so this was intended only for models.Model.__init__.  We
            # create args for dnsviz.analysis.DomainNameAnalysis.__init__ by pulling
            # the 'name' kwarg from kwargs.
            kwargs_modified = {}
            if 'dlv_domain' in kwargs:
                kwargs_modified['dlv_domain'] = kwargs['dlv_domain']
            if 'stub' in kwargs:
                kwargs_modified['stub'] = kwargs['stub']
            dnsviz.analysis.DomainNameAnalysis.__init__(self, (kwargs['name'],), **kwargs_modified)
        models.Model.__init__(self, *args, **kwargs)

    class Meta:
        unique_together = (('name', 'analysis_end'),)
        get_latest_by = 'analysis_end'

    def _get_previous(self):
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

    def save(self, save_related=False):
        with transaction.commit_manually():
            try:
                self.parent_name_db = self.parent_name()
                super(DomainNameAnalysis, self).save()
                if save_related:
                    self.store_related()
            except:
                transaction.rollback()
                raise
            else:
                transaction.commit()


    def store_related(self):
        # add the auth NS to IP mapping
        for name in self._auth_ns_ip_mapping:
            for ip in self._auth_ns_ip_mapping[name]:
                ip = fmt.fix_ipv6(ip)
                self.auth_ns_ip_mapping_db.add(NSMapping.objects.get_or_create(name=name, server=DNSServer.objects.get_or_create(ip_address=ip)[0])[0])

        # add the queries
        for (qname, rdtype), query in self.queries.items():
            if query.edns >= 0:
                edns_max_udp_payload = query.edns_max_udp_payload
                edns_flags = query.edns_flags
                edns_options = ''
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
                    edns_flags=edns_flags, edns_options=edns_options)[0]

            query_obj = DNSQuery.objects.create(qname=query.qname, rdtype=query.rdtype, rdclass=query.rdclass,
                    options=query_options, analysis=self)

            # add the responses
            for server in query.responses:
                for client in query.responses[server]:
                    if query.responses[server][client].message is not None:
                        flags = query.responses[server][client].message.flags
                    else:
                        flags = None
                    #TODO get history
                    response_obj = DNSResponse(query=query_obj, flags=flags, server=fmt.fix_ipv6(server), client=fmt.fix_ipv6(client),
                            error=query.responses[server][client].error, errno=query.responses[server][client].errno,
                            tcp_first=query.responses[server][client].tcp_first, response_time=int(query.responses[server][client].response_time*1000))
                    response_obj.save()
                    response_obj.message = query.responses[server][client].message

    def retrieve_related(self, rdtypes=None, cache=None):
        if cache is None:
            cache = {}

        if self.name != dns.name.root and not self.stub:
            parent = self.__class__.objects.latest(self.parent_name_db, self.analysis_end)
            if parent.pk in cache:
                parent = cache[parent.pk]
            else:
                cache[parent.pk] = parent
                parent.retrieve_related(rdtypes=set([parent.referral_rdtype, dns.rdatatype.NS, dns.rdatatype.DNSKEY, dns.rdatatype.DS]), cache=cache)

            if self.dlv_domain is not None:
                dlv_parent = self.__class__.objects.latest(self.dlv_domain, self.analysis_end)
                if dlv_parent.pk in cache:
                    dlv_parent = cache[dlv_parent.pk]
                else:
                    cache[dlv_parent.pk] = dlv_parent
                    dlv_parent.retrieve_related(rdtypes=set([dns.rdatatype.NS, dns.rdatatype.DNSKEY]), cache=cache)

        if not self.stub:
            if self.name != dns.name.root:
                self.parent = parent
                if self.dlv_domain is not None:
                    self.dlv_parent = dlv_parent

        # add the auth NS to IP mapping
        for name, ip in self.auth_ns_ip_mapping_db.values_list('name', 'server__ip_address'):
            self.add_auth_ns_ip_mappings((dns.name.from_text(name), ip))

        # import delegation NS queries first
        delegation_types = set([dns.rdatatype.NS])
        if self.referral_rdtype is not None:
            delegation_types.add(self.referral_rdtype)

        delegation_queries = []
        other_queries = []

        # add the queries
        if rdtypes is not None:
            rdtypes = rdtypes.union(delegation_types)
            queries = self.queries_db.filter(rdtype__in=rdtypes)
        else:
            queries = self.queries_db.all()
        for query in queries:
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

            query1 = Query.DNSQuery(query.qname, query.rdtype, query.rdclass, query.options.flags, edns, edns_max_udp_payload, edns_flags, edns_options)

            # add the responses
            for response in query.responses.all():
                response1 = Response.DNSResponse(response.message, response.error, response.errno, [], response.response_time, response.tcp_first)
                query1.add_response(response.server, response.client, response1)

            if query1.rdtype in delegation_types:
                delegation_queries.append(query1)
            else:
                other_queries.append(query1)

        for query in delegation_queries:
            self.add_query(query)
        for query in other_queries:
            self.add_query(query)

        for cname in self.cname_targets:
            self.cname_targets[cname] = self.__class__.objects.latest(cname, self.dep_analysis_end)
            if self.cname_targets[cname].pk in cache:
                self.cname_targets[cname] = cache[self.cname_targets[cname].pk]
            else:
                cache[self.cname_targets[cname].pk] = self.cname_targets[cname]
                self.cname_targets[cname].retrieve_related(cache=cache)
        for dname in self.dname_targets:
            self.dname_targets[dname] = self.__class__.objects.latest(dname, self.dep_analysis_end)
            if self.dname_targets[dname].pk in cache:
                self.dname_targets[dname] = cache[self.dname_targets[dname].pk]
            else:
                cache[self.dname_targets[dname].pk] = self.dname_targets[dname]
                self.dname_targets[dname].retrieve_related(cache=cache)
        for signer in self.external_signers:
            self.external_signers[signer] = self.__class__.objects.latest(signer, self.dep_analysis_end)
            if self.external_signers[signer].pk in cache:
                self.external_signers[signer] = cache[self.external_signers[signer].pk]
            else:
                cache[self.external_signers[signer].pk] = self.external_signers[signer]
                self.external_signers[signer].retrieve_related(rdtypes=set([parent.referral_rdtype, dns.rdatatype.NS, dns.rdatatype.DNSKEY, dns.rdatatype.DS]), cache=cache)
        #for target in self.get_ns_dependencies():
        #    self.ns_targets[target] = self.__class__.objects.latest(target, self.dep_analysis_end)
        #    if self.ns_targets[target].pk in cache:
        #        self.ns_targets[target] = cache[self.ns_targets[target].pk]
        #    else:
        #        cache[self.ns_targets[target].pk] = self.ns_targets[target]
        #        self.external_signers[signer].retrieve_related(), cache=cache)
        #        self.ns_targets[target].retrieve_related(rdtypes=set([parent.referral_rdtype, dns.rdatatype.NS, dns.rdatatype.DNSKEY, dns.rdatatype.DS, dns.rdatatype.A, dns.rdatatype.AAAA]), cache=cache)

class NSMapping(models.Model):
    name = DomainNameField(max_length=2048)
    server = models.ForeignKey(DNSServer)

    class Meta:
        unique_together = (('name', 'server'),)

    def __unicode__(self):
        return '%s -> %s' % (self.name.to_unicode(), self.server)

    def __str__(self):
        return '%s -> %s' % (self.name.to_text(), self.server)

class DomainNameAnalysisManager(models.Manager):
    def latest(self, name, date=None):
        f = Q(pk=name, analysis_end__isnull=False)

class DNSServer(models.Model):
    ip_address = models.GenericIPAddressField(unique=True)

    def __unicode__(self):
        return self.ip_address

class NSMapping(models.Model):
    name = DomainNameField(max_length=2048)
    server = models.ForeignKey(DNSServer)

class ResourceRecord(models.Model):
    name = DomainNameField(max_length=2048)
    rdtype = UnsignedSmallIntegerField()
    rdclass = UnsignedSmallIntegerField()
    rdata_wire = BinaryField()

    rdata_name = DomainNameField(max_length=2048, blank=True, null=True, db_index=True)
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
            self._rdata = dns.rdata.from_wire(self.rdclass, self.rdtype, self.rdata_wire, 0, len(self.rdata_wire))
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
    key_tag = UnsignedSmallIntegerField(db_index=True)
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

ResourceRecord.add_to_class('objects', ResourceRecordManager())

class DNSQueryOptions(models.Model):
    flags = UnsignedSmallIntegerField()
    edns_max_udp_payload = UnsignedSmallIntegerField(blank=True, null=True)
    edns_flags = UnsignedIntegerField(blank=True, null=True)
    edns_options = BinaryField(blank=True, null=True)

    class Meta:
        unique_together = (('flags', 'edns_max_udp_payload', 'edns_flags', 'edns_options'),)

class DNSQuery(models.Model):
    qname = DomainNameField(max_length=2048, canonicalize=False)
    rdtype = UnsignedSmallIntegerField()
    rdclass = UnsignedSmallIntegerField()

    options = models.ForeignKey(DNSQueryOptions, related_name='queries')
    analysis = models.ForeignKey(DomainNameAnalysis, related_name='queries_db')

class DNSResponse(models.Model):
    SECTIONS = { 'QUESTION': 0, 'ANSWER': 1, 'AUTHORITY': 2, 'ADDITIONAL': 3 }

    query = models.ForeignKey(DNSQuery, related_name='responses')

    version = models.PositiveSmallIntegerField(default=1)

    # network parameters
    server = models.GenericIPAddressField()
    client = models.GenericIPAddressField()

    # response attributes
    flags = UnsignedSmallIntegerField(blank=True, null=True)

    has_question = models.BooleanField(default=True)
    question_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    question_rdtype = UnsignedSmallIntegerField(blank=True, null=True)
    question_rdclass = UnsignedSmallIntegerField(blank=True, null=True)

    edns_max_udp_payload = UnsignedSmallIntegerField(blank=True, null=True)
    edns_flags = UnsignedIntegerField(blank=True, null=True)
    edns_options = BinaryField(blank=True, null=True)

    error = models.PositiveSmallIntegerField(blank=True, null=True)
    errno = models.PositiveSmallIntegerField(blank=True, null=True)
    tcp_first = models.BooleanField()
    response_time = models.PositiveSmallIntegerField()
    history_serialized = models.CommaSeparatedIntegerField(max_length=4096, blank=True)

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
            rr_cls = ResourceRecord.objects.model_for_rdtype(rrset.rdtype)
            for rr in rrset:
                sio = StringIO.StringIO()
                rr.to_wire(sio)
                rdata_wire = sio.getvalue()
                params = dict(rr_cls.rdata_extra_field_params(rr).items())
                with transaction.commit_manually():
                    try:
                        rr_obj, created = rr_cls.objects.get_or_create(name=rrset.name, rdtype=rrset.rdtype, \
                                rdclass=rrset.rdclass, rdata_wire=rdata_wire, defaults=params)
                    except:
                        transaction.rollback()
                        raise
                    else:
                        transaction.commit()
                if rrset.name.to_text() != rrset.name.canonicalize().to_text():
                    raw_name = rrset.name
                else:
                    raw_name = ''
                rr_map_list.append(ResourceRecordMapper(message=self, section=number, rdata=rr_obj, \
                        ttl=rrset.ttl, order=index, raw_name=raw_name))
        return rr_map_list

    def _export_sections(self, message):
        all_rr_maps = self.rr_mappings.select_related('rr').order_by('section', 'order')

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

        if message.payload is not None:
            self.edns_max_udp_payload = message.payload
            self.edns_flags = message.ednsflags
            self.edns_options = ''
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
    raw_name = DomainNameField(max_length=2048, canonicalize=False, blank=True, null=True)
    rdata = models.ForeignKey(ResourceRecord)
    ttl = UnsignedIntegerField()

    class Meta:
        unique_together = (('message', 'rdata', 'section'),)

    def __unicode__(self):
        return unicode(self.rr)

    def __str__(self):
        return str(self.rr)


class DBAnalyst(dnsviz.analysis.Analyst):
    qname_only = False
    analysis_model = DomainNameAnalysis

    def _analyze(self, name, ns_only=False):
        name_obj = super(DBAnalyst, self)._analyze(name, ns_only)
        # if this object hasn't been saved before
        if name_obj.pk is None:
            # stub zones don't save dep_analysis_end
            if name_obj.stub:
                name_obj.dep_analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)
            name_obj.save(save_related=True)
        return name_obj

    def _analyze_dependencies(self, name_obj):
        super(DBAnalyst, self)._analyze_dependencies(name_obj)
        name_obj.dep_analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)
