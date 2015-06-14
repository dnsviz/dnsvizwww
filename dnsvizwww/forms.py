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
import re

import dns.message, dns.name, dns.rdataclass, dns.rdatatype, dns.rrset

from django import forms
from django.conf import settings
from django.core.mail import send_mail
from django.utils.timezone import utc

from dnsviz.analysis import resolver
import dnsviz.format as fmt
from dnsviz.ipaddr import IPAddr
from dnsviz.resolver import DNSAnswer
from dnsviz.util import get_trusted_keys

from dnsvizwww.models import OfflineDomainNameAnalysis

_implicit_tk_str = '''
.			IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF FVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoX bfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaD X6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpz W5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relS Qageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulq QxA+Uk1ihz0=
dlv.isc.org.		IN	DNSKEY	257 3 5 BEAAAAPHMu/5onzrEE7z1egmhg/WPO0+juoZrW3euWEn4MxDCE1+lLy2 brhQv5rN32RKtMzX6Mj70jdzeND4XknW58dnJNPCxn8+jAGl2FZLK8t+ 1uq4W+nnA3qO2+DL+k6BD4mewMLbIYFwe0PG73Te9fZ2kJb56dhgMde5 ymX4BI/oQ+cAK50/xvJv00Frf8kw6ucMTwFlgPe+jnGxPPEmHAte/URk Y62ZfkLoBAADLHQ9IrS2tryAe7mbBZVcOwIeU/Rw/mRx/vwwMCTgNboM QKtUdvNXDrYJDSHZws3xiRXF1Rf+al9UmZfSav/4NWLKjHzpT59k/VSt TDN0YUuWrBNh
'''

class DNSSECOptionsForm(forms.Form):
    RR_CHOICES = (('all', '--All--'),
            (dns.rdatatype.A, dns.rdatatype.to_text(dns.rdatatype.A)),
            (dns.rdatatype.AAAA, dns.rdatatype.to_text(dns.rdatatype.AAAA)),
            (dns.rdatatype.TXT, dns.rdatatype.to_text(dns.rdatatype.TXT)),
            (dns.rdatatype.PTR, dns.rdatatype.to_text(dns.rdatatype.PTR)),
            (dns.rdatatype.MX, dns.rdatatype.to_text(dns.rdatatype.MX)),
            #(dns.rdatatype.NS, dns.rdatatype.to_text(dns.rdatatype.NS)),
            (dns.rdatatype.SOA, dns.rdatatype.to_text(dns.rdatatype.SOA)),
            (dns.rdatatype.CNAME, dns.rdatatype.to_text(dns.rdatatype.CNAME)),
            (dns.rdatatype.SRV, dns.rdatatype.to_text(dns.rdatatype.SRV)),
            (dns.rdatatype.NAPTR, dns.rdatatype.to_text(dns.rdatatype.NAPTR)),
            (dns.rdatatype.TLSA, dns.rdatatype.to_text(dns.rdatatype.TLSA)))

    A_CHOICES = (('all', '--All--'),
            (1, '1 - RSA/MD5'),
            (3, '3 - DSA/SHA1'),
            (5, '5 - RSA/SHA-1'),
            (6, '6 - DSA-NSEC3-SHA1'),
            (7, '7 - RSASHA1-NSEC3-SHA1'),
            (8, '8 - RSA/SHA-256'),
            (10, '10 - RSA/SHA-512'),
            (12, '12 - GOST R 34.10-2001'),
            (13, '13 - ECDSA Curve P-256 with SHA-256'),
            (14, '14 - ECDSA Curve P-384 with SHA-384'),)

    DS_CHOICES = (('all', '--All--'),
            (1, '1 - SHA-1'),
            (2, '2 - SHA-256'),
            (3, '3 - GOST R 34.11-94'),
            (4, '4 - SHA-384'),)

    ANCHOR_CHOICES = (('.', 'Root zone KSK'),
            ('dlv.isc.org.', 'ISC DLV KSK'),)

    rr = forms.MultipleChoiceField(label='RR types:', choices=RR_CHOICES, initial=['all'], required=True,
            help_text='Select the RR types to be considered in the analysis (note that not all RR types are available for all names).')
    a = forms.MultipleChoiceField(label='DNSSEC algorithms:', choices=A_CHOICES, initial=['all'], required=False,
            help_text='Select the DNSSEC algorithms that should be considered in the analysis.  Selecting no algorithms is equivalent to evaluating a zone as if unsigned.')
    ds = forms.MultipleChoiceField(label='DS digest algorithms:', choices=DS_CHOICES, initial=['all'], required=False,
            help_text='Select the DS digest algorithms that should be considered in the analysis.')
    doe = forms.BooleanField(label='Denial of existence:', initial=False, required=False, widget=forms.CheckboxInput(attrs={'class': 'no-border'}),
            help_text='Show authenticated denial of existence for non-existent RRsets.')
    red = forms.BooleanField(label='Redundant edges:', initial=False, required=False, widget=forms.CheckboxInput(attrs={'class': 'no-border'}),
            help_text='Show redundant edges between DNSKEYs.  Normally redundant edges are pruned to simplify the graph.')
    ta = forms.MultipleChoiceField(label='Trust anchors:', choices=ANCHOR_CHOICES, initial=['.','dlv.isc.org.'], required=False, widget=forms.CheckboxSelectMultiple(attrs={'class': 'no-border'}),
            help_text='Use KSKs from the following zones as trust anchors for the DNSSEC analysis: the root zone; and/or the KSK for ISC\'s DNSSEC-lookaside validation (DLV) service.')
    tk = forms.CharField(label='Additional trusted keys:', initial='', required=False, widget=forms.Textarea(attrs={'cols': 50, 'rows': 5}),
            help_text='Use the following DNSKEY(s) as additional trust anchors for the DNSSEC analysis.  DNSKEYs should be entered one per line, in zone file format.')

    def clean_rr(self):
        if 'all' in self.cleaned_data['rr']:
            return map(int, [rr[0] for rr in self.RR_CHOICES if rr[0] != 'all'])
        else:
            return map(int, self.cleaned_data['rr'])

    def clean_a(self):
        if 'all' in self.cleaned_data['a']:
            return map(int, [a[0] for a in self.A_CHOICES if a[0] != 'all'])
        else:
            return map(int, self.cleaned_data['a'])

    def clean_ds(self):
        if 'all' in self.cleaned_data['ds']:
            return map(int, [ds[0] for ds in self.DS_CHOICES if ds[0] != 'all'])
        else:
            return map(int, self.cleaned_data['ds'])

    def clean_ta(self):
        ta_all = get_trusted_keys(_implicit_tk_str)
        names = set()
        for name in self.cleaned_data['ta']:
            try:
                names.add(dns.name.from_text(name))
            except dns.exception.DNSException:
                raise forms.ValidationError('Invalid domain name entered: %s!' % name)
        ta = []
        for name, key in ta_all:
            if name in names:
                ta.append((name,key))
        return ta

    def clean_tk(self):
        try:
            return get_trusted_keys(self.cleaned_data['tk'])
        except:
            raise forms.ValidationError('Unable to process trusted keys!')

class ContactForm(forms.Form):
    subject = forms.CharField(max_length='64')
    reply_email = forms.EmailField(help_text='(Your email will not be stored or published anywhere.  It is simply used to return correspondence.)')
    message = forms.CharField(label='', widget=forms.Textarea)

    def submit_message(self):
        recipients = [e[1] for e in settings.MANAGERS]
        send_mail('[dnsviz] %s' % self.cleaned_data['subject'],
                self.cleaned_data['message'],
                self.cleaned_data['reply_email'],
                recipients)

def domain_analysis_form(name):
    ANCESTOR_CHOICES = [(name.to_text(), fmt.humanize_name(name, True))]
    n = name
    while n != dns.name.root:
        n = n.parent()
        ANCESTOR_CHOICES.append((n.to_text(), fmt.humanize_name(n, True)))
    ANCESTOR_CHOICES.reverse()

    class DomainNameAnalysisForm(forms.Form):
        EXTRA_TYPES = ((dns.rdatatype.A, dns.rdatatype.to_text(dns.rdatatype.A)),
                (dns.rdatatype.AAAA, dns.rdatatype.to_text(dns.rdatatype.AAAA)),
                (dns.rdatatype.TXT, dns.rdatatype.to_text(dns.rdatatype.TXT)),
                (dns.rdatatype.PTR, dns.rdatatype.to_text(dns.rdatatype.PTR)),
                (dns.rdatatype.MX, dns.rdatatype.to_text(dns.rdatatype.MX)),
                (dns.rdatatype.SOA, dns.rdatatype.to_text(dns.rdatatype.SOA)),
                (dns.rdatatype.CNAME, dns.rdatatype.to_text(dns.rdatatype.CNAME)),
                (dns.rdatatype.SRV, dns.rdatatype.to_text(dns.rdatatype.SRV)),
                (dns.rdatatype.NAPTR, dns.rdatatype.to_text(dns.rdatatype.NAPTR)),
                (dns.rdatatype.TLSA, dns.rdatatype.to_text(dns.rdatatype.TLSA)))

        force_ancestor = forms.TypedChoiceField(label='Force ancestor analysis', choices=ANCESTOR_CHOICES, initial=name.to_text(), required=True, coerce=dns.name.from_text,
                help_text='Usually it is sufficient to select the name itself (%s) or its zone, in which case cached values will be used for the analysis of any ancestor names (unless it is determined that they are out of date).  Occasionally it is useful to re-analyze some portion of the ancestry, in which case the desired ancestor can be selected.  However, the overall analysis will take longer.' % (fmt.humanize_name(name, True)))
        extra_types = forms.TypedMultipleChoiceField(choices=EXTRA_TYPES, initial=(), required=False, coerce=int,
                help_text='Select any extra RR types to query as part of this analysis.  A default set of types will already be queried based on the nature of the name, but any types selected here will assuredly be included.')
        explicit_delegation = forms.CharField(initial='', required=False, widget=forms.Textarea(attrs={'cols': 50, 'rows': 5}),
                help_text='If you wish to designate servers explicitly for the "force ancestor" zone (rather than following delegation from the IANA root), enter the server names, one per line.  You may optionally include an IPv4 or IPv6 address on the same line as the name.')

        def clean_explicit_delegation(self):
            s = self.cleaned_data['explicit_delegation']
            mappings = set()
            i = 1
            for line in s.splitlines():
                line = line.strip()
                if not line:
                    continue
                # get ride of extra columns
                cols = line.split()
                if len(cols) > 1:
                    line = '%s %s' % (cols[0], cols[-1])
                try:
                    name, addr = line.split()
                except ValueError:
                    # first see if it's a plain IP address
                    try:
                        addr = IPAddr(line.strip())
                    except ValueError:
                        # if not, then assign name to mapping
                        name = line
                        addr = None
                    else:
                        # if it's an IP with no name specified, then create
                        # a name
                        name = 'ns%d' % i
                        i += 1
                try:
                    name = dns.name.from_text(name)
                except:
                    raise forms.ValidationError('The domain name was invalid: "%s"' % name)

                # no address is provided, so query A/AAAA records for the name
                if addr is None:
                    query_tuples = ((name, dns.rdatatype.A, dns.rdataclass.IN), (name, dns.rdatatype.AAAA, dns.rdataclass.IN))
                    answer_map = resolver.query_multiple_for_answer(*query_tuples)
                    found_answer = False
                    for a in answer_map.values():
                        if isinstance(a, DNSAnswer):
                            found_answer = True
                            for a_rr in a.rrset:
                                mappings.add((name, IPAddr(a_rr.to_text())))
                        # negative responses
                        elif isinstance(a, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                            pass
                        # error responses
                        elif isinstance(a, (dns.exception.Timeout, dns.resolver.NoNameservers)):
                            raise forms.ValidationError('There was an error resolving "%s".  Please specify an address or use a name that resolves properly.' % fmt.humanize_name(name))

                    if not found_answer:
                        raise forms.ValidationError('"%s" did not resolve to an address.  Please specify an address or use a name that resolves properly.' % fmt.humanize_name(name))

                # otherwise, add the address
                else:
                    if addr and addr[0] == '[' and addr[-1] == ']':
                        addr = addr[1:-1]
                    try:
                        addr = IPAddr(addr)
                    except ValueError:
                        raise forms.ValidationError('The IP address was invalid: "%s"' % addr)
                    mappings.add((name, addr))

            # if there something in the box, yet no mappings resulted, then raise a
            # validation error
            if self.cleaned_data['explicit_delegation'] and not mappings:
                raise forms.ValidationError('Unable to process address records!')

            return mappings

    return DomainNameAnalysisForm

class CalendarWidget(forms.TextInput):
    def __init__(self, attrs={}):
        super(CalendarWidget, self).__init__(attrs={'class': 'datepicker', 'size': '10'})

def domain_date_search_form(name):
    class DomainDateSearchForm(forms.Form):
        date = forms.DateField(widget=CalendarWidget())

        def clean_date(self):
            dt = datetime.datetime(self.cleaned_data['date'].year, self.cleaned_data['date'].month, self.cleaned_data['date'].day, \
                    23, 59, 59, 999999, tzinfo=utc)
            self.name_obj = OfflineDomainNameAnalysis.objects.latest(name, dt)
            if self.name_obj is None:
                del self.name_obj
                raise forms.ValidationError('No analysis for %s known prior to %s!' % (fmt.humanize_name(name), self.cleaned_data['date']))
    return DomainDateSearchForm

def get_dnssec_options_form_data(data):
    values = {}

    dnssec_form_options = set(DNSSECOptionsForm.base_fields).intersection(set(data))
    if dnssec_form_options:
        options_form = DNSSECOptionsForm(data)
        if options_form.is_valid():
            values = options_form.cleaned_data.copy()
        else:
            for name, field in options_form.fields.items():
                if options_form[name].errors:
                    values[name] = field.initial
                else:
                    values[name] = options_form[name].data
            options_form2 = DNSSECOptionsForm(values)
            options_form2.is_valid()
            values = options_form2.cleaned_data.copy()

    else:
        options_form = DNSSECOptionsForm()
        for name, field in options_form.fields.items():
            values[name] = field.initial
        options_form = DNSSECOptionsForm(values)
        options_form.is_valid()
        values = options_form.cleaned_data.copy()

    return options_form, values
