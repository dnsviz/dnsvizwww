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

import base64
from cgi import escape
import struct
import urllib

import dns.dnssec, dns.name, dns.rdatatype, dns.rdataclass

import dnsviz.format as fmt

def datetime_url_encode(dt):
    timestamp = int(fmt.datetime_to_timestamp(dt))
    return base64.urlsafe_b64encode(struct.pack('!L',int(timestamp)))[:-2]

def datetime_url_decode(timestamp):
    timestamp = struct.unpack('!L', base64.urlsafe_b64decode(str(timestamp+'==')))[0]
    return fmt.timestamp_to_datetime(timestamp)

def name_url_encode(name):
    if name == dns.name.root:
        return 'root'
    return urllib.quote(name.canonicalize().to_text().rstrip('.').replace('/', 'S'), safe='')

def name_url_decode(name):
    if name == 'root':
        return dns.name.root
    return dns.name.from_text(name.replace('S', '/'), dns.name.root)

def rr_to_html(name, rdclass, rdtype, ttl, rdata):
    s = '<tr class="rr"><td>%s</td><td>%d</td><td>%s</td><td>%s</td><td>' % (name, ttl, dns.rdataclass.to_text(rdclass), dns.rdatatype.to_text(rdtype))
    if rdtype == dns.rdatatype.DNSKEY:
        flags = [desc for desc, val in DNSKEY_FLAGS.items() if val & rdata.flags]
        if rdata.protocol == 3:
            protocol = 'DNSSEC'
        else:
            protocol = rdata.protocol
        s += '<abbr title="Flags: %s">%d</abbr> <abbr title="Protocol: %s">%d</abbr> <abbr title="Algorithm: %s">%d</abbr> <abbr title="Key:">%s</abbr> ; id = %d' % \
                (' '.join(flags), rdata.flags, protocol, rdata.protocol, dns.dnssec.algorithm_to_text(rdata.algorithm), rdata.algorithm, base64.b64encode(rdata.key), dnssec.key_tag(rdata))
    else:
        s += escape(rdata.to_text(), quote=True)
    s += '</td></tr>'
    return s

def target_for_rrset(rrset, section, rdata=None):
    target = '%s-%s-%d' % (section.lower()[:3], humanize_name(rrset.name), rrset.rdtype)
    if rrset.rdtype == dns.rdatatype.RRSIG:
        target += '-%d' % rrset.covers
    if rdata:
        m = hashlib.md5()
        m.update(rdata.to_text())
        target += '-%s' % m.hexdigest()
    return target
