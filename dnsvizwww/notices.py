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

import bisect
import collections
import json
import re

import dns.name

from dnsviz.analysis import status as Status
import dnsviz.format as fmt

_rrset_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<rdtype>[A-Z0-9]+)')
_dnskey_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)')
_ds_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|\d+(_\d+)*')
_nsec_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<rdtype>[A-Z0-9]+)')
_node_re = re.compile(r'^(?P<node_type>RRset|DNSKEY|DS|DLV|NSEC3?)-(?P<id>\d+(_\d+)*)\|(?P<remnant>.*)')

_digest_re = re.compile(r'(?P<type>DS|DLV)-(?P<id>\d+(_\d+)*)\|(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|\d+(_\d+)*\|([a-fA-F0-9]+)\|[a-z]+$')
_rrsig_dnskey_re = re.compile(r'DNSKEY-\d+\|(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|([a-fA-F0-9]+)\|[a-z]+')
_dname_re = re.compile(r'^RRset-\d+\|(?P<name>[^|]+)\|(?P<rdtype>[A-Z0-9]+)')
_nsecc_re = re.compile(r'(?P<type>NSEC3?)-\d+\|(?P<name>[^\|]+)\|(?P<rdtype>[A-Z0-9]+)$')
_del_re = re.compile(r'^(?P<child>[^|]+)\|(?P<parent>[^|]+)$')
_edge_re = re.compile(r'^(?P<node_type>digest|RRSIG|dname|NSEC3?C|del)-(?P<remnant>.*)$')
_zone_re = re.compile(r'^cluster_(?P<name>.+)_top$')

def _init_notices():
    return collections.OrderedDict((
        ('RRset status', collections.OrderedDict((
            (Status.rrset_status_mapping[Status.RRSET_STATUS_BOGUS], []),
            ('ERROR', []),
            ('WARNING', []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_INSECURE], []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_SECURE], []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_NON_EXISTENT], []),
        ))),
        ('DNSKEY/DS/NSEC status', collections.OrderedDict((
            (Status.rrset_status_mapping[Status.RRSET_STATUS_BOGUS], []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_INSECURE], []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_SECURE], []),
            (Status.rrset_status_mapping[Status.RRSET_STATUS_NON_EXISTENT], []),
        ))),
        ('delegation status', collections.OrderedDict((
            (Status.delegation_status_mapping[Status.DELEGATION_STATUS_BOGUS], []),
            (Status.delegation_status_mapping[Status.DELEGATION_STATUS_LAME], []),
            (Status.delegation_status_mapping[Status.DELEGATION_STATUS_INCOMPLETE], []),
            (Status.delegation_status_mapping[Status.DELEGATION_STATUS_INSECURE], []),
            (Status.delegation_status_mapping[Status.DELEGATION_STATUS_SECURE], []),
        ))),
        ('notices', collections.OrderedDict((
            ('errors', []),
            ('warnings', []),
        ))),
    ))

def _get_label_for_node(notices, node_name, val):
    l = None
    m1 = _node_re.search(node_name)
    if m1 is not None:
        t1 = m1.group('node_type')
        #TODO sort keys by dns name (i.e., not simply by textual name)
        if t1 == 'RRset':
            m2 = _rrset_node_re.search(m1.group('remnant'))
            l = '%s/%s' % (fmt.humanize_name(dns.name.from_text(m2.group('name')), True), m2.group('rdtype'))
            if m1.group('id') == '0':
                l += ' (NXDOMAIN)'
            elif m1.group('id') == '1':
                l += ' (NODATA)'
            if m1.group('id') not in ('2', '3'):
                bisect.insort(notices['RRset status'][val[0]['status']],l)
        elif t1 == 'DNSKEY':
            m2 = _dnskey_node_re.search(m1.group('remnant'))
            l = '%s/DNSKEY (alg %s, id %s)' % (fmt.humanize_name(dns.name.from_text(m2.group('name')), True), m2.group('alg'), m2.group('key_tag'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
        elif t1 in ('DS','DLV'):
            m2 = _ds_node_re.search(m1.group('remnant'))
            l = '%s/%s (alg %s, id %s)' % (fmt.humanize_name(dns.name.from_text(m2.group('name')), True), t1, m2.group('alg'), m2.group('key_tag'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
        elif t1.startswith('NSEC'):
            m2 = _nsec_node_re.search(m1.group('remnant'))
            l = '%s proving non-existence of %s/%s' % (t1, fmt.humanize_name(dns.name.from_text(m2.group('name')), True), m2.group('rdtype'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
    else:
        m1 = _edge_re.search(node_name)
        if m1 is not None:
            t1 = m1.group('node_type')
            if t1 == 'del':
                m2 = _del_re.search(m1.group('remnant'))
                l = '%s to %s' % (fmt.humanize_name(dns.name.from_text(m2.group('parent')), True), fmt.humanize_name(dns.name.from_text(m2.group('child')), True))
                bisect.insort(notices['delegation status'][val[0]['status']],l)
            elif t1 == 'digest':
                m2 = _digest_re.search(m1.group('remnant'))
                l = '%s/%s (alg %s, id %s)' % (fmt.humanize_name(dns.name.from_text(m2.group('name')), True), m2.group('type'), m2.group('alg'), m2.group('key_tag'))
            elif t1 == 'RRSIG':
                m2 = _node_re.search(m1.group('remnant'))
                m3 = _rrsig_dnskey_re.search(m2.group('remnant'))
                dnskey_str = 'alg %s, id %s' % (m3.group('alg'), m3.group('key_tag'))
                t2 = m2.group('node_type')
                if t2 == 'RRset':
                    m3 = _rrset_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/%s %s' % (fmt.humanize_name(dns.name.from_text(m3.group('name')), True), m3.group('rdtype'), dnskey_str)
                elif t2 == 'DNSKEY':
                    m3 = _dnskey_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/DNSKEY %s' % (fmt.humanize_name(dns.name.from_text(m3.group('name')), True), dnskey_str)
                elif t2 in ('DS','DLV'):
                    m3 = _ds_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/%s %s' % (fmt.humanize_name(dns.name.from_text(m3.group('name')), True), t2, dnskey_str)
                elif t2.startswith('NSEC'):
                    m3 = _nsec_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s proving non-existence of %s/%s %s' % (t2, fmt.humanize_name(dns.name.from_text(m3.group('name')), True), m3.group('rdtype'), dnskey_str)
            elif t1.startswith('NSEC'):
                m2 = _nsecc_re.search(m1.group('remnant'))
                l = '%s proving non-existence of %s/%s' % (m2.group('type'), fmt.humanize_name(dns.name.from_text(m2.group('name')), True), m2.group('rdtype'))
            elif t1 == 'dname':
                m2 = _dname_re.search(m1.group('remnant'))
                l = 'CNAME synthesis of %s' % (fmt.humanize_name(dns.name.from_text(m2.group('name')), True))
        else:
            m1 = _zone_re.search(node_name)
            if m1 is not None:
                l = '%s zone' % (fmt.humanize_name(dns.name.from_text(m1.group('name')), True))

    return l

def _populate_notices(notices, obj, label=None):
    if isinstance(obj, dict):
        for node_name, val in obj.items():
            if label is None:
                l = _get_label_for_node(notices, node_name, val)
            else:
                l = label
                if node_name in ('errors', 'warnings'):
                    for e in val:
                        description = e['description']
                        servers_tags = []
                        if 'servers' in e:
                            servers_tags += e['servers']
                        if 'query_options' in e:
                            servers_tags += e['query_options']
                        if servers_tags:
                            description += ' (%s)' % (', '.join(servers_tags))
                        bisect.insort(notices['notices'][node_name], '%s: %s' % (l, description))
            _populate_notices(notices, val, l)
    elif isinstance(obj, (list, tuple, set)):
        if label is not None:
            for val in obj:
                _populate_notices(notices, val, label)

def _clean_notices(notices):
    if not notices['notices']['errors']: del notices['notices']['errors']
    if not notices['notices']['warnings']: del notices['notices']['warnings']

def get_notices(node_info):
    notices = _init_notices()
    _populate_notices(notices, node_info)
    _clean_notices(notices)
    return notices

def notices_to_javascript(notices):
    s = 'AuthGraph.prototype.postNotices = function (noticesElement, mediaURL) {\n'
    s += '\tvar notices = %s;\n' % json.dumps(notices)
    s += '''\tif (noticesElement.nodeType != 1) {
		noticesElement = document.getElementById(noticesElement);
	}
	var s = '';
	function isEmpty(map) {
	    for(var key in map) {
	        if (map.hasOwnProperty(key)) {
		        return false;
		    }
        }
        return true;
    }
	for (var cat in notices) {
		var subcat_list = notices[cat];
		if (isEmpty(subcat_list)) {
			continue;
		}
		s += '<div class="notice-category">';
		s += '<h4><img src="' + mediaURL + this.slugify(cat) + '.png" alt="' + cat.charAt(0).toUpperCase() + cat.slice(1) + '" class="header-icon" />' + cat.charAt(0).toUpperCase() + cat.slice(1) + '</h4>';
		for (var subcat in subcat_list) {
			var items = subcat_list[subcat];
            if (!items.length) {
                continue;
            }
			s += '<div class="' + this.slugify(subcat.toLowerCase()) + '">';
			s += '<h5>' + subcat.charAt(0).toUpperCase() + subcat.toLowerCase().slice(1) + ' <span class="count">(' + items.length + ')</span></h5>';
			s += '<div><ul>';
			for (var itemIndex = 0; itemIndex < items.length; itemIndex++) {
                s += '<li>' + items[itemIndex] + '</li>';
			}
			s += '</ul></div></div>';
		}
		s += '</div>';
	}
	$(s).prependTo(noticesElement);
}
'''
    return s
