#
# This file is a part of DNSViz, a tool suite for DNS/DNSSEC monitoring,
# analysis, and visualization.
# Author: Casey Deccio (casey@deccio.net)
#
# Copyright 2012-2014 Verisign, Inc.
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

import dnsviz.status as Status

_rrset_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<rdtype>[A-Z]+)')
_dnskey_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)')
_ds_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|\d+(_\d+)*')
_nsec_node_re = re.compile(r'^(?P<name>[^|]+)\|(?P<rdtype>[A-Z]+)')
_node_re = re.compile(r'^(?P<node_type>RRset|DNSKEY|DS|NSEC3?)-(?P<id>\d+(_\d+)*)\|(?P<remnant>.*)')

_digest_re = re.compile(r'DS-(?P<id>\d+(_\d+)*)\|(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|\d+(_\d+)*\|([a-fA-F0-9]+)\|[a-z]+$')
_rrsig_dnskey_re = re.compile(r'DNSKEY-\d+\|(?P<name>[^|]+)\|(?P<alg>\d+)\|(?P<key_tag>\d+)\|([a-fA-F0-9]+)\|[a-z]+$')
_dname_re = re.compile(r'^RRset-\d+\|(?P<name>[^|]+)\|(?P<rdtype>[A-Z]+)')
_nsecc_re = re.compile(r'(?P<type>NSEC3?)-\d+\|(?P<name>[^\|]+)\|(?P<rdtype>[A-Z]+)$')
_del_re = re.compile(r'^(?P<child>[^|]+)\|(?P<parent>[^|]+)$')
_edge_re = re.compile(r'^(?P<node_type>digest|RRSIG|dname|NSEC3?C|del)-(?P<remnant>.*)$')

def _init_notices():
    return collections.OrderedDict((
        ('RRset status', collections.OrderedDict((
            (Status.rrset_status_mapping[Status.RRSET_STATUS_BOGUS], []),
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
            l = '%s/%s' % (dns.name.from_text(m2.group('name')).to_unicode(), m2.group('rdtype'))
            if m1.group('id') == '0':
                l += ' (NXDOMAIN)'
            elif m1.group('id') == '1':
                l += ' (NO DATA)'
            bisect.insort(notices['RRset status'][val[0]['status']],l)
        elif t1 == 'DNSKEY':
            m2 = _dnskey_node_re.search(m1.group('remnant'))
            l = '%s/DNSKEY (alg %s, id %s)' % (dns.name.from_text(m2.group('name')).to_unicode(), m2.group('alg'), m2.group('key_tag'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
        elif t1 in ('DS','DLV'):
            m2 = _ds_node_re.search(m1.group('remnant'))
            l = '%s/%s (alg %s, id %s)' % (dns.name.from_text(m2.group('name')).to_unicode(), t1, m2.group('alg'), m2.group('key_tag'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
        elif t1.startswith('NSEC'):
            m2 = _nsec_node_re.search(m1.group('remnant'))
            l = '%s proving non-existence of %s/%s' % (t1, dns.name.from_text(m2.group('name')).to_unicode(), m2.group('rdtype'))
            bisect.insort(notices['DNSKEY/DS/NSEC status'][val[0]['status']],l)
    else:
        m1 = _edge_re.search(node_name)
        if m1 is not None:
            t1 = m1.group('node_type')
            if t1 == 'del':
                m2 = _del_re.search(m1.group('remnant'))
                l = '%s to %s' % (dns.name.from_text(m2.group('parent')).to_unicode(), dns.name.from_text(m2.group('child')).to_unicode())
                bisect.insort(notices['delegation status'][val[0]['status']],l)
            elif t1 == 'digest':
                m2 = _digest_re.search(m1.group('remnant'))
                l = '%s/DS (alg %s, id %s)' % (dns.name.from_text(m2.group('name')).to_unicode(), m2.group('alg'), m2.group('key_tag'))
            elif t1 == 'RRSIG':
                m2 = _node_re.search(m1.group('remnant'))
                m3 = _rrsig_dnskey_re.search(m2.group('remnant'))
                dnskey_str = 'alg %s, id %s' % (m3.group('alg'), m3.group('key_tag'))
                t2 = m2.group('node_type')
                if t2 == 'RRset':
                    m3 = _rrset_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/%s %s' % (dns.name.from_text(m3.group('name')).to_unicode(), m3.group('rdtype'), dnskey_str)
                elif t2 == 'DNSKEY':
                    m3 = _dnskey_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/DNSKEY %s' % (dns.name.from_text(m3.group('name')).to_unicode(), dnskey_str)
                elif t2 in ('DS','DLV'):
                    m3 = _ds_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s/%s %s' % (dns.name.from_text(m3.group('name')).to_unicode(), t2, dnskey_str)
                elif t2.startswith('NSEC'):
                    m3 = _nsec_node_re.search(m2.group('remnant'))
                    l = 'RRSIG %s proving non-existence of %s/%s %s' % (t2, dns.name.from_text(m3.group('name')).to_unicode(), m3.group('rdtype'), dnskey_str)
            elif t1.startswith('NSEC'):
                m2 = _nsecc_re.search(m1.group('remnant'))
                l = '%s proving non-existence of %s/%s' % (m2.group('type'), dns.name.from_text(m2.group('name')).to_unicode(), m2.group('rdtype'))
            elif t1 == 'dname':
                m2 = _dname_re.search(m1.group('remnant'))
                l = 'CNAME synthesis of %s' % (dns.name.from_text(m2.group('name')).to_unicode())
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
                        if isinstance(val, dict):
                            servers = list(val[e])
                            servers.sort()
                            bisect.insort(notices['notices'][node_name], '%s: %s (%s)' % (l, e, ', '.join(servers)))
                        else:
                            bisect.insort(notices['notices'][node_name], '%s: %s' % (l, e))
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
