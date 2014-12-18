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

import datetime
import random
import time

import dns.rdatatype

from django.db import DatabaseError, transaction

import dnsviz.analysis
import dnsviz.format as fmt
from models import DomainName, DomainNameAnalysis

MIN_ANALYSIS_INTERVAL = 14400
MAX_ANALYSIS_TIME = 300

class Analyst(dnsviz.analysis.Analyst):
    qname_only = False
    analysis_model = DomainNameAnalysis

    clone_attrnames = dnsviz.analysis.Analyst.clone_attrnames + ['force_ancestry','start_time']

    def __init__(self, *args, **kwargs):
        self.start_time = kwargs.pop('start_time', datetime.datetime.now(fmt.utc).replace(microsecond=0))
        self.force_ancestry = kwargs.pop('force_ancestry', False)
        self.force_self = kwargs.pop('force_self', True)
        super(Analyst, self).__init__(*args, **kwargs)

    def _analyze_dlv(self):
        if self.dlv_domain is not None and self.dlv_domain != self.name and self.dlv_domain not in self.analysis_cache:
            kwargs = dict([(n, getattr(self, n)) for n in self.clone_attrnames])
            a = self.__class__(self.dlv_domain, force_self=False, **kwargs)
            a.ceiling = self.dlv_domain
            a.analyze()

    def unsaved_dependencies(self, name_obj, trace=None):
        if trace is None:
            trace = []

        unsaved_names = []
        if name_obj.name in trace:
            return unsaved_names
        
        for cname in name_obj.cname_targets:
            for target, cname_obj in name_obj.cname_targets[cname].items():
                if cname_obj is None or cname_obj.pk is None:
                    unsaved_names.append(target)
                    if cname_obj is not None:
                        unsaved_names.extend(self.unsaved_dependencies(cname_obj, trace+[name_obj.name]))
        for signer, signer_obj in name_obj.external_signers.items():
            if signer_obj is None or signer_obj.pk is None:
                unsaved_names.append(signer)
                if signer_obj is not None:
                    unsaved_names.extend(self.unsaved_dependencies(signer_obj, trace+[name_obj.name]))
        if self.follow_ns:
            for target, ns_obj in name_obj.ns_dependencies.items():
                if ns_obj is None or ns_obj.pk is None:
                    unsaved_names.append(target)
                    if ns_obj is not None:
                        unsaved_names.extend(self.unsaved_dependencies(ns_obj, trace+[name_obj.name]))

        return unsaved_names

    def _finalize_analysis_all(self, name_obj):
        name_obj.dep_analysis_end = datetime.datetime.now(fmt.utc).replace(microsecond=0)
        self._save_analysis(name_obj)
        super(Analyst, self)._finalize_analysis_all(name_obj)

    def _cleanup_analysis_all(self, name_obj):
        # release the lock on the name
        DomainName.objects.filter(name=name_obj.name).update(analysis_start=None)

    def _save_analysis(self, name_obj):

        # if this object has already been saved (e.g., it might have been
        # retrieved from the database), then no need to save it.
        if name_obj.pk is not None:
            return

        # whether this object is the nxdomain_ancestor of the name in question
        is_nxdomain_ancestor = \
                name_obj.nxdomain_ancestor is None and \
                name_obj.referral_rdtype is not None and \
                name_obj.queries[(name_obj.name, name_obj.referral_rdtype)].is_nxdomain_all()

        if not (name_obj.ttl_mapping or \
                name_obj.name == self.name or \
                name_obj.name in self._cname_chain or \
                (self._ask_tlsa_queries(self.name) and len(name_obj.name) == len(self.name) - 2) or \
                is_nxdomain_ancestor):
            return

        # check for cyclic dependencies.  if there are no unsaved
        # dependencies in the trace (which will cause everything to be
        # saved in a single transaction) then go ahead and save.
        unsaved_deps = self.unsaved_dependencies(name_obj)
        names_in_trace = [n.name for n,r in self.trace]
        unsaved_dep_in_trace = False
        for dep in unsaved_deps:
            if dep in names_in_trace:
                unsaved_dep_in_trace = True
        if not unsaved_dep_in_trace:
            attempts = 0
            while True:
                attempts += 1
                with transaction.commit_manually():
                    try:
                        name_obj.save_all()
                    except Exception, e:
                        transaction.rollback()
                        # retry if this is a database error and we tried
                        # less than three times
                        if isinstance(e, DatabaseError) and attempts <= 2:
                            pass
                        else:
                            raise
                    else:
                        transaction.commit()
                        break
                time.sleep(random.randint(1,2000)/1000.0)
                
        self.analysis_cache[name_obj.name] = name_obj

        super(Analyst, self)._analyze_dependencies(name_obj)

    def _get_name_for_analysis(self, name, stub=False, lock=True):
        with self.analysis_cache_lock:
            try:
                name_obj = self.analysis_cache[name]
                wait_for_analysis = True
            except KeyError:
                if lock:
                    name_obj = self.analysis_cache[name] = self.analysis_model(name, stub=stub)
                wait_for_analysis = False

        # name is now locked locally (for threads that use analysis_cache) but
        # now we lock it across the database
        if not wait_for_analysis:
            while True:
                # if stub, then we don't care if the previous one was stub or
                # not.
                if stub:
                    f_stub = None
                else:
                    f_stub = False
                # retrieve the freshest DomainNameAnalysis from the DB
                fresh_name_obj = self.analysis_model.objects.latest(name, stub=f_stub)

                # if no analysis is necessary
                if not self._analyze_or_not(fresh_name_obj):

                    # The first check is to determine whether the name needs to
                    # be analyzed, without having to retrieve related information.
                    # Having gotten this far, we pull responses and check again
                    # before determining whether analysis is necessary or not.
                    fresh_name_obj.retrieve_ancestry(fresh_name_obj.RDTYPES_SECURE_DELEGATION, follow_dependencies=False)
                    level = fresh_name_obj.RDTYPES_SECURE_DELEGATION
                    if self.name == name:
                        if self._is_referral_of_type(dns.rdatatype.CNAME):
                            level = fresh_name_obj.RDTYPES_ALL_SAME_NAME
                        elif self._is_referral_of_type(dns.rdatatype.NS):
                            level = fresh_name_obj.RDTYPES_NS_TARGET
                    fresh_name_obj.retrieve_related(level)

                    if not self._analyze_or_not(fresh_name_obj):
                        if level <= fresh_name_obj.RDTYPES_NS_TARGET:
                            fresh_name_obj.retrieve_dependencies()
                        fresh_name_obj._populate_name_status(level)
                        self.analysis_cache[name] = fresh_name_obj
                        return fresh_name_obj

                # if not locking, then return None
                if not lock:
                    return None

                # get the name (or create it)
                dname_obj = DomainName.objects.get_or_create(name=name)[0]
                now = datetime.datetime.now(fmt.utc).replace(microsecond=0)

                attempt_lock = True
                # determine if there is an analysis for this name in progress
                if dname_obj.analysis_start is not None:
                    # if this analysis has been updated, then clean up the lock
                    if fresh_name_obj is not None and fresh_name_obj.analysis_start >= dname_obj.analysis_start:
                        pass
                    # if this analysis has gone stale, then reset it
                    elif now - dname_obj.analysis_start > datetime.timedelta(seconds=MAX_ANALYSIS_TIME):
                        pass
                    else:
                        attempt_lock = False

                # if there is no analysis, then attempt to get the lock for the name.
                # if lock was obtained, then return the name_obj
                if attempt_lock and DomainName.objects.filter(pk=dname_obj.pk, analysis_start=dname_obj.analysis_start).update(analysis_start=now):
                    return name_obj

                time.sleep(3)

        else:
            while name_obj.analysis_end is None:
                time.sleep(1)

            #TODO re-do analyses if force_dnskey is True and dnskey hasn't been queried
            #TODO re-do anaysis if not stub requested but cache is stub?
        return name_obj

    def _analyze_or_not(self, name_obj):
        if name_obj is None:
            return True

        # If force and analysis has not been performed since reference time,
        # then return True.
        force_analysis = self.force_self and (self.force_ancestry or self.name == name_obj.name or filter(lambda x: name_obj.name.is_subdomain(x), self._cname_chain))
        updated_since_analysis_start = name_obj.analysis_end >= self.start_time
        if force_analysis and not updated_since_analysis_start:
            return True

        now = datetime.datetime.now(fmt.utc).replace(microsecond=0)

        # If min TTL of pertinent RRsets has elapsed since last analysis
        # (considering MIN_ANALYSIS_INTERVAL), then return True
        min_ttl = name_obj.min_ttl(dns.rdatatype.NS, -dns.rdatatype.NS, dns.rdatatype.DS, dns.rdatatype.DNSKEY)
        if min_ttl is None or min_ttl < MIN_ANALYSIS_INTERVAL:
            min_ttl = MIN_ANALYSIS_INTERVAL
        time_since_analysis = now - name_obj.analysis_end
        maximum_time_allowed = datetime.timedelta(seconds=max(min_ttl, MIN_ANALYSIS_INTERVAL))
        analysis_due = time_since_analysis > maximum_time_allowed
        if time_since_analysis > maximum_time_allowed:
            return True

        # If RRSIG is expiring (or will expire in cache) since last analysis
        # end, then return True
        earliest_rrsig_expiration = name_obj.earliest_rrsig_expiration(dns.rdatatype.DS, dns.rdatatype.DNSKEY)
        if earliest_rrsig_expiration is not None and \
                name_obj.analysis_end <= earliest_rrsig_expiration <= now:
            return True

        # If the contents of pertinent RRsets have changed since last analysis,
        # then return True
        for rdtype in (dns.rdatatype.NS, dns.rdatatype.DS, dns.rdatatype.DNSKEY):
            if (name_obj.name, rdtype) in name_obj.queries and \
                    name_obj.rrset_has_changed(rdtype):
                return True

        # If not all queries were included in the last analysis, then
        # return True.
        rdtypes_to_query = self._rdtypes_to_query(name_obj.name)
        rdtypes_queried = name_obj.rdtypes_queried()
        if set(rdtypes_to_query).difference(rdtypes_queried) and self.dlv_domain != name_obj.name:
            return True

        return False
