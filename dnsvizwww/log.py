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

import logging
import Queue

from django.utils.html import escape

class QueueForIteratorHandler(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.queue = Queue.Queue()

    def __iter__(self):
        while True:
            try:
                s = self.queue.get(True)
                if s == '':
                    raise StopIteration
                yield s
            except Queue.Empty:
                raise StopIteration

    def emit(self, record):
        if record.levelno == logging.DEBUG and record.getMessage() == '<EOF>':
            s = ''
        else:
            s = self.format(record)
        self.queue.put(s)

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return '{"type":"logmessage","level":"%s","message":"%s"}\r\n' % (record.levelname.lower(), escape(record.getMessage()))

class IsolatedLogger(object):
    def __init__(self, loglevel):
        # initialize a new manager with an instantiation of a custom Logger
        # instance
        class _IsolatedLogger(logging.Logger):
            pass
        self.logger = logging.RootLogger(loglevel)
        _IsolatedLogger.root = self.logger
        _IsolatedLogger.manager = logging.Manager(self.logger)

        self.handler = QueueForIteratorHandler()
        self.handler.setFormatter(JSONFormatter())
        self.handler.setLevel(loglevel)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(loglevel)

    def close(self):
        self.logger.debug('<EOF>')
