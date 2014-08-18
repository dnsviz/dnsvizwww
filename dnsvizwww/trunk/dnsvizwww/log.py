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

import logging
import Queue

from django.conf import settings
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

class HTMLFormatter(logging.Formatter):
    def format(self, record):
        return '<div class="loglevel-%s">%s</div>' % (record.levelname.lower(), escape(record.getMessage()))

class IsolatedLogger(object):
    def __init__(self, loglevel, external_logger, exc_message):
        # initialize a new manager with an instantiation of a custom Logger
        # instance
        class _IsolatedLogger(logging.Logger):
            pass
        self.logger = logging.RootLogger(loglevel)
        _IsolatedLogger.root = self.logger
        _IsolatedLogger.manager = logging.Manager(self.logger)

        self.handler = QueueForIteratorHandler()
        self.handler.setFormatter(HTMLFormatter())
        self.handler.setLevel(loglevel)
        self.logger.addHandler(self.handler)
        self.logger.setLevel(loglevel)

        self.external_logger = external_logger
        self.exc_message = exc_message

    def success_callback(self, result):
        self.logger.info('Success!')
        self.close()

    def exc_callback(self, exc_info):
        self.logger.error(self.exc_message)
        self.external_logger.error(self.exc_message, exc_info=exc_info)
        self.close()

    def close(self):
        self.logger.debug('<EOF>')

class RequireDebugTrue(logging.Filter):
    def filter(self, record):
        return settings.DEBUG
