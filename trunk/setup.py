#!/usr/bin/env python

import glob
import os
import sys

from distutils.core import setup

setup(name='dnsvizwww',
        version='0.1.0',
        author='Casey Deccio',
        author_email='casey@deccio.net',
        url='https://code.google.com/p/dnsviz/',
        description='DNS analysis and visualization tool suite - Web and database components',
        long_description=open('README', 'r').read(),
        license='COPYING',
        packages=['dnsvizwww'],
        data_files=[
                ('share/doc/dnsvizwww', ['README', 'COPYING']),
                ('share/dnsvizwww/static/css', glob.glob(os.path.join('dnsvizwww', 'static', 'css', '*.css'))),
                ('share/dnsvizwww/static/css/redmond', ['dnsvizwww/static/css/redmond/jquery-ui-1.10.4.custom.min.css']),
                ('share/dnsvizwww/static/css/redmond/images', glob.glob(os.path.join('dnsvizwww', 'static', 'css', 'redmond', 'images', '*.png')) + glob.glob(os.path.join('dnsvizwww', 'static', 'css', 'redmond', 'images', '*.gif'))),
                ('share/dnsvizwww/static/images', glob.glob(os.path.join('dnsvizwww', 'static', 'images', '*.png')) + glob.glob(os.path.join('dnsvizwww', 'static', 'images', '*.gif'))),
                ('share/dnsvizwww/static/images', ['dnsvizwww/static/images/favicon.ico']),
                ('share/dnsvizwww/static/images/dnssec_legend', glob.glob(os.path.join('dnsvizwww', 'static', 'images', 'dnssec_legend', '*.png'))),
                ('share/dnsvizwww/static/js', glob.glob(os.path.join('dnsvizwww', 'static', 'js', '*.js'))),
                ('share/dnsvizwww/templates', glob.glob(os.path.join('dnsvizwww', 'templates', '*.html'))),
        ],
        requires=[
                'dnsviz (==0.1.0)',
        ],
)
