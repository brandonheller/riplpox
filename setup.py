#!/usr/bin/env python
'''Setuptools params'''

from setuptools import setup, find_packages

setup(
    name='riplpox',
    version='0.0.0',
    description='A simple OpenFlow-based data center network controller',
    author='Brandon Heller',
    author_email='brandonh@stanford.edu',
    packages=find_packages(exclude='test'),
    long_description="""\
Insert longer description here.
      """,
      classifiers=[
          "License :: OSI Approved :: GNU General Public License (GPL)",
          "Programming Language :: Python",
          "Development Status :: 4 - Beta",
          "Intended Audience :: Developers",
          "Topic :: Internet",
      ],
      keywords='networking protocol Internet OpenFlow data center datacenter',
      license='GPL',
      install_requires=[
        'setuptools',
        'networkx'
      ])
