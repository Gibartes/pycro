#!/usr/bin/env python

from distutils.core import setup

setup(name='Pycro',
      version='1.0',
      description='Macro Program',
      author='Croniel Kwon',
      author_email='konm2000@naver.com',
      url='None',
      packages=[],
      install_requires=['PyQt5', 'pyscreenshot','pynput','rsa','pycrypto','setproctitle','cryptography'],
      scripts=[		'proc/start.py',
					'proc/processor.py',
					'proc/preprocessor.py',
					'proc/cohandler.py',
					'proc/dtype.py',
					'proc/gui.py'],
     )
