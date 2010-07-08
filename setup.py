import os
from distutils.core import setup

readme = open(os.path.join(os.path.dirname(__file__), 'README'))
README = readme.read()
readme.close()

version = __import__('odesk').get_version()


setup(name='python-odesk',
      version=version,
      description='Python bindings to oDesk API',
      long_description=README,
      author='oDesk',
      author_email='python@odesk.com',
      maintainer='Volodymyr Hotsyk',
      maintainer_email='gotsyk@gmail.com',      
      packages = ['odesk',],
      license = 'BSD',
      download_url ='http://github.com/odesk/python-odesk',
      url='http://github.com/odesk/python-odesk',
      classifiers=['Development Status :: 3 - Alpha',
                   'Environment :: Web Environment',
                   'Intended Audience :: Developers',
                   'License :: OSI Approved :: BSD License',
                   'Operating System :: OS Independent',
                   'Programming Language :: Python',
                   'Topic :: Software Development :: Libraries :: Python Modules',
                   'Topic :: Utilities',],)