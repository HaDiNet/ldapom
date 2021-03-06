# -*- coding: utf-8 -*-

from paver.easy import *

@task
def test(options):
    info("Running tests for Python 2")
    sh('python2 -m unittest -v tests')
    info("Running tests for Python 3")
    sh('python3 -m unittest -v tests')

@task
def coverage(options):
    info("Running coverage for Python 2")
    sh('coverage2 run --source ldapom ./tests.py')
    sh('coverage2 report')
    info("Running coverage for Python 3")
    sh('coverage3 run --source ldapom ./tests.py')
    sh('coverage3 report')
