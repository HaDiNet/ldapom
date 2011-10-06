from paver.easy import task, sh

@task
def docs(options):
    sh('doxygen')
