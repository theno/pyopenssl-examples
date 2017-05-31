# -*- coding: utf-8 -*-

import inspect
from functools import wraps
from os.path import dirname

from fabric.api import local, task as fabric_task
from fabric.context_managers import hide, quiet, warn_only


# inspired by: http://stackoverflow.com/a/6618825
def flo(string):
    '''Return the string given by param formatted with the callers locals.'''
    callers_locals = {}
    frame = inspect.currentframe()
    try:
        outerframe = frame.f_back
        callers_locals = outerframe.f_locals
    finally:
        del frame
    return string.format(**callers_locals)


def _wrap_with(color_code):
    '''Color wrapper.
    Example:
        >>> blue = _wrap_with('34')
        >>> print(blue('text'))
        \033[34mtext\033[0m
    '''
    def inner(text, bold=False):
        '''Inner color function.'''
        code = color_code
        if bold:
            code = flo("1;{code}")
        return flo('\033[{code}m{text}\033[0m')
    return inner


black = _wrap_with('30')
red = _wrap_with('31')
green = _wrap_with('32')
yellow = _wrap_with('33')
blue = _wrap_with('34')
magenta = _wrap_with('35')
cyan = _wrap_with('36')
white = _wrap_with('37')
default_color = _wrap_with('0')


def first_paragraph(multiline_str, without_trailing_dot=True, maxlength=None):
    '''Return first paragraph of multiline_str as a oneliner.
    When without_trailing_dot is True, the last char of the first paragraph
    will be removed, if it is a dot ('.').
    Examples:
        >>> multiline_str = 'first line\\nsecond line\\n\\nnext paragraph'
        >>> print(first_paragraph(multiline_str))
        first line second line
        >>> multiline_str = 'first \\n second \\n  \\n next paragraph '
        >>> print(first_paragraph(multiline_str))
        first second
        >>> multiline_str = 'first line\\nsecond line\\n\\nnext paragraph'
        >>> print(first_paragraph(multiline_str, maxlength=3))
        fir
        >>> multiline_str = 'first line\\nsecond line\\n\\nnext paragraph'
        >>> print(first_paragraph(multiline_str, maxlength=78))
        first line second line
        >>> multiline_str = 'first line.'
        >>> print(first_paragraph(multiline_str))
        first line
        >>> multiline_str = 'first line.'
        >>> print(first_paragraph(multiline_str, without_trailing_dot=False))
        first line.
        >>> multiline_str = ''
        >>> print(first_paragraph(multiline_str))
        <BLANKLINE>
    '''
    stripped = '\n'.join([line.strip() for line in multiline_str.splitlines()])
    paragraph = stripped.split('\n\n')[0]
    res = paragraph.replace('\n', ' ')
    if without_trailing_dot:
        res = res.rsplit('.', 1)[0]
    if maxlength:
        res = res[0:maxlength]
    return res


# for decorator with arguments see: http://stackoverflow.com/a/5929165
def print_doc1(*args, **kwargs):
    '''Print the first paragraph of the docstring of the decorated function.
    The paragraph will be printed as a oneliner.
    May be invoked as a simple, argument-less decorator (i.e. ``@print_doc1``)
    or with named arguments ``color``, ``bold``, ``prefix`` of ``tail``
    (eg. ``@print_doc1(color=utils.red, bold=True, prefix=' ')``).
    Examples:
        >>> @print_doc1
        ... def foo():
        ...     """First line of docstring.
        ...
        ...     another line.
        ...     """
        ...     pass
        ...
        >>> foo()
        \033[34mFirst line of docstring\033[0m
        >>> @print_doc1
        ... def foo():
        ...     """First paragraph of docstring which contains more than one
        ...     line.
        ...
        ...     Another paragraph.
        ...     """
        ...     pass
        ...
        >>> foo()
        \033[34mFirst paragraph of docstring which contains more than one line\033[0m
    '''
    # output settings from kwargs or take defaults
    color = kwargs.get('color', blue)
    bold = kwargs.get('bold', False)
    prefix = kwargs.get('prefix', '')
    tail = kwargs.get('tail', '\n')

    def real_decorator(func):
        '''real decorator function'''
        @wraps(func)
        def wrapper(*args, **kwargs):
            '''the wrapper function'''
            try:
                prgf = first_paragraph(func.__doc__)
                print(color(prefix + prgf + tail, bold))
            except AttributeError as exc:
                name = func.__name__
                print(red(flo('{name}() has no docstring')))
                raise(exc)
            return func(*args, **kwargs)
        return wrapper

    invoked = bool(not args or kwargs)
    if not invoked:
        # invoke decorator function which returns the wrapper function
        return real_decorator(func=args[0])

    return real_decorator


def print_full_name(*args, **kwargs):
    '''Decorator, print the full name of the decorated function.
    May be invoked as a simple, argument-less decorator (i.e. ``@print_doc1``)
    or with named arguments ``color``, ``bold``, or ``prefix``
    (eg. ``@print_doc1(color=utils.red, bold=True, prefix=' ')``).
    '''
    color = kwargs.get('color', default_color)
    bold = kwargs.get('bold', False)
    prefix = kwargs.get('prefix', '')
    tail = kwargs.get('tail', '')

    def real_decorator(func):
        '''real decorator function'''
        @wraps(func)
        def wrapper(*args, **kwargs):
            '''the wrapper function'''
            first_line = ''
            try:
                first_line = func.__module__ + '.' + func.__qualname__
            except AttributeError:
                first_line = func.__name__
            print(color(prefix + first_line + tail, bold))
            return func(*args, **kwargs)
        return wrapper

    invoked = bool(not args or kwargs)
    if not invoked:
        # invoke decorator function which returns the wrapper function
        return real_decorator(func=args[0])

    return real_decorator


def supported(*args, **kwargs):
    '''Only execute decorated task-function if the OpenSSL version is supported.

    Keyword-Args:
        openssl_versions: List of OpenSSL version strings

    Example:

        @task
        @supported(openssl_versions=['OpenSSL-1.1.0', 'OpenSSL-1.0.2'])
        def run_openssl_example_xyz():
            ...
    '''
    supported_versions = kwargs.get('openssl_versions', [])

    def real_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            with hide('running'):
                cur = local('openssl version', capture=True)
            for ver in supported_versions:
                if cur.startswith(ver.replace('-', ' ')):
                    return func(*args, **kwargs)
            print(flo('Example does not support {cur} ' + yellow('(skip)')))
            return
        return wrapper

    # if the decorated function is actually invoked
    invoked = bool(not args or kwargs)
    if not invoked:
        return real_decorator(func=args[0])
    return real_decorator


def task(func):
    '''Composition of decorator functions for inherent self-documentation on
    task execution.

    On execution, each task prints out its name and its first docstring line.
    '''
    prefix = '\n# '
    tail = '\n'
    return fabric_task(print_full_name(
        color=magenta, prefix=prefix, tail=tail)(print_doc1(func)))


@task
def clean(deltox=None):
    '''Remove temporary files and compiled binaries not under version control.

    Args:
        deltox: Also delete virtual environments used by tox
    '''
    basedir = dirname(__file__)

    print(cyan('delete files not under version control'))
    ignore_filter = r"grep -v downloaded-examples | grep -v '\.c$' |"
    local("bash -c '" +
          flo('cd {basedir}  &&  '
              'git check-ignore **/* | {ignore_filter} xargs rm -rvf') +
          "'")

    # temporary python files

    print(cyan('\ndelete temp files and dirs for packaging'))
    local(flo(
        'rm -rf  '
        '{basedir}/pyopenssl_examples.egg-info/  '
        '{basedir}/dist  '
        '{basedir}/README  '
        '{basedir}/build/  '
    ))

    print(cyan('\ndelete temp files and dirs for editing'))
    local(flo(
        'rm -rf  '
        '{basedir}/.cache  '
        '{basedir}/.ropeproject  '
    ))

    print(cyan('\ndelete bytecode compiled versions of the python src'))
    # cf. http://stackoverflow.com/a/30659970
    with warn_only():
        local(flo('find  {basedir}/pyopenssl_examples  '
                  '{basedir}/pyopenssl_examples/tests  ') +
              '\( -name \*pyc -o -name \*.pyo -o -name __pycache__ '
              '-o -name \*.c -o -name \*.o -o -name \*.so \) '
              '-prune '
              '-exec rm -rf {} +')

    print(cyan('\ndelete automatically created and compiled c code'))
    local(flo('rm -f {basedir}/pyopenssl_examples/cffi/example_02_real.c'))
    local(flo('rm -f {basedir}/pyopenssl_examples/cffi/example_*.o'))
    local(flo('rm -f {basedir}/pyopenssl_examples/cffi/example_*.so'))

    if deltox:
        print(cyan('\ndelete tox virtual environments'))
        local(flo('cd {basedir}  &&  rm -rf .tox/'))


# python related tasks


def _pyenv_exists():
    with quiet():
        res = local('pyenv', capture=True)
        if res.return_code == 127:
            return False
    return True


def _determine_latest_pythons():
    # TODO implementation
    return ['2.6.9', '2.7.13', '3.3.6', '3.4.6', '3.5.3', '3.6.1']


def _highest_minor(pythons):
    highest = pythons[-1]
    major, minor, patch = highest.split('.', 2)
    return flo('{major}.{minor}')


@task
def pythons():
    '''Install latest pythons with pyenv.

    The python version will be activated in the projects base dir.

    Will skip already installed latest python versions.
    '''
    if not _pyenv_exists():
        print('\npyenv not installed. install it with fabsetup '
              '(https://github.com/theno/fabsetup):\n\n    ' +
              cyan('fab setup.pyenv -H localhost'))
        sys.exit(1)

    latest_pythons = _determine_latest_pythons()

    print(cyan('\n## install latest python versions'))
    for version in latest_pythons:
        local(flo('pyenv install --skip-existing {version}'))

    print(cyan('\n## activate pythons'))
    basedir = dirname(__file__)
    latest_pythons_str = '  '.join(latest_pythons)
    local(flo('cd {basedir}  &&  pyenv local  system  {latest_pythons_str}'))

    highest_python = latest_pythons[-1]
    print(cyan(flo('\n## prepare Python-{highest_python} for testing and '
                   'packaging')))
    packages_for_testing = 'pytest  tox'
    packages_for_packaging = 'pypandoc  twine'
    local(flo('~/.pyenv/versions/{highest_python}/bin/pip  install --upgrade  '
              'pip  {packages_for_testing}  {packages_for_packaging}'))


def _local_needs_pythons(*args, **kwargs):
    with warn_only():
        res = local(*args, **kwargs)
        print(res)
        if res.return_code == 127:
            print(cyan('missing python version(s), '
                       'run fabric task `pythons`:\n\n    '
                       'fab pythons\n'))
            sys.exit(1)


@task
def tox(args=''):
    '''Build package and run unit tests against several pythons with tox.

    Args:
        args: Optional arguments passed to tox.
        Example:

            fab tox:'-e py36 -r'
    '''
    basedir = dirname(__file__)

    latest_pythons = _determine_latest_pythons()
    # e.g. highest_minor_python: '3.6'
    highest_minor_python = _highest_minor(latest_pythons)

    _local_needs_pythons(flo('cd {basedir}  &&  '
                             'python{highest_minor_python} -m tox {args}'),
                         capture=False)


@task
def run():
    '''Run all pyopenssl_examples.'''
    basedir = dirname(__file__)
    cmds = [
        'pyopenssl_examples/bio/bio_connect.py  editorconfig.org',

        'pyopenssl_examples/cffi/example_01_simple.py',

        'pyopenssl_examples/cffi/example_02_real_build.py',
        'pyopenssl_examples/cffi/example_02_real_run.py',

        'pyopenssl_examples/cffi/openssl/bio_01_connect_build.py',
        'pyopenssl_examples/cffi/openssl/bio_01_connect.py  editorconfig.org',
        # 'pyopenssl_examples/cffi/openssl/bio_01_connect.py  --help',

        'pyopenssl_examples/cffi/openssl/bio_02_tls_build.py',
        'pyopenssl_examples/cffi/openssl/bio_02_tls.py  editorconfig.org',

        'pyopenssl_examples/cffi/openssl/bio_03_scts_build.py',
        'pyopenssl_examples/cffi/openssl/bio_03_scts.py  ritter.vg',
    ]
    with warn_only():
        for cmd in cmds:
            print(cyan(flo('\n## Run `{cmd}`\n')))
            local(flo('cd {basedir}  &&  '
                      "PYTHONPATH='.'  .tox/py36/bin/python  {cmd}"))
