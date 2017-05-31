# PyOpenSSL-Examples

Code-Examples which show how to use the API of PyOpenSSL.

## Usage

The (bash) commands to run the examples will be executed by [Fabric][1] tasks:

```
fab -l

Available commands:

    clean    Remove temporary files and compiled binaries not under version
             control.
    pythons  Install latest pythons with pyenv.
    tox      Build package and run unit tests against several pythons
             with tox.
    run      Run all pyopenssl_examples.
```

Show task details, e.g.:
```
fab -d tox
```


### Provisioning

Install and setup python versions and virtualenvs for development with pyenv:
```
fab pythons
fab tox
```

### Run pyopenssl-examples

Now, compile and run the examples:
```bash
# run all pyopenssl-examples
fab run

# run one example "manually"
PYTHONPATH='.' \
.tox/py36/bin/python  pyopenssl_examples/bio-connect.py  editorconfig.org
```

All executed command line commands will be printed out.  You can rerun this
commands "manually", modify them, play with them.  Also it's a good start to
look for function `run()` in `fabfile.py`. And try this for a better
overview:

```bash
# so much output, cannot see the wood for the trees ...
fab run --hide=output
fab run --hide=stdout
```

[1]: http://docs.fabfile.org
