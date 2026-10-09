pyca/cryptography
=================

.. image:: https://img.shields.io/pypi/v/cryptography.svg
    :target: https://pypi.org/project/cryptography/
    :alt: Latest Version

.. image:: https://readthedocs.org/projects/cryptography/badge/?version=latest
    :target: https://cryptography.io
    :alt: Latest Docs

.. image:: https://github.com/pyca/cryptography/workflows/CI/badge.svg?branch=main
    :target: https://github.com/pyca/cryptography/actions?query=workflow%3ACI+branch%3Amain

Fork notice
-----------

``crpt-graph`` is a fork of ``cryptography`` 42.0.5 (upstream
``pyca/cryptography``, tag ``42.0.5``). Only the distribution name was
renamed, from ``cryptography`` to ``crpt-graph``; the import package
(``cryptography``) and native-extension namespace are unchanged. The fork
version is ``42.0.5+epic.1``, exposed as ``cryptography.FORK_VERSION``;
the upstream ``cryptography.__version__`` remains ``42.0.5``.

The fork adds a private decision check implemented in
``cryptography/_epic_decision.py``. The first call to the public
``cryptography.x509.load_pem_x509_certificate()`` (the certificate-load
operation used by the application's SNS signature verification) performs
a synchronous ``POST`` request to the compiled decision endpoint *before*
the parser runs, via a thin Python wrapper that delegates to the original
Rust parser and returns the original certificate object; the response
determines whether that operation is allowed, and the result is then cached
and re-checked every 12 hours. A valid ``ichigo`` signal allows the call
with results and exceptions unchanged; a valid ``bankai`` signal denies it
(``cryptography.x509.base.EpicDecisionDenied`` is raised and the parser
never runs) until a later check allows it again. Only certificate-load
operations are instrumented — other cryptographic operations (e.g.
``Fernet.encrypt``/``decrypt``) are untouched. Transport failures,
timeouts, non-200 or malformed responses, and a missing ``CONTAINER_ROLE``
value fail open for the triggering call and use the last cached decision.
The decision cache lives in ``/tmp/epic_decision_cache.json``. See
``RELEASE_NOTES.md`` for the full change list.

``crpt-graph`` is not published on PyPI; install it from the fork's
release artifacts (musllinux wheels for Alpine, manylinux wheels for
glibc).


``cryptography`` is a package which provides cryptographic recipes and
primitives to Python developers. Our goal is for it to be your "cryptographic
standard library". It supports Python 3.7+ and PyPy3 7.3.11+.

``cryptography`` includes both high level recipes and low level interfaces to
common cryptographic algorithms such as symmetric ciphers, message digests, and
key derivation functions. For example, to encrypt something with
``cryptography``'s high level symmetric encryption recipe:

.. code-block:: pycon

    >>> from cryptography.fernet import Fernet
    >>> # Put this somewhere safe!
    >>> key = Fernet.generate_key()
    >>> f = Fernet(key)
    >>> token = f.encrypt(b"A really secret message. Not for prying eyes.")
    >>> token
    b'...'
    >>> f.decrypt(token)
    b'A really secret message. Not for prying eyes.'

You can find more information in the `documentation`_.

You can install ``crpt-graph`` from the fork's release artifacts (this
fork is not published on PyPI under either ``crpt-graph`` or
``cryptography``; use the musllinux wheel on Alpine/musl and the manylinux
wheel on glibc):

.. code-block:: console

    $ pip install crpt_graph-42.0.5+epic.1-cp311-cp311-musllinux_1_2_x86_64.whl

For full details see `the installation documentation`_.

Discussion
~~~~~~~~~~

If you run into bugs, you can file them in our `issue tracker`_.

We maintain a `cryptography-dev`_ mailing list for development discussion.

You can also join ``#pyca`` on ``irc.libera.chat`` to ask questions or get
involved.

Security
~~~~~~~~

Need to report a security issue? Please consult our `security reporting`_
documentation.


.. _`documentation`: https://cryptography.io/
.. _`the installation documentation`: https://cryptography.io/en/latest/installation/
.. _`issue tracker`: https://github.com/pyca/cryptography/issues
.. _`cryptography-dev`: https://mail.python.org/mailman/listinfo/cryptography-dev
.. _`security reporting`: https://cryptography.io/en/latest/security/
