Installation
============

|cli| is a Python CLI (Python 3.10+) over PC/SC.

Install
---------

Install with `pipx <https://pipx.pypa.io/>`__ — it puts ``cryptnox-id`` on your
``PATH`` **globally** while keeping the tool's dependencies (``click``, ``rich``,
``cbor2``, ``cryptography``, ``pyscard``, …) in their own isolated environment.
It is also the method that works out of the box on current Linux distributions,
where installing into the system Python is blocked (PEP 668).

.. code-block:: console

   $ pipx install cryptnox-id-cli
   $ cryptnox-id --version

(pipx itself: ``apt install pipx`` / ``dnf install pipx`` / ``brew install pipx``,
or on Windows ``py -m pip install --user pipx`` then ``py -m pipx ensurepath``.)

**Windows alternative** — plain pip works there and gives a global command too,
as long as your Python ``Scripts`` directory is on ``PATH``:

.. code-block:: powershell

   pip install cryptnox-id-cli
   cryptnox-id --version

A classic virtual environment also works, but the command is then available
only while that venv is activated — fine for development (see the README),
not what you want for day-to-day card management.

Three console entry points are installed and interchangeable: ``cryptnox-id``,
the short ``cnx-id``, and ``cryptnox-id-card``.

PC/SC per platform
--------------------

* **Windows** — built in (the *Smart Card* service, ``SCardSvr``); nothing to
  install.
* **Linux** — install ``pcscd`` and the CCID driver
  (``apt install pcscd libccid``). Building ``pyscard`` from source also needs
  ``build-essential swig libpcsclite-dev`` (and ``python3-dev`` on a distro
  Python without headers).
* **macOS** — built in. Note two things: the system Python is 3.9 (below the
  3.10 floor) — install 3.10+ with `uv <https://docs.astral.sh/uv/>`_, Homebrew
  or python.org; and ``cbor2`` must be ``<6`` (enforced in packaging), since 6.x
  has no Intel-mac wheel.

Confirm the install sees a reader:

.. code-block:: console

   $ cryptnox-id readers

Windows single-file executable
--------------------------------

A standalone ``cryptnox-id.exe`` (no Python install required) is built with
PyInstaller from ``packaging/cryptnox-id.spec``. PyInstaller cannot
cross-compile, so each platform's binary is built on that platform; the wheel
above is the cross-platform path and runs anywhere Python 3.10+ and PC/SC exist.

WSL2 (Windows Subsystem for Linux)
------------------------------------

WSL2 has no PC/SC by default, but a USB reader can be passed through with
`usbipd-win <https://github.com/dorssel/usbipd-win>`_. Verified end to end: PIV
over contact, DESFire EV2 over contactless, and FIDO2 over contactless (no
elevation) all work from Ubuntu in WSL2 against physical cards.

.. code-block:: powershell

   # Windows (Administrator), one-time per reader (find <id> with: usbipd list):
   usbipd bind   --busid <id>
   # per session (WSL must be running):
   usbipd attach --wsl --busid <id>     # detaches the reader from Windows

.. code-block:: console

   # WSL (Ubuntu):
   $ sudo apt install pcscd libccid pcsc-tools usbutils
   $ sudo pcscd
   $ cryptnox-id --reader PICC mifare info    # contactless; --reader ICC/ACR39U for contact

.. code-block:: powershell

   usbipd detach --busid <id>           # return the reader to Windows

Reader **names and indices differ on Linux**, so select by name substring
(``PICC`` = contactless, ``ICC`` / ``ACR39U`` = contact), not index. While a
reader is attached to WSL, Windows cannot see it.

Next
------

* :doc:`/getting-started` — first commands and reader selection
* :doc:`/overview` — what the card and CLI do
