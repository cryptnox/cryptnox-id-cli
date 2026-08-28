.. _cli-shell:

Interactive shell
=================

``shell`` starts a captive prompt that runs |cli| subcommands without the
program-name prefix — type ``piv info``, not ``cryptnox-id piv info`` — and
loops until you leave. It is built for desktop use: point a shortcut at it and
card management opens as a small console, no terminal habits required.

.. code-block:: console

   $ cryptnox-id shell
   cryptnox-id interactive shell. Type a command without the 'cryptnox-id' prefix (e.g. 'piv info').
     help            show available commands
     <command> -h    help for a command
     clear           clear the screen
     exit / quit     leave the shell

   cryptnox-id> readers
   ...
   cryptnox-id> piv info
   ...
   cryptnox-id> exit

Only this CLI's own commands run — it is **not** an operating-system shell;
``ls`` or ``dir`` are unknown commands here.

Built-ins and keys
--------------------

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Input
     - Effect
   * - ``help``
     - List the available commands (same as ``--help``).
   * - ``<command> -h``
     - Help for one command, e.g. ``piv -h``.
   * - ``clear``
     - Clear the screen.
   * - ``exit`` / ``quit``
     - Leave the shell.
   * - :kbd:`Ctrl-C`
     - Cancel the current line; the shell stays open.
   * - :kbd:`Ctrl-D` (end of input)
     - Leave the shell.

Arguments follow shell quoting rules (``--subject "CN=Test User"`` works); an
unbalanced quote is reported and the prompt returns. Command history and line
editing are available where Python's ``readline`` exists (Linux, macOS).

Global options carry in
-------------------------

Global options passed when *launching* the shell apply to every command run
inside it — ``--reader``, ``--json``, ``--verbose``, ``--apdu-log``,
``--dry-run``, ``--yes``, ``--timeout``, ``--no-color``:

.. code-block:: console

   $ cryptnox-id --reader 1 --json shell

Every command in that session now targets reader 1 and prints JSON.

Each line is its own invocation, with a fresh card session per command —
exactly as if run from the OS prompt (the SCP03 admin channel is
per-command). A failing command prints its error and returns to the prompt;
it never ends the shell.

Desktop shortcut (Windows)
----------------------------

Create a shortcut whose target is the installed binary with the ``shell``
argument, e.g.::

   C:\...\Scripts\cryptnox-id.exe shell

Double-clicking it opens the captive prompt directly. ``fido …`` commands need
Administrator rights on Windows, but the shortcut does not have to be elevated:
when it isn't, the CLI offers to re-run the command as Administrator — approve
the UAC prompt and the result is shown back in your window (see
:doc:`/fido2/quick-start-a-passkey-on-the-card`). Starting the shortcut elevated once avoids the
per-command prompts.

Piped input
-------------

Without a terminal the shell reads commands line by line from standard input,
so short sequences can be scripted:

.. code-block:: console

   $ printf 'readers\npiv info\n' | cryptnox-id shell
