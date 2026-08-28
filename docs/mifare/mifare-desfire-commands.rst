MIFARE DESFire commands
=======================

Contactless MIFARE DESFire commands (DESFire-capable reader required). Keys
are AES-128, supplied via ``--zero-key`` (factory default of a new
application) or ``--key-env NAME`` — never on the command line.

Inspection
----------

.. code-block:: text

   mifare info           version + free memory + applications
   mifare version        hardware/software version, storage size, UID
   mifare free-memory    free EEPROM
   mifare apps list      application directory

Applications
------------

.. code-block:: text

   mifare app create     create an application (AES keys; new keys all-zero)
   mifare app delete     delete an application and every file in it
                         (authenticated; PERMANENT — see Destructive below)

Keys
----

.. code-block:: text

   mifare keys authenticate   prove a key / session crypto (AuthenticateEV2First)
   mifare keys change         rotate a key (same-key or cross-key)

Files and data
--------------

.. code-block:: text

   mifare files list             file directory of an application
   mifare files create-standard  create a standard data file (plain/MAC/FULL)
   mifare write                  write data (MAC-protected; --full for encrypted)
   mifare read                   read data (plain for free-read; --full for encrypted)

Value and record files
----------------------

.. code-block:: text

   mifare value create    create a value file (bounded signed counter)
   mifare value get       read the current value
   mifare value credit    add to the value (commits the transaction)
   mifare value debit     subtract from the value (commits the transaction)

   mifare record create   create a linear or cyclic record file
   mifare record write    append a record (commits)
   mifare record read     read records
   mifare record clear    clear the record file (commits)

Secure Dynamic Messaging (EV3)
------------------------------

.. code-block:: text

   mifare sdm setup     create + configure an SDM/SUN file with a URL template
   mifare sdm read      read the file, decrypt the PICC mirror, verify the MAC

See the :doc:`/mifare/quick-start-a-tamper-evident-nfc-tag-sdm-sun` for the end-to-end flow.

Destructive
-----------

.. code-block:: text

   mifare app delete    delete an application and every file in it — permanent
                        (confirmation required unless --yes)
   mifare format        FormatPICC: erase ALL applications (gated; AES PICC
                        master key required)
