.. raw:: html

   <div class="vi-hero">
     <div class="vi-hero-brand">
       <img class="vi-hero-mark" src="_static/mark.svg" width="64" height="64" alt="" />
       <div>
         <p class="vi-hero-name">ljos-policyd</p>
         <p class="vi-hero-tag">May this command line run?</p>
       </div>
     </div>
     <p class="vi-hero-tagline">May this command line run? The answer is allow, with a warning when a rule matches.</p>
     <div class="vi-hero-pills">
       <span>check / exec / capnp</span>
       <span>Allow, and show the warning</span>
       <span>uv first</span>
     </div>
     <div class="vi-hero-actions">
       <a class="vi-btn vi-btn-gold" href="getting-started.html">Get started</a>
       <a class="vi-btn vi-btn-ghost" href="reference.html">Reference</a>
     </div>
   </div>

First minute
============

.. code:: console

   $ ljos-policyd check -- uv run pytest
   allow
   $ ljos-policyd check -- sudo id
   allow    warn    sudo    a privilege runner is on the command

Typed verdict is Cap'n PolicyDecision (phronesis; Ali Akber Saifee / indynull, HaoZeke). A Janet pack can name more. The printed line is still allow, with that rule and one warning.

.. code:: janet

   (defn check [argv]
     (when (has-prefix? (get argv 0) "sudo")
       (deny "sudo")))

The seat composes that pack after this verdict: ``ljos policy -- uv run pytest``.

Install
=======

.. code:: console

   $ cargo binstall ljos-policyd
   $ ljos-policyd check -- uv run pytest
   allow

``exec`` prints a warning on stderr when a rule matches, then runs the line. Exit status is the program's.

The :doc:`tutorial <getting-started>` is the same walk with ``exec`` and ``POLICYD_BIN``.

.. toctree::
   :maxdepth: 1
   :caption: Guides
   :hidden:

   getting-started
   howto
   reference
   explanation
   seat
