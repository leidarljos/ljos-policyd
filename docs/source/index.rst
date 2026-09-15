.. raw:: html

   <div class="vi-hero">
     <div class="vi-hero-brand">
       <img class="vi-hero-mark" src="_static/mark.svg" width="64" height="64" alt="" />
       <div>
         <p class="vi-hero-name">ljos-policyd</p>
         <p class="vi-hero-tag">May this command line run?</p>
       </div>
     </div>
     <p class="vi-hero-tagline">May this command line run? First deny wins.</p>
     <div class="vi-hero-pills">
       <span>check / exec / capnp</span>
       <span>First deny wins</span>
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

   $ uvx ljos-policyd check -- uv run pytest
   allow
   $ uvx ljos-policyd check -- sudo id
   deny    sudo

Typed verdict is Cap'n PolicyDecision (phronesis; Ali Akber Saifee / indynull, HaoZeke). A Janet pack can deny more. It cannot allow what this binary denied.

.. code:: janet

   (defn check [argv]
     (when (has-prefix? (get argv 0) "sudo")
       (deny "sudo")))

The seat composes that pack after this verdict: ``ljos policy -- uv run pytest``.

Install
=======

.. code:: console

   $ uvx ljos-policyd check -- uv run pytest
   allow
   $ cargo binstall ljos-policyd

``exec`` runs the line only if the verdict is allow. A deny exits 2.

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
