.. raw:: html

   <div class="vi-hero">
     <div class="vi-hero-brand">
       <img class="vi-hero-mark" src="_static/mark.svg" width="64" height="64" alt="" />
       <div>
         <p class="vi-hero-name">ljos-policyd</p>
         <p class="vi-hero-tag">May this command line run?</p>
       </div>
     </div>
     <p class="vi-hero-tagline">Argv law. Prints a verdict. Does not reload a pack. Not a store.</p>
     <div class="vi-hero-pills">
       <span>check / exec</span>
       <span>First deny wins</span>
       <span>The model is not the gate</span>
     </div>
     <div class="vi-hero-actions">
       <a class="vi-btn vi-btn-gold" href="getting-started.html">Get started</a>
       <a class="vi-btn vi-btn-ghost" href="reference.html">Reference</a>
     </div>
   </div>

One question: may this argv run? The binary prints ``allow`` or ``deny`` and a
reason. The harness hook and ``ljos policy`` call it when it is on ``PATH``
(or ``POLICYD_BIN``). Absence is not a deny. Reloading a pack is not a
check. Writes stay out of this crate.

Install
=======

.. code:: console

   $ cargo binstall ljos-policyd
   $ ljos-policyd check -- cargo test
   allow
   $ ljos-policyd check -- sudo id
   deny    sudo

``exec`` runs the line only if the verdict is allow. A deny exits 2.

.. toctree::
   :maxdepth: 1
   :caption: Guides
   :hidden:

   getting-started
   howto
   reference
   explanation
