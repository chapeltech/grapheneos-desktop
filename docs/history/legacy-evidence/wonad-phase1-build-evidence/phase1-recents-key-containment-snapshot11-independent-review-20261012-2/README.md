# Snapshot 11 rejected-start pair-parity RED

This is a bounded host counterexample against immutable snapshot 11. It is not
Android runtime evidence and changes no repository or platform source.

The fixture fills the claimed action-ticket budget, observes a null install for
the next claimed `APP_SWITCH` DOWN, then proves its exact matching UP has both
`Decision.consume == false` and no terminal owner. The generated KGC consumes
the rejected DOWN but its null-owner UP branch falls through. With ordinary
focused-window key capture enabled, the outer method returns that UP to the
capturing app before the after-capture system-key catch-all; without key
capture, that later catch-all still consumes `APP_SWITCH`.

The successor must retain terminal consumption for a stateful pair whose DOWN
was consumed even if no stock START was delivered (budget rejection, stale
reservation, or delivery-ack failure).
