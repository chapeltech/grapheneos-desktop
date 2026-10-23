# Independent review: authoritative Recents focus routing proposal

This directory is a bounded, read-only review of the frozen proposal at
`phase1-recents-authoritative-focus-routing-proposal-20261012-1`. It is not an
OS, APK, Binder, emulator, or runtime qualification result. It makes no release
claim and does not modify the proposal or any repository source.

## Frozen inputs

- `FocusQueryCoordinator.kt`:
  `1355c4282e280fbc6de8da27f62f9b4f8617f0e955cd7c6ba80eeecdaa82a788`
- `FocusCommandGate.kt`:
  `3025432ac31039b6af82d217ac94f82635067f94a25e3f470c101d27f857826e`
- original `FocusRoutingFixture.kt`:
  `ef865479d38b5d72bae4ddb48fc661dc100eb059e51b5b2fd39ebd5cb6bc338e`
- pinned Android `HandlerExecutor.java`:
  `cacb177ad81b8b92e7df67ad816019f7f38d9e511b523b4094d001c4d6a9c81d`
- pinned Android `RemoteCallback.java`:
  `de6969a49c42afa42f0f032b3eb1445e5c2e80847f0e3e33ac6f92e2bb981775`
- pinned Android `IRemoteCallback.aidl`:
  `31120af262690e1d7f4dd4f2befdcca13c4fa30ed10278bfdc722c31298e0b2a`

The test also pins the source-tree Kotlin compiler, standard library, and JDK
executable. Compilation uses at most 256 MiB Java heap; execution uses at most
64 MiB. It starts no Gradle daemon, Docker container, VM, Android build, or
guest.

## Concrete results

1. **Confirmed dispatch-rejection slot wedge.** The frozen coordinator sets
   `inFlight=true` and catches only `RejectedExecutionException`. The exact
   pinned Shell `HandlerExecutor.execute()` throws plain `RuntimeException`
   when `Handler.post()` returns false. The adversarial fixture runs that exact
   exception shape: it escapes and every later request is rejected as busy.
   A successor must ensure that every nonaccepted worker dispatch resets the
   slot. If it catches `RuntimeException` around `execute`, the submitted
   runnable should contain its own callback exception handling so a synchronous
   executor cannot make a completed callback look like a rejected submission.

2. **Confirmed final-check-to-route race.** A deterministic replacement thread
   is blocked on the gate lock during the final check, completes immediately
   after the lock is released, and the old request's route effect then runs.
   `accept()` returns true. A last check followed by an unlocked effect is not
   linearization. The Android adapter must execute endpoint replacement,
   eligibility state mutation/check, and the actual route effect on one actor
   (the Launcher MAIN executor), or use another single atomic authorization and
   effect boundary. The route closure itself must not merely enqueue a later
   effect elsewhere.

3. **Confirmed same-object reconnect ambiguity in the coordinator.** Calling
   `attach()` with the same owner object permits an old in-flight response after
   the reconnect. The Android adapter therefore needs a fresh opaque owner
   incarnation for every endpoint creation, even when Binder returns the same
   object. `invalidate()` must carry that exact incarnation so an old death or
   disconnect cannot invalidate its replacement. In contrast,
   `FocusCommandGate.replace()` does invalidate an old request for a reused
   endpoint because it advances its private epoch; the adapter must call it for
   every connection epoch.

4. **Bounded hung callback behavior is conditional on executor ownership.** An
   actual one-thread fixture blocks the callback, replaces the owner, and proves
   100 further requests do not enqueue work. It recovers only after the exact
   old callback completes. This is fail-closed and bounded only if production
   uses one process-global, owned, fixed-size worker with no per-timeout or
   per-reconnect replacement and no unbounded admission queue. It must never be
   Shell MAIN, Launcher MAIN, or another shared critical executor. A hung
   one-way Binder callback may retain this worker indefinitely; creating a new
   worker to recover would turn a bounded failure into unbounded threads/calls.

5. **Exception recovery works after actual task entry.** Query exceptions are
   normalized by the frozen coordinator, and its `finally` releases the slot
   after callback exceptions. This does not cure the pre-task dispatch failure
   in result 1.

## Adapter prerequisites

- Schedule exactly one MAIN timeout before sending the remote query. On query
  dispatch failure, response-post failure, timeout-post failure, or dead
  endpoint, abandon only the exact request and cancel/remove only its exact
  callbacks. Do not let repeated replacement while MAIN is frozen accumulate
  per-connection timeout/response work.
- Use the same monotonic clock as MAIN's delayed-handler scheduling. An early
  timer deliberately does not clear the slot and is not rescheduled by the
  frozen gate.
- Binder listener work may only claim the exact callback and enqueue the one
  MAIN response. All endpoint/epoch replacement, live eligibility evaluation,
  and actual Recents route effect must stay on MAIN.
- Treat the UI executor's post result as an admission result. The pinned
  Launcher `LooperExecutor.execute()` posts without checking the Boolean return;
  using that method alone cannot distinguish a dropped post from accepted work.
- Old timeout and callback messages must be harmless to a replacement and must
  never clear or route its request.

## Independent host execution

Command:

```text
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -B -m unittest -v test_review.py
```

Final replay result: 4 tests passed in 5.192 seconds. An earlier identical
replay passed in 4.959 seconds. The compiled fixture reports both
`confirmed_runtime_rejection_wedge=true` and
`confirmed_final_route_race=true`. This is host characterization of the exact
frozen methods and pinned source behavior, not Android adapter or runtime proof.

