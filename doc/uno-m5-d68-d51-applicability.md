# D68 shortfall prediction applicability after the D51 trigger update

Specification SHA256:
`4f80cceb2f28788545294bdf6ef17d58e82113c535de74366f60166c2e575917`.
Coordinator identifies the specification change as memo `cba2d107`; the local
memo HEAD observed while checking the same file hash was `8784255b`.

This is an applicability note, not a replacement of the pre-observation
prediction committed in `475214710` (English reference correction `9be4f9c67`).
No A shortfall fixture, expected output or observation was read. D51 adds the
arrival trigger for deferred tests; it does not change these accounting inputs.

Let x be principal, q outgoing fee, b original reserve, f protocol fee, y the
actual in-window bounce receipt, and s the terminal slot fee. All quantities
are explicit authenticated/event inputs; none is a local default. As before:

    m = checked(y+b); d = min(s,m); z = checked(m-d)

The shortfall branch has z<x. If m>s, issue pending z; otherwise transfer m
as D65 income and issue no pending. Do not promise the unpaid difference or
create a record representing an unfunded payable.

After prepare and fees:
`R_actual=R_book=R0-x-q-f`, `N_book=R0-x-q-b-f`, `W=x+b`, `P=x`, `D=0`.
At the complete Failed boundary:
`R_actual=R_book=R0-x-q-f+y-d`, `N_book=R0-x-q-b-f+z`, `W=P=D=0`.
Since z=y+b-d, the final R and N values are equal. Across that boundary,
`delta(R_actual+P)=y-d-x=delta(D+N_book+W)`. Waiting without an event changes
neither side. Thus BOTH equations remain satisfied even when z<x or z=0.

Coordinator increases by d; refundable deposits and bucket holdings do not
change. No operating-budget debit supplies a shortfall. Return loss x-y is
already reflected in y: do not subtract it a second time. Reserve spending is
capped by b, rather than storing a larger actual loss as consumed reserve.

These are symbolic predictions under the stated atomic direct-disposition
branch, not host observations. No-bounce, full-slot, bucket and late-return
branches require their own events. The complete conditions and previously
frozen tables remain in `uno-m5-d68-shortfall-prediction.md`. The effective
queue's independent prediction item is complete; real host comparisons await
A's committed producers and must not rewrite these predictions.
