"""Issue-to-pull-request agent loop for this repository.

The dispatcher in this package owns the GitHub label state machine, administrator authorization, subscription quota
tracking, and notifications. Models run only inside stage invocations. See ``docs/agent-loop.md``.
"""
