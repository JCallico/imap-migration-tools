---
name: release-green-loop
description: Take a pull request through the PR green loop, pause for the user's final review and confirmation, then merge it, create a release, and verify release automation. Use when the user explicitly requests the complete merge-and-release delivery loop.
---

# Release Green Loop

Deliver a prepared change through a green pull request and a verified release without crossing the merge boundary until
the user reviews the final state and explicitly approves it.

## Authorization and scope

Read and follow `../pr-green-loop/SKILL.md`, along with the repository's contributor instructions. An explicit request
to run `$release-green-loop` authorizes the subordinate PR green loop's commit-and-push cycle, but automatic skill
selection alone authorizes no mutation.

The user must separately confirm the reviewed, green pull request before any merge, tag, published release, package
publication, deployment, or other release-triggered mutation. Do not treat the initial request to run the loop as that
confirmation. Never use administrator bypass, force-push, rewrite a release tag, or weaken a protection or check unless
the user explicitly requests the specific action after being told its consequences.

## Prepare the release

Before or while running the PR green loop, inspect the repository's release conventions and automation. Establish the
intended merge method, release tag and title, release-note source, draft or prerelease status, target branch, and any
downstream effects such as publishing packages or deploying. Use values supplied by the user or unambiguous repository
conventions; ask rather than guess when multiple version bumps, merge methods, or publication modes are plausible.

Confirm that the release tooling and credentials are available using read-only checks. Ensure the proposed tag and
release do not already exist, compare with recent releases, and identify workflows that will run on merge, tag creation,
or release publication.

## Make the pull request green

Run the complete PR green loop. Continue until every required check and delayed external status is successful for the
latest PR head commit, the branch is synced, the pull request is approved, non-draft, and mergeable, and its description
and release notes accurately describe the final change.

## Mandatory review checkpoint

Stop before merging and present a compact final-review summary containing:

- the pull-request link, title, base branch, and exact green head SHA;
- the final change and file summary, verification performed, and required-check results;
- the proposed merge method;
- the proposed release tag, title, notes source, and draft or prerelease status; and
- every known downstream publication or deployment that creating the release will trigger.

Ask the user explicitly whether to merge that pull request and create the described release. Wait for an affirmative
response. A vague acknowledgment, the original request to start the loop, or approval of an earlier commit is not
sufficient.

The confirmation is bound to the reviewed PR head SHA and release details. Revalidate them immediately after approval.
If the head changes, checks regress, required approvals disappear, mergeability changes, or any proposed release detail
or downstream effect changes, stop, show the new state, and request fresh confirmation.

## Merge and release

1. Merge using the confirmed method through the repository's normal protected path. If a merge queue or auto-merge is
   required, enable it without bypassing protections and wait for the actual merge.
2. Record the resulting commit on the base branch and verify through the hosting service that the pull request merged.
   Fetch the remote base branch and ensure the recorded commit is reachable from it.
3. Wait for required post-merge checks on that exact base-branch commit. Diagnose failures and retry unchanged jobs only
   when doing so is safe. If a source or configuration fix is needed, do not release; report that a follow-up change is
   required and request direction.
4. Create the confirmed release at the exact merged commit. Follow repository conventions for whether tooling creates
   the tag, and verify the resulting tag resolves to that commit. Do not silently retarget an existing tag.
5. Monitor release-triggered workflows and external publication checks to completion. Attribute results to the exact
   release tag and commit rather than to older runs.

## Failure and completion

Inspect logs and annotations for release failures. Safely retry a transient unchanged job when supported, but never
delete or move a published tag, replace a published artifact, reuse an immutable package version, or create a new
version without explicit user direction. Stop with a concrete recovery plan when repair requires a new pull request,
version, credential, permission, or external-system change.

Finish only when the pull request is merged, the release and tag target the recorded merged commit, and all required
post-merge and release checks have succeeded. Report the pull request, green head SHA, merge commit, release and tag,
release notes, verification results, downstream publication status, and any safe follow-up work.
