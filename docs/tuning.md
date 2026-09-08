# Tuning notes

These detections describe behaviors rather than fixed indicators. Before using
one as an alert, run it as a hunt and review at least one representative period
of normal administrative activity.

## Suggested workflow

1. Confirm that process names, command lines, parent processes, users, and hosts
   are populated consistently.
2. Measure the result volume and identify recurring management tools, software
   deployment systems, and support workflows.
3. Prefer narrow exclusions based on a combination of signer, parent process,
   managed account, device group, and exact command pattern.
4. Keep broad allowlists out of the base rule. Add environment-specific filters
   in the deployment layer where they can be reviewed independently.
5. Re-run positive and negative regression cases after changing detection logic.
6. Record the query version, observation window, result count, and reason for
   each production exclusion.

## Severity

`high` indicates behavior that should be reviewed promptly but can still be
legitimate administration. `medium` indicates suspicious behavior that usually
needs environmental context or correlation before escalation.
