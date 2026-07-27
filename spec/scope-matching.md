# Scope Matching (deterministic, no LLM)

Two operations, both pure functions over the `Scope` object (see `schemas/scope.schema.json`).

## 1. `matches(scope, request) -> boolean`

A `request` is `{ action, resource?, amount?, counterparty?, dataCategories?, timestamp }`.

Deny unless **all** of the following hold:

1. `request.action` is present in `scope.actions`.
2. If `scope.resources` is set: `request.resource` is present in it. If unset: any resource passes.
3. If `scope.max_amount` is set: `request.amount` is present, same `currency`, and `value <= scope.max_amount.value`. If the request carries an amount but the scope defines none, deny — an unbounded amount must never pass through a scope that never mentioned money.
4. If `scope.counterparties.deny` is set and `request.counterparty` is in it: deny outright, even if `allow` would also match.
5. If `scope.counterparties.allow` is set: `request.counterparty` must be in it.
6. If `scope.data_categories` is set: every entry in `request.dataCategories` must be present in it.
7. If `scope.time_windows` is set: `request.timestamp` must fall inside at least one window (day + time range, evaluated in that window's `timezone`). If unset: any time passes (subject to `valid_from`/`valid_until` on the Delegation itself, checked separately).

Any missing/unparseable field required by an active constraint is a deny, not a pass-through.

## 2. `narrows(parent, child) -> boolean`

Used when validating a sub-delegation (`can_delegate: true` on the parent). A child scope is valid only if it cannot authorize anything the parent didn't:

1. `child.actions` ⊆ `parent.actions`.
2. If `parent.resources` is set, `child.resources` must be set and be a subset of it. (A child may not go from bounded to unbounded.)
3. If `parent.max_amount` is set: `child.max_amount` must be set, same currency, `child.value <= parent.value`.
4. `child.counterparties.allow` (if any) ⊆ `parent.counterparties.allow` (if any parent allow-list exists). `child.counterparties.deny` ⊇ `parent.counterparties.deny` (child may add denials, never remove them).
5. `child.data_categories` (if any) ⊆ `parent.data_categories` (if any parent list exists).
6. `child.time_windows` must be fully contained within the union of `parent.time_windows`, if the parent restricted time at all.

If any check fails, the sub-delegation is invalid at issuance time — a Verifier that receives it MUST reject the entire chain, not just the offending action.

## Why pure functions

Both operations take structured input and return a boolean with no external state (registry lookups, revocation, and time validity are handled separately in the verification flow, see `docs/verification-flow.md`). This is what makes them auditable, testable, and immune to prompt injection: there is nothing here an LLM interprets.
