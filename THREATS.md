
# TrustVault Threat Model

## 1. Scope

TrustVault is a document-sharing application with administrator, owner,
and viewer roles. Its security depends on authentication, document-level
authorization, upload validation, and audit logging.

This document describes threats that must be tested against the
implemented application.

## 2. Assets to Protect

- Uploaded documents and their contents
- User accounts and login sessions
- Document ownership and sharing permissions
- Audit records
- Application secrets and database credentials

## 3. Threats and Mitigations

| Threat | Mitigation to verify | Required test |
|---|---|---|
| Unauthenticated document access | Require authentication on protected routes | Anonymous user cannot list or download documents |
| Unauthorized document download | Check read permission before sending a file | User without access cannot download it |
| Unauthorized document modification | Check edit permission on every modifying operation | Viewer cannot edit a document |
| Unauthorized permission changes | Restrict grants and revocations to the document owner | Non-owner cannot grant or revoke access |
| Access after permission revocation | Check current grants on every request | Revoked user immediately loses access |
| Malicious file upload | Validate extension, content, and size; store files privately | Reject disallowed, oversized, and invalid uploads |
| Document identifier guessing | Enforce authorization independently of document IDs | Changing an ID never bypasses permissions |
| Audit record tampering | Hash-chain audit events and verify the chain | Altered event or broken chain is detected |
| Unauthorized audit access | Require an authenticated administrator | Owner/viewer cannot view the admin audit page |
| Session compromise | Use secure session-cookie settings in production | Verify cookie flags over HTTPS |

## 4. Audit Events

Verify that successful and denied sensitive operations are logged,
including downloads, uploads, permission grants, revocations, and
attempts to access documents without authorization.

Confirm that audit records contain enough information to investigate
an incident without storing document contents, passwords, or session
secrets in event details.

## 5. Security Tests

Run the automated tests from the project root:

```powershell
python -m pytest -v
```

Also perform integration tests for:

- Anonymous access to protected routes
- Owner, viewer, and administrator access
- Download attempts using another user's document ID
- Read-only versus edit permission
- Grant and revoke operations
- Access immediately after revocation
- Invalid and oversized uploads
- Audit logging for allowed and denied operations
- Audit-chain verification
- Unauthorized access to administrator functions

Record the actual results and relevant test names before submission.
A test must not be described as passing until it has been executed.

## 6. Known Limitations

Update this section based on the final implementation and test results.

- A database-backed hash chain may not protect audit records against an
  attacker who can rewrite the database and recompute the entire chain.
  Independent log storage or external hash anchoring would strengthen it.
- Debug mode must not be enabled in public production deployment.
- Uploaded files must not be stored in a publicly accessible directory.
- Rate limiting, brute-force protection, backup recovery, and production
  monitoring must be evaluated before deployment.
- A successful unit-test run does not establish that all application
  routes and deployment settings are secure.

## 7. Final Review

Before submission, replace unverified statements with actual findings.
Record each discovered weakness, its correction, the test used to verify
the correction, and the associated Git commit.
