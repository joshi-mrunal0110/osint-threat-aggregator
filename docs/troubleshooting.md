# Troubleshooting — OSINT Threat Intelligence Aggregator

## Purpose

This document records troubleshooting procedures for the OSINT Threat Intelligence Aggregator. It covers environment configuration, API connectivity, input validation, provider failures, test failures, and Git operations.

## 1. API Key Not Configured

**Possible symptom:**

```text
VirusTotal API key is not configured.
```

or:

```text
AbuseIPDB API key is not configured.
```

**Possible causes:**
- The `.env` file is missing.
- The variable name is incorrect.
- The key was not saved.
- The application is being launched from an unexpected working directory.

**Resolution:**
1. Verify that `.env` exists in the project root.
2. Confirm the variable names are `VT_API_KEY` and `ABUSEIPDB_API_KEY`.
3. Check that the values are valid API keys.
4. Ensure that `.env` contains no placeholder values in place of real local credentials.
5. Run the application from the project root.

**Security note:** Never print or share the real key while troubleshooting.

## 2. API Authentication or Permission Failure

**Possible symptom:**

```text
VirusTotal rejected the API key.
```

or:

```text
AbuseIPDB rejected the API key.
```

**Possible causes:**
- The key is invalid or expired.
- The wrong key was copied.
- The account does not have the required API access.

**Resolution:**
1. Check the relevant provider's account dashboard.
2. Verify the key locally without displaying it in screenshots or logs.
3. Confirm that the endpoint and authentication header match the provider's API documentation.
4. Retry with an authorized key.

For HTTP 403 responses, also verify account permissions and endpoint access.

## 3. API Rate Limit or Quota Reached

**Possible symptom:**

```text
VirusTotal rate limit or quota reached.
```

or:

```text
AbuseIPDB rate limit or quota reached.
```

**Possible causes:**
- Too many requests were made in a short period.
- The account's daily or monthly quota was exhausted.
- The provider restricted access.

**Resolution:**
1. Stop repeated retries.
2. Check the provider's current quota and usage information.
3. Wait until the permitted request window resets, if applicable.
4. Use mocked responses for ordinary unit tests.
5. Consider caching previously retrieved results in a future version.

**Learning:** A rate-limit error is an API access limitation, not necessarily a defect in the application's scoring or aggregation logic.

## 4. Network Timeout or Connection Failure

**Possible symptom:**

```text
VirusTotal request timed out. Try again later.
```

or:

```text
Could not connect to AbuseIPDB.
```

**Possible causes:**
- Internet connectivity is unavailable.
- The provider is temporarily unavailable.
- A firewall, proxy, or network policy is blocking the request.
- The connection took longer than the configured timeout.

**Resolution:**
1. Confirm that the computer has internet access.
2. Check the provider's service status if available.
3. Verify that the system's network and proxy settings permit HTTPS requests.
4. Retry after a short interval.
5. Run mocked tests to check local code independently of network availability.

The provider modules use request timeouts so the application does not wait indefinitely.

## 5. Indicator Validation Error

**Possible symptom:**

```text
Error: Invalid indicator ...
```

**Possible causes:**
- The input is malformed.
- A domain contains an invalid format.
- A file hash has the wrong length or contains unsupported characters.
- Extra whitespace or an incorrect value was entered.

**Resolution:**
1. Verify the indicator format.
2. Use a valid IPv4 or IPv6 address, domain, or supported file hash.
3. Review the validator's accepted formats.
4. Run the validator tests:

```powershell
python -m pytest -v tests/test_validator.py
```

Validation should occur before external API requests.

## 6. No Report Found

**Possible symptom:**

```text
No report was found for this indicator.
```

**Possible causes:**
- The provider has no report for the submitted indicator.
- The resource is unavailable through the current endpoint.
- The indicator type or value is incorrect.

**Resolution:**
1. Recheck the indicator.
2. Review the provider's report directly using its official interface.
3. Record the missing result as unavailable rather than interpreting it as evidence of safety.
4. Investigate using additional sources when appropriate.

## 7. Unexpected or Invalid API Response

**Possible symptom:**

```text
VirusTotal returned an invalid JSON response.
```

or:

```text
AbuseIPDB returned an unexpected response format.
```

**Possible causes:**
- The server returned an unexpected response.
- The API response format changed.
- An error response was not structured as expected.

**Resolution:**
1. Check the HTTP status code.
2. Review the provider's current API documentation.
3. Inspect the response structure locally without logging credentials.
4. Update the response parser if the API schema has changed.
5. Add a mocked regression test for the new response format.

## 8. Provider Failure During Aggregation

**Expected behavior:** A failure from one provider should be recorded without discarding the successful result from the other provider.

**Troubleshooting steps:**
1. Inspect `provider_results` in the generated report.
2. Inspect `provider_errors` to identify the failing provider.
3. Check that the relevant API key and network access are configured.
4. Run the aggregator tests:

```powershell
python -m pytest -v tests/test_aggregator.py
```

5. Verify that a provider failure does not silently produce a false claim that the indicator is safe.

## 9. Unexpected Risk Score

**Possible causes:**
- One provider returned no usable scoring data.
- Analysis statistics were unavailable.
- The provider scores differ.
- The score was calculated from only one source.

**Resolution:**
1. Inspect the raw provider results.
2. Verify the available VirusTotal analysis statistics.
3. Check the AbuseIPDB confidence score.
4. Confirm how many sources contributed to the final score.
5. Review the thresholds in `src/scoring.py`.

The score is a heuristic. A low score does not guarantee that an indicator is benign, and an unknown score does not mean the indicator is safe.

## 10. Automated Tests Fail

**Diagnostic command:**

```powershell
python -m pytest -v
```

**Resolution:**
1. Read the first failing test and its traceback.
2. Identify the affected module.
3. Check whether the failure is caused by a changed function, incorrect test expectation, missing dependency, or unintended code change.
4. Run the relevant test file separately.
5. Re-run the complete test suite after the fix.

Examples:

```powershell
python -m pytest -v tests/test_virustotal.py
python -m pytest -v tests/test_abuseipdb.py
python -m pytest -v tests/test_aggregator.py
python -m pytest -v tests/test_scoring.py
python -m pytest -v tests/test_report.py
```

Unit tests use mocked responses to avoid consuming provider quotas unnecessarily.

## 11. Python Module Import Errors

**Possible symptom:**

```text
ModuleNotFoundError
```

**Possible causes:**
- The command was executed from the wrong directory.
- The virtual environment is not active.
- A dependency is missing.
- The package or file structure is incorrect.

**Resolution:**
1. Change to the project root:

```powershell
cd D:\osint-threat-aggregator
```

2. Activate the virtual environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

3. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

4. Run the application using module syntax:

```powershell
python -m src.main 8.8.8.8
```

## 12. `.env` Accidentally Appears in Git Status

**Diagnostic commands:**

```powershell
git check-ignore .env
git ls-files .env
```

**Expected behavior:**
- `git check-ignore .env` prints `.env`.
- `git ls-files .env` prints nothing.

**Resolution if the file is not ignored:**
1. Add `.env` to `.gitignore`.
2. Check whether the file is already tracked.
3. If it was tracked, remove it from Git's index without deleting the local file:

```powershell
git rm --cached .env
```

4. Commit the ignore-rule change.

If a real API key has already been pushed to a public repository, revoke or rotate it immediately. Removing the file from a later commit does not erase the exposed secret from Git history.

## 13. Git Commit or Push Failure

**Diagnostic command:**

```powershell
git status
```

**Resolution:**
1. Check which files are modified, staged, or untracked.
2. Stage only the intended project files.
3. Never stage `.env` or other files containing credentials.
4. Read the Git error message before retrying.
5. Verify the remote URL when necessary:

```powershell
git remote -v
```

6. After a successful push, confirm the latest commit appears on GitHub.

## General Troubleshooting Principle

When an error occurs, record:
- The command that was executed.
- The exact error message, with secrets redacted.
- The likely cause.
- The corrective action taken.
- The test or command used to verify the fix.

Only mark a problem as resolved after verifying the result.