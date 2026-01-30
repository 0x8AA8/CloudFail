# TASK-001: Upgrade to Python 3.11.7+ and fix all issues

## Objective
Update the entire CloudFail project to require and run on Python 3.11.7+ and fix all known bugs, errors, and issues. The end state must be stable, documented, and runnable on Python 3.11.7+.

## Scope
- All source files in the repo, including `cloudfail.py`, `DNSDumpsterAPI.py`, `socks.py`, `sockshandler.py`.
- Tooling and docs: `requirements.txt`, `Dockerfile`, `README.md`.
- Data files in `data/` may be referenced for correctness only (do not mutate unless explicitly required for a fix).

## Strict rules
- Do not remove features or reduce functionality unless a security or correctness fix requires it.
- Do not add network calls beyond what already exists; preserve the existing behavior.
- Do not introduce non-ASCII characters unless the file already contains them.
- Do not change the project name, CLI flags, or output format unless required for correctness.
- Fix issues with minimal, well-justified changes.
- Any new dependency must be justified and documented in `README.md`.
- All edits must be consistent with Python 3.11.7+ behavior.

## Required fixes (must address all)
1) Windows detection bug in `cloudfail.py`:
   - Current code uses `platform == 'Windows'` which is always false because `platform` is a module.
   - Fix to use `platform.system() == 'Windows'` or equivalent.

2) NameError in TOR failure path:
   - `print(e, net_exc)` references undefined `net_exc`.
   - Replace with a safe, defined error output.

3) Subdomain scan progress math:
   - Guard against division by zero if subdomain list has fewer than 100 lines.

4) Subdomain list counting mismatch:
   - When `--subdomains` is provided, progress counting still reads `data/subdomains.txt`.
   - Use the selected list consistently and ensure files are properly closed.

5) Deprecated SSL usage:
   - Replace `ssl.wrap_socket` usage in `sockshandler.py` with `ssl.SSLContext` equivalents.

6) Python 3.11 compatibility cleanup:
   - Remove or modernize any Python 2 compatibility or deprecated patterns that are unnecessary in Python 3.11.
   - Ensure `collections.Callable` hack is removed if no longer needed and does not break runtime.

## Python 3.11.7+ upgrade requirements
- Declare a minimum Python version requirement of 3.11.7+ in documentation.
- Update the Dockerfile to use a Python 3.11.7+ base or install 3.11.7+ explicitly.
- If applicable, add a `pyproject.toml` or similar metadata to pin the Python requirement (only if doing so does not break existing workflows).

## Dependency requirements
- Update `requirements.txt` to modern versions compatible with Python 3.11.7+.
- Remove redundant or obsolete dependencies (e.g., avoid both `bs4` and `beautifulsoup4` unless strictly required).
- Ensure `requests`, `urllib3`, `certifi`, `idna`, `chardet`/`charset-normalizer`, `dnspython`, `colorama`, `win_inet_pton` versions are compatible with Python 3.11.

## Documentation updates
- Update `README.md` to explicitly state Python 3.11.7+ requirement.
- Update install instructions to reflect any changes in dependencies or commands.
- If the Dockerfile is updated, include a brief note in README.

## Quality bar / acceptance criteria
- All code paths run without syntax errors under Python 3.11.7+.
- The CLI starts without crashing for both normal and `--tor` modes (tor connectivity failures must be handled gracefully).
- Subdomain scan progress output works for small and large lists.
- Windows-specific IP parsing works on Windows.
- Deprecated API usage is removed or replaced with 3.11-compatible equivalents.
- `requirements.txt` installs cleanly on Python 3.11.7+.

## Deliverables
- Code changes committed (or ready to commit) covering all fixes.
- Updated `requirements.txt`, `Dockerfile`, and `README.md`.
- A short change summary at the top of this task file when done (append a completion note and list of modified files).

## Notes
- Keep behavior and output as close to the original as possible.
- Be explicit in code where a bug fix changes behavior; add minimal comments if needed.
