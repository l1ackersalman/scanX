# scanX — Project Instructions for Claude Code

## Project vision

Build scanX, a portable, Django-based web application for authorized security reconnaissance.

The project already has a working Bash reconnaissance script. The first objective is to integrate that script into a web interface without changing its existing functionality.

Development must happen incrementally. Do not attempt to build the entire platform in one implementation.

## Existing technology

- Python and Django
- SQLite
- Bootstrap and custom CSS
- Bash scanner
- Linux environment
- Git and GitHub
- NVIDIA Nemotron through Claude Code

## Source files

- `scanner/scanx.sh` — original Bash scanner. Treat this as the source of truth for existing scan behaviour.
- `docs/ui-reference.html` — UI design reference. Reuse its visual language and layout where appropriate.

Do not silently rewrite, remove, or replace existing scanner functionality.

## Development principles

1. Work in small, independently testable phases.
2. Inspect the existing code before modifying it.
3. Explain the proposed changes before implementing substantial changes.
4. Do not invent scanner features that are not in the existing script.
5. Preserve existing tool arguments, output behaviour, and error handling unless a change is necessary and explained.
6. Keep application code modular and maintainable.
7. Avoid unnecessary dependencies.
8. Never put API keys, tokens, or passwords in source code.
9. Keep scan data and generated output separate from source code.
10. Update README and tests when functionality changes.
11. Never claim a feature works without testing it.
12. Do not modify unrelated files.

## Phase 1 — Initial working scanner

This phase is the highest priority.

Build only the following:

- Django project and application.
- Simple dashboard with a scan form.
- Domain input and validation.
- Start scan action.
- Background execution of the original Bash scanner.
- Live scan output/log display.
- Scan status: pending, running, completed, failed.
- Scan history.
- Access to the original scan output.
- Basic download of the generated output.

The web application must invoke the existing Bash script rather than reimplementing its reconnaissance logic in Python.

Use a separate worker process for long-running scans. Do not run the scanner directly inside a normal Django HTTP request.

Use safe subprocess execution:
- Pass arguments as a list.
- Do not use `shell=True`.
- Set execution timeouts and handle termination.
- Capture standard output and standard error.
- Handle missing tools and non-zero exit codes.
- Prevent concurrent scans from corrupting shared output files.

## Phase 1 UI

Use `docs/ui-reference.html` as the visual reference.

Preserve its general design language:
- Dark-first interface.
- Lime-green accent.
- Clean cards and borders.
- Responsive layout.
- Header and navigation structure.
- Consistent spacing and typography.

Do not implement every navigation item yet. Keep future sections as placeholders only if useful. The first usable page should focus on starting and monitoring scans.

## Portability

Design for installation on another Linux device.

- Avoid absolute paths tied to the developer's home directory.
- Use project-relative paths and configurable settings.
- Provide dependency checks.
- Provide an installation script.
- Provide a start script.
- Keep secrets in environment variables.
- Provide `.env.example`, not a real secret file.
- Keep scan outputs in a configurable data directory.
- Document external tool prerequisites and versions.
- Do not assume that a Go binary exists at one particular path.

## Security and scope

This is an authorized reconnaissance tool.

- Require a valid target domain.
- Require explicit confirmation that the user is authorized to scan it.
- Never allow arbitrary shell commands through the web interface.
- Restrict scans to explicitly authorized targets.
- Validate target scope before active probing.
- Do not allow the web application to become an unrestricted proxy or command-execution interface.
- Do not expose secrets in logs or HTTP responses.

## GitHub workflow

- Keep `main` stable.
- Use feature branches for new work.
- Make small, meaningful commits.
- Never commit `.env`, secrets, databases, or generated scan output.
- Add tests before merging significant changes.
- Update documentation for new features.

## How to work

At the beginning of each phase:

1. Inspect the current repository.
2. Identify what already exists.
3. Describe the planned implementation.
4. List the files that need to change.
5. Identify potential compatibility or security problems.
6. Wait for approval before large architectural changes.

After implementation:

1. Run relevant tests.
2. Run Django checks.
3. Test the actual scanner integration where safe.
4. Report exactly what works and what remains incomplete.
5. Summarize modified files.
6. Suggest the next smallest development step.

## Current priority

Implement Phase 1 only.

Do not build target management, screenshots, AI agents, technology detection, vulnerability scanning, or advanced reporting yet.

First deliver a reliable web interface that runs the existing Bash scanner and presents its actual results.
