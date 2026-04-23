# Publish to PyPI

Quick guide for publishing new versions to PyPI after making changes.

## Prerequisites

- PyPI account: https://pypi.org
- API token generated from Account Settings

## Steps

### 1. Update Version

Edit `pyproject.toml` and bump the version:

```toml
[project]
name = "cache-wraith-audit-tool"
version = "1.0.2"  # ← bump this
```

**PyPI doesn't allow re-uploading the same version!**

### 2. Build Distribution

```bash
# Clean old builds first
rm -rf dist/ build/ *.egg-info

# Build new wheel and sdist
python -m build
```

### 3. Upload to PyPI

```bash
twine upload dist/*
```

Enter your API token when prompted.

### 4. Verify

Check your package:
- https://pypi.org/project/cache-wraith-audit-tool/

Test installation:
```bash
pipx install cache-wraith-audit-tool
```

## Quick Command List

```bash
# One-liner to bump, build, upload
# (update version in pyproject.toml first!)
rm -rf dist/ build/ && python -m build && twine upload dist/*
```

## Troubleshooting

| Error | Solution |
|-------|----------|
| `HTTPError: 400 Bad Request` | Version already exists — bump version in `pyproject.toml` |
| `No module named twine` | `pipx install twine` |
| `twine: command not found` | Use `~/.local/bin/twine` or reinstall with pipx |

## Install Tools (First Time)

```bash
pipx install build
pipx install twine
```
