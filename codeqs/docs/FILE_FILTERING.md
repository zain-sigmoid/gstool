# File Filtering Documentation

## Virtual Environment & Package Exclusions

The consolidated code review tool automatically excludes common virtual environment directories and package installations when scanning codebases. This ensures analysis focuses on actual source code rather than installed dependencies.

## Excluded Directories

### Virtual Environments
- `venv/`, `.venv/`
- `env/`, `.env/` 
- `virtualenv/`, `pyvenv/`, `.pyvenv/`
- `venv2/`, `venv3/`

### Python Package Directories
- `site-packages/`
- `__pycache__/`
- `.pytest_cache/`
- `egg-info/`, `.eggs/`
- `build/`, `dist/`

### Version Control
- `.git/`, `.svn/`, `.hg/`, `.bzr/`

### IDE and Editor Directories
- `.vscode/`, `.idea/`, `.vs/`

### Build and Cache Directories
- `.mypy_cache/`, `.coverage/`
- `.tox/`, `.nox/`
- `htmlcov/`
- `docs/_build/`

### Mixed Projects
- `node_modules/` (for projects with both Python and Node.js)

## Detection Logic

The system uses multiple detection methods:

1. **Directory name matching**: Direct comparison against known exclusion patterns
2. **Virtual environment detection**: Looks for `pyvenv.cfg`, `bin/activate`, `Scripts/activate.bat`
3. **Structure analysis**: Identifies `lib/python*` and `include/python*` directories

## Customization

You can customize the filtering behavior:

```python
from core.file_utils import CodebaseFileFilter

# Create custom filter
filter = CodebaseFileFilter()

# Add custom exclusions
filter.add_excluded_directory("my_custom_env")

# Remove default exclusions (if needed)
filter.remove_excluded_directory("build")

# Use custom filter
files = filter.find_python_files("/path/to/project")
```

## Benefits

- **Faster analysis**: Skip thousands of package files
- **Relevant results**: Focus on actual source code
- **Reduced noise**: Eliminate false positives from dependencies
- **Better performance**: Significantly reduced file count for large projects

## Example

Before filtering:
```
project/
├── src/main.py                    ← Analyzed ✅
├── tests/test_main.py             ← Analyzed ✅  
├── venv/lib/python3.10/           ← Skipped ❌
│   └── site-packages/numpy/...    ← Skipped ❌
└── __pycache__/main.cpython-310.pyc ← Skipped ❌
```

After filtering: Only `src/main.py` and `tests/test_main.py` are analyzed.