# HTML Debugger

A comprehensive Python script for debugging and analyzing HTML files. It detects common issues, validates structure, and provides detailed reports.

## Features

✅ **Structure Validation**
- Checks for DOCTYPE, html, head, body, and title tags
- Validates meta charset declaration

✅ **Tag Analysis**
- Detects unclosed tags
- Identifies mismatched closing tags
- Warns about deprecated HTML tags (center, font, etc.)
- Validates self-closing tags

✅ **Attribute Validation**
- Checks for missing `alt` attributes in `<img>` tags
- Validates `href` attributes in `<a>` tags
- Detects duplicate ID attributes

✅ **Detailed Reporting**
- Line-by-line error reporting
- Categorized errors and warnings
- Summary statistics

## Installation

No external dependencies required! Uses Python's built-in libraries.

```bash
# Make the script executable (optional)
chmod +x html_debugger.py
```

## Usage

### Basic Usage

```bash
python3 html_debugger.py index.html
```

### Verbose Mode

```bash
python3 html_debugger.py index.html -v
```

### Multiple Files

```bash
python3 html_debugger.py index.html about.html contact.html
```

### Using Wildcards

```bash
python3 html_debugger.py *.html
```

## Example Output

```
============================================================
HTML Debugger - Analyzing: sample.html
============================================================

❌ ERRORS (2):
------------------------------------------------------------
  • Missing <html> tag
  • Line 10: Unclosed tag '<div>'

⚠️  WARNINGS (3):
------------------------------------------------------------
  • Missing charset meta tag
  • Line 12: <img> tag missing 'alt' attribute
  • Line 15: Duplicate ID 'content'

============================================================
Summary: 2 error(s), 3 warning(s)
============================================================
```

## What It Checks

### Errors (Critical Issues)
- Missing essential HTML structure tags
- Unclosed tags
- Mismatched closing tags
- Closing tags without opening tags

### Warnings (Best Practices)
- Missing DOCTYPE declaration
- Missing charset meta tag
- Missing title tag
- Deprecated HTML tags
- Missing alt attributes on images
- Missing href attributes on links
- Duplicate ID attributes

## Command Line Options

```
usage: html_debugger.py [-h] [-v] files [files ...]

positional arguments:
  files          HTML file(s) to analyze

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Show verbose output with additional information
```

## Examples

### Example 1: Check a single file
```bash
python3 html_debugger.py index.html
```

### Example 2: Check with verbose output
```bash
python3 html_debugger.py index.html -v
```

### Example 3: Check all HTML files in directory
```bash
python3 html_debugger.py *.html
```

## Tips

1. **Fix errors first**: Address critical errors before warnings
2. **Line numbers**: Use the line numbers to quickly locate issues
3. **Batch processing**: Check multiple files at once for consistency
4. **Verbose mode**: Use `-v` flag for additional statistics

## Common Issues Detected

| Issue | Type | Description |
|-------|------|-------------|
| Unclosed tags | Error | Tags that are opened but never closed |
| Mismatched tags | Error | Closing tags that don't match opening tags |
| Duplicate IDs | Warning | Multiple elements with the same ID |
| Missing alt | Warning | Images without alt text (accessibility) |
| Deprecated tags | Warning | Old HTML tags that shouldn't be used |
| Missing charset | Warning | No character encoding specified |

## License

Free to use and modify.
