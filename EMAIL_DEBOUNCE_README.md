# Email Debounce Checker

A Python script to validate email addresses by checking syntax, DNS/MX records, and optionally performing SMTP verification.

## Features

- ✅ **Syntax Validation**: Validates email format using regex patterns
- ✅ **DNS/MX Record Check**: Verifies domain exists and has valid mail servers
- ✅ **SMTP Verification**: Optional deep verification by connecting to mail servers
- ✅ **Bulk Processing**: Check multiple emails at once
- ✅ **File Input**: Read emails from a text file
- ✅ **JSON Output**: Export results in JSON format

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

Or install directly:
```bash
pip install dnspython
```

## Usage

### Basic Usage

Check a single email:
```bash
python3 email_debounce_checker.py user@example.com
```

### Check Multiple Emails

```bash
python3 email_debounce_checker.py user1@gmail.com user2@yahoo.com user3@outlook.com
```

### Check from File

Create a file with emails (one per line):
```bash
echo "user1@gmail.com" > emails.txt
echo "user2@yahoo.com" >> emails.txt
echo "invalid@fakedomain123.com" >> emails.txt

python3 email_debounce_checker.py --file emails.txt
```

### Enable SMTP Verification

⚠️ **Warning**: SMTP verification is slower and may be blocked by some mail servers

```bash
python3 email_debounce_checker.py user@example.com --smtp
```

### JSON Output

```bash
python3 email_debounce_checker.py user@example.com --json
```

### Custom Timeout

```bash
python3 email_debounce_checker.py user@example.com --timeout 5
```

## Options

```
positional arguments:
  emails                Email address(es) to check

optional arguments:
  -h, --help            Show help message
  --file, -f FILE       File containing email addresses (one per line)
  --smtp                Enable SMTP verification (slower)
  --timeout TIMEOUT     Timeout in seconds (default: 10)
  --json                Output results in JSON format
```

## Example Output

```
Checking 1 email(s)...

============================================================
Email: user@gmail.com
Status: ✓ VALID
============================================================
Syntax Check: ✓ Valid syntax
DNS Check: ✓ Found 5 MX record(s)
MX Records:
  - gmail-smtp-in.l.google.com
  - alt1.gmail-smtp-in.l.google.com
  - alt2.gmail-smtp-in.l.google.com

============================================================
Summary: 1/1 valid email(s)
============================================================
```

## Validation Levels

1. **Syntax Check**: 
   - Validates email format
   - Checks local part and domain length
   - Ensures proper structure

2. **DNS Check**:
   - Verifies domain exists
   - Checks for MX (Mail Exchange) records
   - Lists available mail servers

3. **SMTP Check** (Optional):
   - Connects to mail server
   - Verifies mailbox exists
   - Does NOT send actual emails

## Common Use Cases

- **Email List Cleaning**: Remove invalid emails from mailing lists
- **Form Validation**: Verify emails during user registration
- **Data Quality**: Ensure email data integrity in databases
- **Bounce Prevention**: Reduce email bounce rates

## Limitations

- SMTP verification may be blocked by some mail servers
- Some domains use catch-all addresses (accept all emails)
- Rate limiting may apply for bulk checks
- Temporary DNS issues may cause false negatives

## Exit Codes

- `0`: Success
- `1`: Error (missing arguments, file not found, etc.)

## License

Free to use and modify.
