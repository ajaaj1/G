#!/usr/bin/env python3
"""
HTML Debugger - A comprehensive tool for debugging and analyzing HTML files
"""

import re
import sys
from html.parser import HTMLParser
from typing import List, Dict, Tuple
import argparse


class HTMLDebugger(HTMLParser):
    """Enhanced HTML parser for debugging purposes"""
    
    def __init__(self):
        super().__init__()
        self.errors = []
        self.warnings = []
        self.tag_stack = []
        self.line_num = 1
        self.ids = set()
        self.duplicate_ids = []
        self.unclosed_tags = []
        self.self_closing_tags = {
            'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 
            'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'
        }
        self.deprecated_tags = {
            'acronym', 'applet', 'basefont', 'big', 'center', 'dir',
            'font', 'frame', 'frameset', 'noframes', 'strike', 'tt'
        }
        
    def handle_starttag(self, tag, attrs):
        """Handle opening tags"""
        # Check for deprecated tags
        if tag in self.deprecated_tags:
            self.warnings.append(
                f"Line {self.getpos()[0]}: Deprecated tag '<{tag}>' found"
            )
        
        # Track non-self-closing tags
        if tag not in self.self_closing_tags:
            self.tag_stack.append((tag, self.getpos()[0]))
        
        # Check for duplicate IDs
        attrs_dict = dict(attrs)
        if 'id' in attrs_dict:
            id_value = attrs_dict['id']
            if id_value in self.ids:
                self.duplicate_ids.append(
                    f"Line {self.getpos()[0]}: Duplicate ID '{id_value}'"
                )
            else:
                self.ids.add(id_value)
        
        # Check for missing alt attribute in img tags
        if tag == 'img' and 'alt' not in attrs_dict:
            self.warnings.append(
                f"Line {self.getpos()[0]}: <img> tag missing 'alt' attribute"
            )
        
        # Check for missing href in anchor tags
        if tag == 'a' and 'href' not in attrs_dict:
            self.warnings.append(
                f"Line {self.getpos()[0]}: <a> tag missing 'href' attribute"
            )
    
    def handle_endtag(self, tag):
        """Handle closing tags"""
        if tag in self.self_closing_tags:
            return
            
        if not self.tag_stack:
            self.errors.append(
                f"Line {self.getpos()[0]}: Unexpected closing tag '</{tag}>'"
            )
            return
        
        # Check if closing tag matches the most recent opening tag
        if self.tag_stack and self.tag_stack[-1][0] == tag:
            self.tag_stack.pop()
        else:
            # Try to find matching opening tag
            found = False
            for i in range(len(self.tag_stack) - 1, -1, -1):
                if self.tag_stack[i][0] == tag:
                    self.errors.append(
                        f"Line {self.getpos()[0]}: Mismatched closing tag '</{tag}>' "
                        f"(opened at line {self.tag_stack[i][1]})"
                    )
                    self.tag_stack.pop(i)
                    found = True
                    break
            
            if not found:
                self.errors.append(
                    f"Line {self.getpos()[0]}: Closing tag '</{tag}>' without matching opening tag"
                )
    
    def handle_data(self, data):
        """Handle text data"""
        pass
    
    def handle_comment(self, data):
        """Handle HTML comments"""
        pass
    
    def error(self, message):
        """Handle parsing errors"""
        self.errors.append(f"Parse error: {message}")
    
    def get_unclosed_tags(self):
        """Get list of unclosed tags"""
        return [
            f"Line {line}: Unclosed tag '<{tag}>'"
            for tag, line in self.tag_stack
        ]


def check_html_structure(html_content: str) -> Dict:
    """
    Check HTML structure for common issues
    """
    results = {
        'errors': [],
        'warnings': [],
        'info': []
    }
    
    # Check for DOCTYPE
    if not re.search(r'<!DOCTYPE\s+html', html_content, re.IGNORECASE):
        results['warnings'].append("Missing DOCTYPE declaration")
    
    # Check for html tag
    if not re.search(r'<html', html_content, re.IGNORECASE):
        results['errors'].append("Missing <html> tag")
    
    # Check for head tag
    if not re.search(r'<head', html_content, re.IGNORECASE):
        results['errors'].append("Missing <head> tag")
    
    # Check for body tag
    if not re.search(r'<body', html_content, re.IGNORECASE):
        results['errors'].append("Missing <body> tag")
    
    # Check for title tag
    if not re.search(r'<title', html_content, re.IGNORECASE):
        results['warnings'].append("Missing <title> tag in <head>")
    
    # Check for meta charset
    if not re.search(r'<meta\s+charset', html_content, re.IGNORECASE):
        results['warnings'].append("Missing charset meta tag")
    
    return results


def analyze_html(file_path: str, verbose: bool = False) -> None:
    """
    Analyze HTML file and report issues
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
    except FileNotFoundError:
        print(f"❌ Error: File '{file_path}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        sys.exit(1)
    
    print(f"\n{'='*60}")
    print(f"HTML Debugger - Analyzing: {file_path}")
    print(f"{'='*60}\n")
    
    # Check basic structure
    structure_results = check_html_structure(html_content)
    
    # Parse HTML
    parser = HTMLDebugger()
    try:
        parser.feed(html_content)
    except Exception as e:
        print(f"⚠️  Parser exception: {e}")
    
    # Collect all issues
    all_errors = structure_results['errors'] + parser.errors
    all_warnings = (structure_results['warnings'] + 
                   parser.warnings + 
                   parser.duplicate_ids +
                   parser.get_unclosed_tags())
    
    # Display results
    if all_errors:
        print(f"❌ ERRORS ({len(all_errors)}):")
        print("-" * 60)
        for error in all_errors:
            print(f"  • {error}")
        print()
    
    if all_warnings:
        print(f"⚠️  WARNINGS ({len(all_warnings)}):")
        print("-" * 60)
        for warning in all_warnings:
            print(f"  • {warning}")
        print()
    
    if not all_errors and not all_warnings:
        print("✅ No issues found! Your HTML looks good.")
    
    # Summary
    print(f"{'='*60}")
    print(f"Summary: {len(all_errors)} error(s), {len(all_warnings)} warning(s)")
    print(f"{'='*60}\n")
    
    # Verbose output
    if verbose:
        print("\n📊 Additional Information:")
        print(f"  • Total unique IDs: {len(parser.ids)}")
        print(f"  • File size: {len(html_content)} bytes")
        print(f"  • Lines: {html_content.count(chr(10)) + 1}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Debug and analyze HTML files for common issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python html_debugger.py index.html
  python html_debugger.py index.html -v
  python html_debugger.py *.html
        """
    )
    
    parser.add_argument(
        'files',
        nargs='+',
        help='HTML file(s) to analyze'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show verbose output with additional information'
    )
    
    args = parser.parse_args()
    
    # Process each file
    for file_path in args.files:
        analyze_html(file_path, args.verbose)
        if len(args.files) > 1:
            print("\n")


if __name__ == '__main__':
    main()
