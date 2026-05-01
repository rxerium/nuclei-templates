#!/usr/bin/env python3
"""
Phishing Template Update Script
Updates phishing templates with new dual matchers based on validation results.
"""

import json
import yaml
import re
from pathlib import Path
from typing import Dict, List

PHISHING_DIR = Path("http/osint/phishing")
UPDATES_JSON = Path("templates_to_update.json")


def load_updates() -> Dict:
    """Load the updates JSON file."""
    with open(UPDATES_JSON, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_template_raw(template_path: Path) -> str:
    """Load template as raw text to preserve formatting."""
    with open(template_path, 'r', encoding='utf-8') as f:
        return f.read()


def update_template(template_path: Path, suggested_matchers: List[Dict], current_title: str) -> bool:
    """Update a template with new dual matchers."""
    try:
        # Load raw template content
        content = load_template_raw(template_path)
        
        # Parse YAML to get structure
        template_data = yaml.safe_load(content)
        
        if 'http' not in template_data or not template_data['http']:
            print(f"  ✗ No HTTP section found in {template_path.name}")
            return False
        
        # Check if template already has 2+ word matchers
        word_matchers = []
        for matcher in template_data['http'][0].get('matchers', []):
            if matcher.get('type') == 'word':
                word_matchers.append(matcher)
        
        if len(word_matchers) >= 2:
            print(f"  ℹ Template already has {len(word_matchers)} word matchers, skipping")
            return False
        
        # Build new matchers section
        new_matchers = []
        
        # Add title matcher (from suggested matchers or current title)
        title_matcher = None
        for sm in suggested_matchers:
            if sm.get('part') == 'header' or not sm.get('part'):
                title_matcher = sm
                break
        
        if not title_matcher and current_title:
            title_matcher = {
                'type': 'word',
                'part': 'header',
                'words': [current_title]
            }
        
        if title_matcher:
            new_matchers.append(title_matcher)
        
        # Add body/description matcher
        body_matcher = None
        for sm in suggested_matchers:
            if sm.get('part') == 'body':
                body_matcher = sm
                break
        
        if body_matcher:
            new_matchers.append(body_matcher)
        
        # If we don't have 2 matchers, we can't proceed
        if len(new_matchers) < 2:
            print(f"  ✗ Could not generate 2 matchers for {template_path.name}")
            return False
        
        # Build the new matchers YAML snippet
        matchers_yaml = "    matchers:\n"
        
        for i, matcher in enumerate(new_matchers):
            matchers_yaml += "      - type: word\n"
            if 'part' in matcher:
                matchers_yaml += f"        part: {matcher['part']}\n"
            matchers_yaml += "        words:\n"
            for word in matcher['words']:
                # Escape single quotes in YAML
                word_escaped = word.replace("'", "''")
                matchers_yaml += f"          - '{word_escaped}'\n"
            if i < len(new_matchers) - 1:
                matchers_yaml += "\n"
        
        # Find and replace the existing word matcher section
        # Pattern: Find the first word matcher block
        pattern = r'(    matchers:\n)((?:      - type: word\n(?:        (?:words|condition|part):.*\n)*(?:          - .*\n)*)+)'
        
        # Check if pattern exists
        if re.search(pattern, content):
            # Replace only the word matcher, keep status and dsl matchers
            def replacer(match):
                # Keep the "matchers:" line and replace everything until the next non-word matcher
                original = match.group(0)
                
                # Find where the word matchers end
                lines = original.split('\n')
                replacement_lines = matchers_yaml.rstrip('\n').split('\n')
                
                return '\n'.join(replacement_lines) + '\n'
            
            # Use a more specific pattern to replace just word matchers
            word_matcher_pattern = r'(      - type: word\n(?:        (?:words|condition|part):.*\n)*(?:          - .*\n)*(?:\n)?)'
            
            # Count how many word matchers exist
            existing_word_matchers = re.findall(word_matcher_pattern, content)
            
            # Replace the first word matcher with our new dual matchers
            content_updated = re.sub(word_matcher_pattern, '', content, count=len(existing_word_matchers))
            
            # Now insert the new matchers after "matchers:\n"
            content_updated = re.sub(
                r'(    matchers:\n)',
                matchers_yaml,
                content_updated,
                count=1
            )
        else:
            print(f"  ✗ Could not find matcher pattern in {template_path.name}")
            return False
        
        # Write updated content
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(content_updated)
        
        print(f"  ✓ Updated {template_path.name}")
        return True
        
    except Exception as e:
        print(f"  ✗ Error updating {template_path.name}: {e}")
        return False


def main():
    """Main update workflow."""
    print("=" * 80)
    print("Phishing Template Update Script")
    print("=" * 80)
    
    # Load updates
    if not UPDATES_JSON.exists():
        print(f"\n✗ Updates file not found: {UPDATES_JSON}")
        print("  Please run validate_phishing_templates.py first.")
        return
    
    updates_data = load_updates()
    templates_to_update = updates_data.get('templates', [])
    
    print(f"\nFound {len(templates_to_update)} templates to update\n")
    
    if not templates_to_update:
        print("No templates need updating!")
        return
    
    updated_count = 0
    skipped_count = 0
    error_count = 0
    
    for template_data in templates_to_update:
        template_name = template_data['template_name']
        template_path = PHISHING_DIR / f"{template_name}.yaml"
        
        print(f"Updating: {template_name}")
        
        if not template_path.exists():
            print(f"  ✗ Template file not found: {template_path}")
            error_count += 1
            continue
        
        # Skip if WAF blocked or error status
        if template_data['status'] in ['waf_blocked', 'error']:
            print(f"  ⊘ Skipping (status: {template_data['status']})")
            skipped_count += 1
            continue
        
        suggested_matchers = template_data.get('suggested_matchers', [])
        current_title = template_data.get('title', '')
        
        if update_template(template_path, suggested_matchers, current_title):
            updated_count += 1
        else:
            error_count += 1
        
        print()
    
    # Summary
    print("=" * 80)
    print("Update Complete")
    print("=" * 80)
    print(f"\nTotal: {len(templates_to_update)}")
    print(f"  Updated: {updated_count}")
    print(f"  Skipped: {skipped_count}")
    print(f"  Errors: {error_count}")


if __name__ == "__main__":
    main()
