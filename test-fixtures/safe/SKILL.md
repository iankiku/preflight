---
name: Safe Test Skill
description: A skill following security best practices
version: "1.0"
author: Test Author
tags:
  - testing
  - safe
---

# Safe Test Skill

This skill demonstrates secure patterns.

## Usage

Provide clear instructions without prompt injection patterns.

## Code Examples

```python
# Safe: Using validated input
def process_data(data: str) -> str:
    validated = validate_input(data)
    return transform(validated)
```

```bash
# Safe: No command substitution, no pipes to shell
echo "Processing files..."
ls -la ./data/
```

## Best Practices

- Always validate input
- Never use eval
- Use environment variables for secrets (not hardcoded)
