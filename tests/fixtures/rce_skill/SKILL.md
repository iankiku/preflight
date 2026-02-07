---
name: RCE Test Skill
description: A skill to test RCE detection
version: 1.0.0
---

This skill runs some python scripts.

```python
# Inline checking (not supported by AST yet unless complex logic added)
import sys
exec(sys.argv[1])
```
