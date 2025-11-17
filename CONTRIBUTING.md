# Contributing to RedTeam Penetration Testing Framework

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and professional
- Follow responsible disclosure practices
- Use the framework ethically and legally
- Help others learn and improve

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported
2. Create a detailed issue with:
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - System information
   - Logs/screenshots if applicable

### Suggesting Features

1. Check existing issues and pull requests
2. Create an issue describing:
   - Use case
   - Proposed solution
   - Benefits
   - Potential drawbacks

### Contributing Code

#### Plugin Development

1. Follow the [Plugin Development Guide](docs/PLUGIN_DEVELOPMENT.md)
2. Place plugin in appropriate category:
   - `plugins/recon/` - Reconnaissance
   - `plugins/vuln/` - Vulnerability detection
   - `plugins/exploit/` - Exploitation testing
3. Include docstrings and comments
4. Test thoroughly
5. Add example usage

#### Core Framework

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make changes following code style
4. Add tests if applicable
5. Update documentation
6. Submit pull request

## Code Style

### Python Style Guide

Follow PEP 8 with these additions:

```python
# Imports
import standard_library
import third_party
from local_module import something

# Class naming
class MyPlugin(BasePlugin):
    """Clear docstring"""
    pass

# Method naming
def my_method(self, param: str) -> bool:
    """Clear docstring with types"""
    pass

# Comments
# Explain WHY, not WHAT
# Code should be self-documenting

# Type hints
def scan_target(self, target: Target) -> PluginResult:
    pass
```

### Documentation

- All plugins must have docstrings
- Update README for new features
- Add examples for complex features
- Include remediation guidance in findings

## Testing

### Manual Testing

Before submitting:

1. Test plugin independently
2. Test with different scan modes
3. Test with various targets
4. Verify error handling
5. Check logging output

### Test Targets

Use only authorized test targets:
- Your own systems
- Intentionally vulnerable apps (DVWA, WebGoat, etc.)
- Test lab environments
- Never test production without authorization

## Pull Request Process

1. Update documentation
2. Add yourself to contributors (if desired)
3. Ensure code follows style guide
4. Include test results
5. Describe changes clearly
6. Reference related issues

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Plugin
- [ ] Documentation
- [ ] Performance improvement

## Testing
How was this tested?

## Checklist
- [ ] Code follows style guide
- [ ] Documentation updated
- [ ] Tested thoroughly
- [ ] No sensitive data included
```

## Plugin Submission Guidelines

### Required Elements

1. **Clear Purpose**: What does it detect/test?
2. **Documentation**: How to use it?
3. **Error Handling**: Graceful failure
4. **Rate Limiting**: Respect scan modes
5. **Evidence**: Provide proof of findings
6. **Remediation**: How to fix issues

### Quality Checklist

- [ ] Follows BasePlugin structure
- [ ] Has proper category
- [ ] Includes description
- [ ] Validates targets
- [ ] Handles errors gracefully
- [ ] Respects timeouts
- [ ] Uses async/await correctly
- [ ] Provides clear evidence
- [ ] Includes remediation steps
- [ ] Tests on safe targets
- [ ] No hardcoded credentials
- [ ] No destructive actions

## Security Considerations

### Do NOT

- ❌ Include exploits for 0-days
- ❌ Add destructive capabilities
- ❌ Enable DoS attacks
- ❌ Store credentials
- ❌ Exfiltrate data
- ❌ Include backdoors

### Do

- ✅ Safe detection only
- ✅ Rate limiting
- ✅ Clear logging
- ✅ Ethical testing
- ✅ Proper authorization checks
- ✅ Responsible disclosure

## Documentation

### What to Document

1. **Plugin Usage**
   - What it does
   - When to use it
   - Configuration options
   - Example output

2. **Code Changes**
   - Why the change was made
   - Impact on existing code
   - Breaking changes
   - Migration guide

3. **New Features**
   - Use cases
   - Configuration
   - Examples
   - Limitations

## Version Control

### Commit Messages

Format:
```
<type>: <subject>

<body>

<footer>
```

Types:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `style:` Formatting
- `refactor:` Code restructuring
- `test:` Tests
- `chore:` Maintenance

Examples:
```
feat: Add WordPress plugin scanner

Implements detection of vulnerable WordPress plugins
by checking version numbers against CVE database.

Closes #123
```

### Branching

- `main` - Stable releases
- `develop` - Development
- `feature/name` - New features
- `fix/name` - Bug fixes
- `plugin/name` - New plugins

## Release Process

1. Update version in `setup.py`
2. Update CHANGELOG
3. Tag release: `git tag v1.0.0`
4. Create GitHub release
5. Update documentation

## Community

### Getting Help

- Read documentation in `/docs`
- Check existing issues
- Review example plugins
- Ask in discussions

### Helping Others

- Answer questions
- Review pull requests
- Improve documentation
- Share use cases

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Credited in release notes
- Recognized in documentation

## Legal

By contributing, you agree that:
- Your contributions are original
- You have rights to contribute
- Contributions are licensed under MIT
- You follow responsible disclosure
- You use the framework ethically

## Questions?

- Create an issue for questions
- Tag with `question` label
- Be specific and detailed
- Include context

---

Thank you for contributing to security! 🔒
