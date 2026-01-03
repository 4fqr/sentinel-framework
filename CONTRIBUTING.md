# 🤝 Contributing to Sentinel Framework

Thank you for your interest in contributing to Sentinel Framework! This document provides guidelines and instructions for contributing.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)

## 📜 Code of Conduct

- **Be respectful** and inclusive
- **Be collaborative** and help others
- **Focus on what is best** for the community
- **Show empathy** towards others

## 🎯 How Can I Contribute?

### 1. Report Bugs

Found a bug? Help us by:
- Checking if the issue already exists
- Providing detailed reproduction steps
- Including system information
- Attaching relevant logs

### 2. Suggest Features

Have an idea? We'd love to hear it:
- Check existing feature requests
- Explain the problem it solves
- Describe your proposed solution
- Provide examples if possible

### 3. Improve Documentation

Documentation is crucial:
- Fix typos and grammar
- Add missing examples
- Improve clarity
- Translate to other languages

### 4. Write Code

Contribute code by:
- Fixing bugs
- Implementing new features
- Adding new detectors
- Improving performance
- Writing tests

## 🛠️ Development Setup

### Fork and Clone

```bash
# Fork the repository on GitHub, then:
git clone https://github.com/YOUR_USERNAME/sentinel-framework.git
cd sentinel-framework

# Add upstream remote
git remote add upstream https://github.com/4fqr/sentinel-framework.git
```

### Create Development Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```

### Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=sentinel --cov-report=html

# Run specific test file
pytest tests/test_core.py

# Run tests with verbose output
pytest -v
```

## 📝 Coding Standards

### Python Style

We follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) with these tools:

```bash
# Format code with Black
black sentinel/

# Check style with Flake8
flake8 sentinel/

# Type checking with mypy
mypy sentinel/
```

### Code Structure

```python
"""
Module docstring explaining purpose
"""

import standard_library
import third_party
import local_modules

from typing import List, Dict, Optional


class ClassName:
    """Class docstring explaining purpose"""
    
    def __init__(self, param: str) -> None:
        """
        Initialize the class
        
        Args:
            param: Description of parameter
        """
        self.param = param
    
    def method_name(self, arg: int) -> bool:
        """
        Method docstring
        
        Args:
            arg: Description of argument
        
        Returns:
            Description of return value
        
        Raises:
            ValueError: When invalid input
        """
        # Implementation
        return True
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <subject>

<body>

<footer>
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(detectors): add cryptominer detection
fix(sandbox): handle timeout errors gracefully
docs(readme): update installation instructions
```

## 🔄 Submitting Changes

### 1. Create a Branch

```bash
# Update your fork
git fetch upstream
git checkout main
git merge upstream/main

# Create feature branch
git checkout -b feature/my-feature
```

### 2. Make Changes

- Write your code
- Add tests
- Update documentation
- Run tests locally

### 3. Commit Changes

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat(detectors): add new detector"

# Push to your fork
git push origin feature/my-feature
```

### 4. Open Pull Request

- Go to GitHub and open a Pull Request
- Fill out the PR template
- Link any related issues
- Wait for review

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Commit messages follow convention
- [ ] PR description is clear
- [ ] Related issues linked

## 🐛 Reporting Bugs

### Before Submitting

1. **Search existing issues** - It might already be reported
2. **Try latest version** - Bug might be fixed
3. **Isolate the problem** - Minimal reproduction case

### Bug Report Template

```markdown
**Description**
Clear description of the bug

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen

**Actual Behavior**
What actually happened

**Environment**
- OS: [e.g., Windows 10]
- Python Version: [e.g., 3.9.7]
- Sentinel Version: [e.g., 1.0.0]
- Docker Version: [e.g., 20.10.8]

**Logs**
```
Paste relevant logs here
```

**Screenshots**
If applicable, add screenshots
```

## 💡 Suggesting Features

### Feature Request Template

```markdown
**Problem Description**
Clear description of the problem

**Proposed Solution**
How would you solve it?

**Alternatives Considered**
What other approaches did you consider?

**Use Case**
How would you use this feature?

**Examples**
Code examples if applicable
```

## 🔍 Code Review Process

### What We Look For

- **Correctness** - Does it work?
- **Tests** - Are there tests?
- **Documentation** - Is it documented?
- **Style** - Follows guidelines?
- **Performance** - Is it efficient?
- **Security** - Is it safe?

### Review Timeline

- Initial response: Within 48 hours
- Full review: Within 1 week
- Merge: After approval + tests pass

## 🏆 Recognition

Contributors are recognized in:
- **CHANGELOG.md** - Your contributions listed
- **Contributors page** - Your profile featured
- **Release notes** - Major contributions highlighted

## 📞 Getting Help

Need help contributing?

- 💬 **GitHub Discussions** - Ask questions
- 📧 **Email** - Contact maintainers
- 📖 **Documentation** - Read the docs
- 👥 **Community** - Join our community

## 📚 Additional Resources

- [Python Style Guide](https://www.python.org/dev/peps/pep-0008/)
- [Git Best Practices](https://git-scm.com/book/en/v2)
- [Testing Guide](https://docs.pytest.org/)
- [Docker Documentation](https://docs.docker.com/)

---

**Thank you for contributing to Sentinel Framework! 🛡️**

Together, we're making malware analysis more accessible and powerful.
