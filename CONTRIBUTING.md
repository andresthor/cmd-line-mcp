# Contributing to cmd-line-mcp

Thank you for your interest in contributing to cmd-line-mcp! This document provides guidelines and instructions for contributing to this project.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/cmd-line-mcp.git
   cd cmd-line-mcp
   ```
3. Set up the development environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -e ".[dev]"  # Install with development dependencies
   ```

## Development Workflow

1. Create a branch for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, following the code style and standards

3. Run tests to ensure your changes don't break existing functionality:
   ```bash
   pytest
   ```

4. Format your code with Black:
   ```bash
   black src tests
   ```

5. Lint your code with flake8:
   ```bash
   flake8 src tests
   ```

6. Commit your changes with a descriptive commit message:
   ```bash
   git commit -m "Add feature: your feature description"
   ```

7. Push your changes to your fork:
   ```bash
   git push -u origin feature/your-feature-name
   ```

8. Create a pull request from your fork to the main repository

## Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use type hints for function parameters and return values
- Write docstrings for all modules, classes, and functions
- Keep line length to 88 characters (Black's default)

## Testing

- Write tests for all new features and bug fixes
- Maintain or improve test coverage
- Tests should be fast, independent, and not rely on external resources

## Adding New Commands

If you want to add support for new commands:

1. Identify the category of the command (read, write, system)
2. Update the appropriate list in `config.py`
3. Add tests for the new command
4. Document the new command in the README.md

## Security Considerations

The cmd-line-mcp project is used to execute shell commands, so security is a critical concern:

1. Always validate input thoroughly
2. Be conservative with command categorization 
3. Add dangerous patterns for potentially harmful command variations
4. Test all changes for security implications

## Pull Request Process

1. Update the README.md with details of changes to the interface, if applicable
2. Update the documentation with new commands or features
3. Increase the version numbers in any examples files and the README.md to the new version
4. Add yourself to CONTRIBUTORS.md if you're not already listed

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License.