#!/bin/bash
set -e

echo "Setting up Arcturian development environment..."

# Install Node dependencies
if [ -f "package.json" ]; then
  echo "📦 Installing Node dependencies..."
  npm install
fi

# Install Python dependencies
if [ -f "requirements.txt" ]; then
  echo "🐍 Installing Python dependencies..."
  pip install -r requirements.txt
fi

# Install security scanning tools
echo "🔒 Installing security tools..."
npm install --save-dev vitest @testing-library/react eslint-plugin-security
pip install bandit safety pylint

# Configure Git hooks
echo "🔗 Setting up Git hooks..."
mkdir -p .git/hooks
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
echo "Running security checks before commit..."
npm run lint:security || true
python -m bandit -r src/ || true
EOF
chmod +x .git/hooks/pre-commit

echo "✅ Development environment ready!"
echo ""
echo "Available commands:"
echo "  npm run test              - Run unit tests"
echo "  npm run test:watch        - Run tests in watch mode"
echo "  npm run lint              - Run linter"
echo "  npm run lint:security     - Run security linter"
echo "  python -m bandit -r src/  - Run Python security scan"
echo ""
