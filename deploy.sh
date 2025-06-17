#!/bin/bash

# 🚀 Skibidi Wallet Backend Production Deployment Script

echo "🚀 Starting Skibidi Wallet Backend Production Deployment..."

# Clean any existing artifacts
echo "🧹 Cleaning build artifacts..."
cargo clean

# Build for production with optimizations
echo "🔨 Building for production..."
cargo build --release

# Check if build was successful
if [ $? -eq 0 ]; then
    echo "✅ Production build completed successfully!"
    echo "📦 Optimized binary located at: ./target/release/skibidi-wallet-backend"
    echo ""
    echo "🌐 To run in production:"
    echo "   RUST_LOG=info ./target/release/skibidi-wallet-backend"
    echo ""
    echo "🚀 Ready for deployment!"
else
    echo "❌ Build failed! Please check errors above."
    exit 1
fi

# Show binary size for reference
echo "📊 Production binary size:"
ls -lh ./target/release/skibidi-wallet-backend

echo ""
echo "✨ Deployment preparation complete!"
echo "🔑 Remember to:"
echo "   - Set appropriate environment variables"
echo "   - Configure firewall rules"
echo "   - Set up reverse proxy (nginx/caddy)"
echo "   - Configure SSL certificates"
echo "   - Set up monitoring and logging" 