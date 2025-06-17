# 🚀 Railway Deployment Guide

## Quick Deploy Steps

1. **Go to [Railway.app](https://railway.app)** and sign up with GitHub

2. **Click "New Project"** → **"Deploy from GitHub repo"**

3. **Select your repository** and choose this directory: `skibidi-backend/skibidi-wallet-backend`

4. **Railway auto-detects Rust** and will start building automatically!

5. **Get your URL** - Railway will give you something like: `https://your-app-name.up.railway.app`

6. **Update your React Native app**:
   - Open `skibidi-wallet/src/config.ts`
   - Replace `https://your-railway-app.up.railway.app` with your actual Railway URL

## That's it! 🎉

Your backend will be live and ready for your mobile app to use.

## Testing Your Deployment

Once deployed, you can test your backend by visiting:
- `https://your-railway-app.up.railway.app/` - Health check
- `https://your-railway-app.up.railway.app/backend-status` - Backend status

## Troubleshooting

If build fails:
1. Check Railway logs in the dashboard
2. Make sure you selected the correct directory (`skibidi-backend/skibidi-wallet-backend`)
3. Ensure your GitHub repo is public or Railway has access 