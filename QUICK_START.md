# 🚀 Quick Start - Security & Compliance

## Prerequisites
- CDKTF CLI (`npm install -g cdktf-cli`)
- Go 1.20+ installed

## Deploy

```bash
# Install dependencies
go mod download

# Deploy
cdktf deploy

# Verify CloudTrail
aws cloudtrail get-trail-status --name compliance-trail
```

**Cost**: ~$60-80/month
**Time**: 15-20 minutes
