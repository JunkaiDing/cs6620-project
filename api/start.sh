#!/bin/bash
# Run on EC2 after CloudFormation deploys
# Place this at /home/ec2-user/start.sh

set -e

# Pull latest code
cd /home/ec2-user
if [ ! -d "cs6620-project" ]; then
  git clone https://github.com/JunkaiDing/cs6620-project.git
fi
cd cs6620-project
git pull

# Load env
export $(cat /home/ec2-user/.env | xargs)

# Start API
cd api
uvicorn app:app --host 0.0.0.0 --port 8000
