#!/bin/bash
# Repo and paths
REPO_URL="https://github.com/olbat/ut1-blacklists.git"
REPO_DIR="/opt/categorization/ut1-blacklists"

# Clone or update repo
if [ ! -d "$REPO_DIR/.git" ]; then
    git clone --depth=1 "$REPO_URL" "$REPO_DIR"
else
    git -C "$REPO_DIR" pull --ff-only
fi

./update_categories.py
