#!/bin/bash
set -o errexit -o pipefail -o noclobber -o nounset

cd "$(dirname "$0")"

rm -f ./assets.json
rm -f ./assets-testnet.json
echo '{"id":1, "method": "assets", "params": {"embedded_icons":false,"all_assets":true}}' | websocat --buffer-size 1048576 wss://api.sideswap.io/json-rpc-ws | jq '.result.assets | [.[] | select(.always_show == true)]' > ./assets.json
echo '{"id":1, "method": "assets", "params": {"embedded_icons":false,"all_assets":true}}' | websocat --buffer-size 1048576 wss://api-testnet.sideswap.io/json-rpc-ws | jq '.result.assets | [.[] | select(.always_show == true)]' > ./assets-testnet.json

GIT_STATUS="$(git status --porcelain)"
if [[ -n "$GIT_STATUS" ]]; then
    echo "Make sure the default assets are up to date!"
    echo "Git status: $GIT_STATUS"
    exit 1
else
    echo "Assets are up to date"
fi

#git fetch --quiet
LOCAL="$(git rev-parse @)"
REMOTE="$(git rev-parse origin/main)"

if [[ "$LOCAL" = "$REMOTE" ]]; then
    echo "✅ Repo is clean and branch is up‑to‑date with upstream."
else
    echo "❌ Repo is not not up-to-date with upstream"
    exit 1
fi
