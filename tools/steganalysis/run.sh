#!/bin/sh
set -e
if [ $# -lt 2 ]; then
  echo "usage: tools/steganalysis/run.sh PHOTO_DIR WORK_DIR [BUCKET ...]" >&2
  exit 64
fi
PHOTOS=$1
WORK=$2
shift 2
BUCKETS=${*:-6 8 10 12 14}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
mkdir -p "$WORK/feat"
[ -f "$WORK/covers/tiles.json" ] || python3 "$HERE/make_tiles.py" --checker "$WORK/covers" "$PHOTOS"/*.jpg
(cd "$ROOT" && cargo run -q --release -p stegpony-core --example stego_batch -- "$WORK/covers" "$WORK/stego" $BUCKETS)
python3 "$HERE/sims.py" "$WORK/covers" "$WORK/sim" 10
[ -f "$WORK/feat/covers.npz" ] || python3 "$HERE/features.py" "$WORK/covers" "$WORK/feat/covers.npz"
SETS=""
for k in $BUCKETS; do
  [ -f "$WORK/feat/b$k.npz" ] || python3 "$HERE/features.py" "$WORK/stego/b$k" "$WORK/feat/b$k.npz"
  SETS="$SETS $WORK/feat/b$k.npz"
done
for t in juni_b10 nsf5_b10; do
  [ -f "$WORK/feat/$t.npz" ] || python3 "$HERE/features.py" "$WORK/sim/$t" "$WORK/feat/$t.npz"
  SETS="$SETS $WORK/feat/$t.npz"
done
python3 "$HERE/classify.py" "$WORK/feat/covers.npz" "$WORK/covers/tiles.json" 5 $SETS
