#!/usr/bin/env bash
set -euo pipefail

artwork_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
res_dir="$artwork_dir/../app/src/main/res"

for density_size in mdpi:48 hdpi:72 xhdpi:96 xxhdpi:144 xxxhdpi:192; do
    density="${density_size%%:*}"
    size="${density_size##*:}"
    output_dir="$res_dir/mipmap-$density"
    mkdir -p "$output_dir"
    rsvg-convert --width "$size" --height "$size" "$artwork_dir/ic_launcher.svg" --output "$output_dir/ic_launcher.png"
    rsvg-convert --width "$size" --height "$size" "$artwork_dir/ic_launcher_round.svg" --output "$output_dir/ic_launcher_round.png"
done

rsvg-convert --width 512 --height 512 "$artwork_dir/ic_launcher_store.svg" --output "$artwork_dir/play-store-icon.png"
