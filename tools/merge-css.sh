#!/usr/bin/env bash
# Usage: ./merge-css.sh light.css dark.css > merged.css

light="$1"
dark="$2"

if [[ -z "$light" || -z "$dark" ]]; then
  echo "Usage: $0 light.css dark.css"
  exit 1
fi

paste "$light" "$dark" | \
awk -F'\t' '
function replace_colors(l, d,   out, pos, m) {
  out = ""
  pos = 1
  while (match(l, /#[0-9A-Fa-f]{6}/)) {
    # add text before match
    out = out substr(l, 1, RSTART-1)

    lcol = substr(l, RSTART, RLENGTH)
    dcol = substr(d, RSTART, RLENGTH)

    if (lcol != dcol) {
      out = out "light-dark(" lcol "," dcol ")"
    } else {
      out = out lcol
    }

    l = substr(l, RSTART + RLENGTH)
    d = substr(d, RSTART + RLENGTH)
  }
  out = out l
  return out
}

{
  if ($1 == $2) {
    print $1
  } else {
    print replace_colors($1, $2)
  }
}'

