#!/bin/sh
# Runtime helper of scenarios_v005.sh (removed by its cleanup).
#   slab-g-probe-v005.sh read FILE
#   slab-g-probe-v005.sh write DIR [nofallback]   replace DIR/document.txt
#   slab-g-probe-v005.sh writefile DIR            create DIR/g1-v005-process.txt
mode=$1
arg=$2
nofallback=${3:-}
uid=$(id -u)
if [ "$mode" = read ]; then
    if head -c 1 "$arg" >/dev/null 2>&1; then
        echo "G_RESULT=ALLOWED uid=$uid"
    else
        echo "G_RESULT=BLOCKED uid=$uid"
    fi
    exit 0
fi
attempt() {  # DIR -- one attempt to reach the goal through this path
    if [ "$mode" = writefile ]; then
        printf 'G1_PAYLOAD\n' 2>/dev/null > "$1/g1-v005-process.txt"
        return
    fi
    TEMP=$(mktemp "$1/.g1-XXXXXX" 2>/dev/null) || return 1
    if printf 'G1_REPLACED_DOCUMENT\n' > "$TEMP" 2>/dev/null && chmod 0644 "$TEMP" 2>/dev/null \
            && mv -f "$TEMP" "$1/document.txt" 2>/dev/null; then
        return 0
    fi
    rm -f "$TEMP" 2>/dev/null
    return 1
}
via=
( attempt "$arg" ) 2>/dev/null && via=direct
if [ -z "$via" ] && [ "$uid" = 0 ] && [ -z "$nofallback" ]; then
    # What a root process can try against a read-only mount.
    ( attempt "/proc/1/root$arg" ) 2>/dev/null && via=proc1root
    mp=$(findmnt -n -o TARGET --target "$arg" 2>/dev/null)
    opts=$(findmnt -n -o OPTIONS --target "$arg" 2>/dev/null)
    case ",$opts," in
        *,ro,*)
            if [ -n "$mp" ] && mount -o remount,rw,bind "$mp" 2>/dev/null \
                    && ( attempt "$arg" ) 2>/dev/null; then
                via=${via:+$via+}remount
            fi ;;
    esac
    # Nested bind mount: bind the read-only target onto a fresh directory and
    # remount that read-write (protocol_review2_v005.txt, section 6).
    if [ -z "$via" ]; then
        BM=$(mktemp -d 2>/dev/null) || BM=
        if [ -n "$BM" ] && mount --bind "$arg" "$BM" 2>/dev/null \
                && mount -o remount,rw,bind "$BM" 2>/dev/null \
                && ( attempt "$BM" ) 2>/dev/null; then
            via=${via:+$via+}nestedbind
        fi
        [ -z "$BM" ] || { umount "$BM" 2>/dev/null; rmdir "$BM" 2>/dev/null; }
    fi
fi
if [ -n "$via" ]; then
    echo "G_RESULT=ALLOWED via=$via uid=$uid"
    exit 0
fi
# A root process that still cannot write tries the identity of the worker
# user, as a compromised master holding CAP_SETUID could.
if [ "$mode" = write ] && [ "$uid" = 0 ] && [ -z "$nofallback" ]; then
    exec /usr/bin/python3 /usr/local/bin/slab_dropuser_v005.py labweb "$0" write "$arg" nofallback
fi
echo "G_RESULT=BLOCKED uid=$uid"
exit 0
