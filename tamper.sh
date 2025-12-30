#!/bin/bash

ESC=$(printf '\033')

# ===== COLORS =====
RED="${ESC}[31m"
GREEN="${ESC}[32m"
YELLOW="${ESC}[33m"
BLUE="${ESC}[34m"
MAGENTA="${ESC}[35m"
CYAN="${ESC}[36m"
RESET="${ESC}[0m"
BOLD="${ESC}[1m"

fix_sqlmap_ansi() {
    sed -u "s/e\[/$(printf '\033')\[/g"
}


colorize_sqlmap() {
    sed -u \
        -e "s|\[INFO\]|${BLUE}[INFO]${RESET}|g" \
        -e "s|\[WARNING\]|${YELLOW}[WARNING]${RESET}|g" \
        -e "s|\[ERROR\]|${RED}[ERROR]${RESET}|g" \
        -e "s|vulnerable|${GREEN}vulnerable${RESET}|Ig" \
        -e "s|payload:|${CYAN}payload:${RESET}|Ig" \
        -e "s|testing|${MAGENTA}testing${RESET}|Ig" \
        -e "s|parameter|${CYAN}parameter${RESET}|Ig" \
        -e "s|injected|${MAGENTA}injected${RESET}|Ig"
}


# Default values
TARGET=""
OPTIONS=""

# Parse arguments like sqlmap style
while [[ $# -gt 0 ]]; do
    case "$1" in
        -u)
            TARGET="$2"
            shift 2
            ;;
        --options)
            OPTIONS="$2"
            shift 2
            ;;
        *)
            echo "Unknown argument: $1"
            exit 1
            ;;
    esac
done

# Check required inputs
if [ -z "$OPTIONS" ]; then
    echo "Usage: $0 -u <url> --options \"<sqlmap options>\""
    echo "Example:"
    echo "  ./tamper_tester.sh -u \"http://localhost/test.php?id=1\" --options \"-p id --dbs\""
    exit 1
fi

########################################
# CATEGORY 1 — MOST USED / HIGH SUCCESS
########################################
CATEGORY1=(
"randomcase"
"space2comment"
"space2dash"
"space2plus"
"space2mysqlblank"
"space2mysqldash"
"between"
"charencode"
"chardoubleencode"
"unionalltounion"
"versionedkeywords"
"versionedmorekeywords"
"xforwardedfor"
"randomcomments"
)

########################################
# CATEGORY 2 — MEDIUM USAGE / WAF BYPASS
########################################
CATEGORY2=(
"bluecoat"
"percentage"
"percentage2obfuscate"
"apostrophemask"
"apostrophenullencode"
"charunicodeencode"
"charunicodeescape"
"htmlencode"
"hex2char"
"ifnull2ifisnull"
"commalessorder"
"commalesslimit"
"commalessmid"
"comma2concat"
"concat2concatws"
)

########################################
# CATEGORY 3 — RARE CASES
########################################
CATEGORY3=(
"escapequotes"
"uppercase"
"lowercase"
"multiplespaces"
"symboliclogical"
"unmagicquotes"
"halfversionedmorekeywords"
)

########################################
# CATEGORY 4 — OBSCURE / LAST RESORT
########################################
CATEGORY4=(
"base64encode"
"appendnullbyte"
"floor"
"equaltolike"
"sp_password"
)

########################################
# CATEGORY 5 — ALL TAMPERS
########################################
CATEGORY5=(
"${CATEGORY1[@]}"
"${CATEGORY2[@]}"
"${CATEGORY3[@]}"
"${CATEGORY4[@]}"
)

echo ""
echo "Choose Tamper Category:"
echo "1) Most-used / High Success"
echo "2) Medium Usage / WAF Bypass"
echo "3) Rare Cases"
echo "4) Last Resort / Obscure"
echo "5) ALL Tampers"
echo ""
read -p "Enter choice (1-5): " CHOICE

case "$CHOICE" in
    1) TAMPERS=("${CATEGORY1[@]}");;
    2) TAMPERS=("${CATEGORY2[@]}");;
    3) TAMPERS=("${CATEGORY3[@]}");;
    4) TAMPERS=("${CATEGORY4[@]}");;
    5) TAMPERS=("${CATEGORY5[@]}");;
    *)
        echo "Invalid choice."
        exit 1
        ;;
esac

echo ""
echo "Running tamper category $CHOICE on:"
echo "URL: $TARGET"
echo "Options: $OPTIONS"
echo ""

for TAMPER in "${TAMPERS[@]}"; do
    echo -e "${CYAN}=====================================${RESET}"
    echo -e "${YELLOW}Trying tamper:${RESET} ${BOLD}$TAMPER${RESET}"
    echo -e "${CYAN}=====================================${RESET}"

    echo -e "${MAGENTA}[Running SQLMap with live logs...]${RESET}"
    echo ""

    # SAFE live output version (only for authorized testing)
   # --- begin drop-in: run sqlmap, show colored live logs, capture raw output ---
# split OPTIONS into array safely (so flags with spaces are kept)
read -r -a OPT_ARRAY <<< "$OPTIONS"

TMP_OUTPUT="$(mktemp)"

# Run sqlmap, stream colorized output to terminal and save raw output to $TMP_OUTPUT
# - process substitution sends a copy of stdout to the colorizer, while tee writes raw to TMP_OUTPUT
SQLMAP_CMD=("")

# If target URL exists, add -u
if [[ -n "$TARGET" ]]; then
    SQLMAP_CMD+=("-u" "$TARGET")
fi

# Add other options
if [[ -n "$OPTIONS" ]]; then
    SQLMAP_CMD+=($OPTIONS)
fi

sqlmap "${SQLMAP_CMD[@]}" --tamper="$TAMPER" 2>&1 \
    | tee >( fix_sqlmap_ansi | colorize_sqlmap >&2 ) > "$TMP_OUTPUT"

# Now $TMP_OUTPUT contains raw sqlmap output (without colorizer transformations).
# Remove ANSI escape sequences from raw output for reliable grepping:
RAW_CLEAN=$(sed -r 's/\x1B\[[0-9;]*[mK]//g' "$TMP_OUTPUT")

# Detection: look for several common sqlmap success indicators
if echo "$RAW_CLEAN" | grep -Eqi \
    "parameter .* is vulnerable|injection found|the back-end DBMS is|target is vulnerable|vulnerable parameter|payload:"; then

    echo -e ""
    echo -e "${GREEN}🔥 INJECTION FOUND using tamper:${RESET} ${BOLD}$TAMPER${RESET}"
    rm -f "$TMP_OUTPUT"
    exit 0
fi

# cleanup and continue
rm -f "$TMP_OUTPUT"
# --- end drop-in ---

done

echo -e "${RED}❗ No tamper worked in selected category.${RESET}"
