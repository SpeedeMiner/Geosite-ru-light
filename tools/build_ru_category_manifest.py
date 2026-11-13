from pathlib import Path
import os
import re

DATA = Path("domain-list-community/data")
output = Path(os.environ["CATEGORY_FILE"])

selected = set()
visited = set()
missing_v2fly = set()

excluded = {
    "private",
    "tld-ru",
    "category-geoblock-ru",
}

def normalize(name: str) -> str:
    return name.strip().lower()

def is_negative_category(name: str) -> bool:
    name = normalize(name)
    if not name:
        return False
    if any(marker in name for marker in ("blocked", "geoblock", "re-filter", "refilter")):
        return True
    return re.search(r"(^|[-_.])ban([-_.]|$)", name) is not None

def is_excluded(name: str) -> bool:
    name = normalize(name)
    if not name:
        return True
    if name in excluded:
        return True
    return is_negative_category(name)

def visit(name: str):
    name = normalize(name)

    if not name or name in visited or is_excluded(name):
        return

    visited.add(name)
    path = DATA / name

    if not path.is_file():
        missing_v2fly.add(name)
        return

    selected.add(f"runetfreedom|{name}")

    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        raise RuntimeError(f"failed to read v2fly category {name}: {exc}") from exc

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.lower().startswith("include:"):
            payload = line.split(":", 1)[1].strip()
            parts = payload.split()
            # Selective includes with attributes are filters, not whole-list
            # includes. The resolved category-ru in the upstream DAT already
            # contains the effective rules, so do not promote the child here.
            if len(parts) != 1:
                continue
            target = parts[0]
            if re.fullmatch(r"[A-Za-z0-9_.!+-]+", target):
                visit(target)

visit("category-ru")
# Explicit root: category-ru does not include this upstream category.
# Its include dependencies are merged through the same RU manifest path.
visit("category-ip-geo-detect")

for path in sorted(DATA.iterdir()):
    if (
        path.is_file()
        and not path.name.startswith(".")
        and path.name.lower().endswith("-ru")
    ):
        visit(path.name)

extra_categories = {
    "2gis", "aviasales", "autoru", "avito", "dzen", "kinopoisk",
    "mailru", "mailru-group", "max", "mosmetro", "mts", "ok", "okko",
    "ozon", "rutube", "sokolov", "wildberries", "wb", "wink", "x5",
    "yandex",
    "beget", "carrotquest", "cdek", "comssone", "drweb", "envybox", "habr",
    "gismeteo", "group-ib", "headhunter", "ideco-ru", "kaspersky", "kontur",
    "mindbox", "myoffice-ru", "netcraze", "nic-ru", "positive-technologies",
    "regru", "selectel", "servicepipe", "skyeng", "smena", "tilda",
    "timeweb", "ucoz", "whoosh",
    "megafon", "mts-ru", "rostelecom", "t2-ru",
    "vk", "sberbank", "tinkoff", "alfabank", "vtb", "gazprombank",
}

optional_missing = []
for name in sorted(extra_categories):
    normalized = normalize(name)
    path = DATA / normalized
    if path.is_file():
        visit(normalized)
    else:
        optional_missing.append(normalized)

if missing_v2fly:
    print()
    print("ERROR: required v2fly include categories are missing:")
    for name in sorted(missing_v2fly):
        print(f"  - {name}")
    raise SystemExit(1)

print()
print(f"Optional standalone categories present: {len(extra_categories) - len(optional_missing)}/{len(extra_categories)}")
if optional_missing:
    print("Optional standalone categories absent in current v2fly data (not fatal):")
    for name in optional_missing:
        print(f"  - {name}")

# Import positive RU-tree suffix rules directly: a v2fly category may
# be absent as a top-level category in runetfreedom's compiled DAT.
# No global DNS/TLD, generic cloud provider or negative category promotion.
corporate_domains = set()
corporate_visited = set()
corporate_missing = set()

def safe_corporate_suffix_tokens(parts):
    if not parts:
        return False
    token = parts[0].lower()
    if token.startswith(("full:", "regexp:", "keyword:", "include:")):
        return False
    # v2fly attributes are selectors. Do not treat arbitrary
    # @cn/@!ru/@ads/@telemetry as RU-owned domain evidence.
    return all(attr.lower() == "@ru" for attr in parts[1:])

# Regression tests run at each PR and main/scheduled build.
assert safe_corporate_suffix_tokens(["service.example.com"])
assert safe_corporate_suffix_tokens(["service.example.com", "@ru"])
assert safe_corporate_suffix_tokens(["service.example.com", "@RU", "@ru"])
for sample in (
    ["service.example.com", "@ads"],
    ["service.example.com", "@ru", "@ads"],
    ["service.example.com", "@!ru"],
    ["service.example.com", "@cn"],
    ["service.example.com", "@telemetry"],
    ["full:service.example.com", "@ru"],
    ["regexp:.*", "@ru"],
    ["keyword:service", "@ru"],
):
    assert not safe_corporate_suffix_tokens(sample), sample

def import_corporate_category(name: str):
    name = normalize(name)
    if name in corporate_visited or is_excluded(name):
        return
    corporate_visited.add(name)
    path = DATA / name
    if not path.is_file():
        corporate_missing.add(name)
        return
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        entry = raw.split("#", 1)[0].strip()
        if not entry:
            continue
        parts = entry.split()
        token = parts[0]
        if token.lower().startswith("include:"):
            if len(parts) == 1:
                child = token.split(":", 1)[1]
                if re.fullmatch(r"[A-Za-z0-9_.!+-]+", child):
                    import_corporate_category(child)
            continue
        if not safe_corporate_suffix_tokens(parts):
            continue
        if token.startswith("domain:"):
            token = token[7:]
        try:
            token = token.strip(".").lower().encode("idna").decode("ascii")
        except UnicodeError:
            continue
        if re.fullmatch(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+", token):
            corporate_domains.add(token)

# All positive include dependencies of category-ru and extra_categories.
# This catches bank/retail/entertainment source-only rules, not just
# manually enumerated corporate categories.
for category in sorted(visited):
    if (DATA / category).is_file():
        import_corporate_category(category)
if corporate_missing:
    raise SystemExit("missing v2fly dependencies: " + ", ".join(sorted(corporate_missing)))
if not corporate_domains:
    raise SystemExit("empty direct v2fly corporate domain extraction")
direct_output = Path("v2fly-corporate-extra-domains.txt")
direct_output.write_text(
    "# Generated positive v2fly suffix rules\n"
    + "".join(f"domain:{value}\n" for value in sorted(corporate_domains)),
    encoding="utf-8",
)
print(f"Direct v2fly positive RU-tree suffix rules: {len(corporate_domains)}")

def add_external_categories(source: str, categories) -> int:
    excluded_count = 0
    for raw_name in categories:
        name = normalize(raw_name)
        if not name:
            continue
        if is_negative_category(name):
            print(f"Excluded negative external category: {source}|{name}")
            excluded_count += 1
            continue
        selected.add(f"{source}|{name}")
    return excluded_count

excluded_external_count = 0

excluded_external_count += add_external_categories("hydra", {
    "whitelist",
    "private",
    "category-ru",
})

excluded_external_count += add_external_categories("mvrvntn", {
    "category-ru",
})

excluded_external_count += add_external_categories("yularzhi", {
    "category-ru",
    "private",
})

excluded_external_count += add_external_categories("vpnyasha", {
    "our-whitelist",
    "our-category-ru",
    "our-games",
})

excluded_external_count += add_external_categories("kirill", {
    "category-ru",
})

excluded_external_count += add_external_categories("digne", {
    "category-ru",
})

excluded_external_count += add_external_categories("grimbird", {
    "category-ru-whitelist",
    "ozon",
    "ru-analytics",
    "ru-cdn",
    "ru-finance",
    "ru-medical",
    "ru-retail-extra",
    "ru-transport",
    "ru-tv",
    "ru-whitelist-extended",
    "swift",
})

leaked_negative = sorted(
    item for item in selected
    if is_negative_category(item.split("|", 1)[1])
)
if leaked_negative:
    print("ERROR: negative categories leaked into manifest:")
    for item in leaked_negative:
        print(f"  - {item}")
    raise SystemExit(1)

with output.open("w", encoding="utf-8") as f:
    for item in sorted(selected):
        f.write(item + "\n")

hydra_append_categories = [
    "apple",
    "epicgames",
    "escapefromtarkov",
    "faceit",
    "github",
    "google-deepmind",
    "google-play",
    "microsoft",
    "pinterest",
    "riot",
    "steam",
    "telegram",
    "twitch",
    "twitch-ads",
    "youtube",
    "win-spy",
]

append_output = Path(os.environ["HYDRA_APPEND_FILE"])
append_output.write_text(
    "\n".join(f"hydra|{name}" for name in hydra_append_categories) + "\n",
    encoding="utf-8",
)

print()
print("========================================")
print("RU CATEGORY MANIFEST")
print("========================================")
print(f"Manifest entries: {len(selected)}")
print(f"Manifest written to: {output}")
print(f"Excluded v2fly categories: {len(excluded)} fixed names + negative-name patterns")
print(f"Excluded negative external categories: {excluded_external_count}")
