#!/usr/bin/env python3
"""Browse CodeQL findings in SARIF files, or export them as a report.

With a terminal on stdin and stdout the findings open in fzf, most severe first,
with the selected finding's source and data-flow path in a preview. Otherwise,
or with --list, the same details print as a text report. --html and --markdown
write a full report instead: source excerpts, every data-flow step, rule help.
"""

import argparse
import datetime
import glob
import html
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import unquote, urlparse

# GitHub's buckets for a rule's security-severity score.
BUCKETS = (("critical", 9.0), ("high", 7.0), ("medium", 4.0), ("low", 0.0))
# Results of non-security rules carry no score and sort below every scored one.
LEVELS = {"error": -1.0, "warning": -2.0, "note": -3.0, "none": -4.0}
ORDER = [name for name, _ in BUCKETS] + list(LEVELS)
STYLE = {
    "critical": "1;35", "high": "1;31", "medium": "1;33", "low": "1;34",
    "error": "31", "warning": "33", "note": "36", "none": "2",
    "dim": "2", "bold": "1", "loc": "36", "span": "1;4;31", "mark": "1;31",
}
# "[user-provided value](1)": a link to the result's relatedLocations entry 1.
LINK = re.compile(r"\[([^\]]*)\]\((\d+)\)")
LEGEND = "enter: details   ctrl-e: open in editor   ctrl-/: toggle preview   esc: quit"


class Paint:
    def __init__(self, enabled):
        self.enabled = enabled

    def __call__(self, text, style):
        if not self.enabled or not text:
            return text
        return f"\033[{STYLE[style]}m{text}\033[0m"


PLAIN = Paint(False)


# --- SARIF -> findings ---------------------------------------------------------

def location(loc):
    """Flatten a SARIF location into the fields displayed."""
    phys = loc.get("physicalLocation") or {}
    region = phys.get("region") or {}
    context = phys.get("contextRegion") or {}
    line = region.get("startLine") or 0
    return {
        "uri": (phys.get("artifactLocation") or {}).get("uri") or "",
        "line": line,
        "col": region.get("startColumn") or 1,
        "end_line": region.get("endLine") or line,
        "end_col": region.get("endColumn"),
        "snippet": (context.get("snippet") or {}).get("text"),
        "snippet_line": context.get("startLine"),
        "message": (loc.get("message") or {}).get("text") or "",
    }


def same_place(a, b):
    return (a["uri"], a["line"], a["col"], a["end_col"]) == (b["uri"], b["line"], b["col"], b["end_col"])


def rules_by_id(run):
    tool = run.get("tool") or {}
    rules = {}
    for component in [tool.get("driver") or {}] + list(tool.get("extensions") or []):
        for rule in component.get("rules") or []:
            if rule.get("id"):
                rules.setdefault(rule["id"], rule)
    return rules


def finding(result, run, rules, fid, sarif):
    rid = result.get("ruleId") or (result.get("rule") or {}).get("id")
    rule = rules.get(rid) if rid else None
    if rule is None:
        index = result.get("ruleIndex", (result.get("rule") or {}).get("index"))
        driver = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        if isinstance(index, int) and 0 <= index < len(driver):
            rule = driver[index]
            rid = rid or rule.get("id")
    rule, rid = rule or {}, rid or "?"
    props = rule.get("properties") or {}

    level = result.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
    if not level:
        level = {"recommendation": "note"}.get(props.get("problem.severity"), props.get("problem.severity"))
    if level not in LEVELS:
        level = "warning"
    try:
        score = float(props["security-severity"])
    except (KeyError, TypeError, ValueError):
        score = None
    if score is None:
        severity, rank = level, LEVELS[level]
    else:
        severity, rank = next((name for name, floor in BUCKETS if score >= floor), "low"), score

    cwes = []
    for tag in props.get("tags") or []:
        match = re.fullmatch(r"external/cwe/cwe-0*(\d+)", tag)
        if match:
            cwes.append("CWE-" + match.group(1))

    locations = [location(loc) for loc in result.get("locations") or []]
    related = {str(rel["id"]): location(rel)
               for rel in result.get("relatedLocations") or [] if isinstance(rel.get("id"), int)}
    paths = []
    for flow in result.get("codeFlows") or []:
        for thread in flow.get("threadFlows") or []:
            steps = []
            for step in thread.get("locations") or []:
                loc = location(step.get("location") or {})
                # CodeQL often reports the same node twice in a row; keep one.
                if steps and same_place(steps[-1], loc):
                    steps[-1] = loc
                else:
                    steps.append(loc)
            if steps:
                paths.append(steps)

    return {
        "id": fid,
        "sarif": sarif,
        "rule": rid,
        "title": (rule.get("shortDescription") or {}).get("text") or props.get("name") or rid,
        "description": " ".join((props.get("description")
                                 or (rule.get("fullDescription") or {}).get("text") or "").split()),
        "precision": props.get("precision") or "",
        "severity": severity,
        "score": score,
        "rank": rank,
        "cwes": cwes,
        "message": (result.get("message") or {}).get("text") or "",
        "where": locations[0] if locations else location({}),
        "related": related,
        "paths": paths,
    }


def load(sarifs):
    """Findings from every file, most severe first, the same finding once; plus
    what reports need besides: each rule's help and the tools that ran."""
    found, seen, dupes = [], set(), 0
    info = {"help": {}, "tools": []}
    for fi, sarif in enumerate(sarifs):
        try:
            with open(sarif, encoding="utf-8") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            raise SystemExit(f"codeql-findings: {sarif}: {exc}")
        if not isinstance(doc, dict):
            raise SystemExit(f"codeql-findings: {sarif}: not a SARIF log")
        for ri, run in enumerate(doc.get("runs") or []):
            rules = rules_by_id(run)
            tool = run.get("tool") or {}
            driver = tool.get("driver") or {}
            for component in [driver] + list(tool.get("extensions") or []):
                name = component.get("name") or ""
                if name and (component is driver or name.endswith("-queries")):
                    entry = f"{name} {component.get('semanticVersion') or component.get('version') or ''}".strip()
                    if entry not in info["tools"]:
                        info["tools"].append(entry)
            for rid, rule in rules.items():
                rule_help = rule.get("help") or {}
                if rid not in info["help"] and (rule_help.get("markdown") or rule_help.get("text")):
                    info["help"][rid] = (rule_help.get("markdown") or rule_help.get("text"), bool(rule_help.get("markdown")))
            for xi, result in enumerate(run.get("results") or []):
                f = finding(result, run, rules, f"{fi}.{ri}.{xi}", sarif)
                w = f["where"]
                key = (f["rule"], w["uri"], w["line"], w["col"], f["message"])
                if key in seen:
                    dupes += 1
                    continue
                seen.add(key)
                found.append(f)
    found.sort(key=lambda f: (-f["rank"], f["where"]["uri"], f["where"]["line"]))
    return found, dupes, info


def wanted(f, args):
    if args.severity != "all":
        if f["score"] is None or f["score"] < dict(BUCKETS)[args.severity]:
            return False
    if args.rule and not any(text.lower() in f["rule"].lower() for text in args.rule):
        return False
    return True


# --- source code -------------------------------------------------------------

class Sources:
    """Source lines from the checkout, else from the snippets in the SARIF."""

    def __init__(self, root):
        self.root = root
        self.files = {}

    def path(self, uri):
        if not uri:
            return None
        if uri.startswith("file:"):
            return unquote(urlparse(uri).path)
        path = unquote(uri)
        return path if os.path.isabs(path) else os.path.join(self.root, path)

    def line(self, loc, n):
        uri = loc["uri"]
        if uri not in self.files:
            try:
                with open(self.path(uri), encoding="utf-8", errors="replace") as fh:
                    self.files[uri] = fh.read().splitlines()
            except (OSError, TypeError):
                self.files[uri] = None
        lines = self.files[uri]
        if lines is not None:
            return lines[n - 1] if 1 <= n <= len(lines) else None
        if loc["snippet"] and loc["snippet_line"]:
            snippet = loc["snippet"].splitlines()
            i = n - loc["snippet_line"]
            return snippet[i] if 0 <= i < len(snippet) else None
        return None

    def around(self, loc, before, after):
        """(line number, text) for the lines around a location that exist."""
        if not loc["line"]:
            return []
        rows = []
        for n in range(max(1, loc["line"] - before), loc["line"] + after + 1):
            text = self.line(loc, n)
            if text is not None:
                rows.append((n, text))
        return rows


def split_span(text, loc, n):
    """A source line as (before, flagged span, after), tabs expanded. The span is
    empty unless n is the location's own line."""
    if n != loc["line"]:
        return text.expandtabs(4), "", ""
    start = max(loc["col"] - 1, 0)
    end = loc["end_col"] - 1 if loc["end_line"] == n and loc["end_col"] else len(text)
    end = max(start, min(end, len(text)))
    pre, mid, post = text[:start], text[start:end], text[end:]
    a = pre.expandtabs(4)
    b = (pre + mid).expandtabs(4)[len(a):]
    c = (pre + mid + post).expandtabs(4)[len(a) + len(b):]
    return a, b, c


def marked(text, loc, n, paint):
    a, b, c = split_span(text, loc, n)
    return a + paint(b, "span") + c


# --- shared text helpers -----------------------------------------------------

def where(loc):
    if not loc or not loc["uri"]:
        return "(no location)"
    return f"{loc['uri']}:{loc['line']}:{loc['col']}" if loc["line"] else loc["uri"]


def label(f, paint, pad=False):
    text = f["severity"].upper() + (f" {f['score']:.1f}" if f["score"] is not None else "")
    return paint(text.ljust(12) if pad else text, f["severity"])


def message(f, paint, places):
    def link(match):
        text, loc = match.group(1), f["related"].get(match.group(2))
        if places and loc and loc["line"]:
            return f"{paint(text, 'bold')} ({paint(where(loc), 'loc')})"
        return text
    return LINK.sub(link, f["message"])


def severity_counts(found):
    counts = {}
    for f in found:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def by_rule(found):
    """[(rule id, findings)], most severe rule first, then the busiest."""
    groups = {}
    for f in found:
        groups.setdefault(f["rule"], []).append(f)
    return sorted(groups.items(), key=lambda kv: (-kv[1][0]["rank"], -len(kv[1]), kv[0]))


def plural(n, word):
    return f"{n} {word}{'' if n == 1 else 's'}"


# --- terminal rendering ------------------------------------------------------

def heading(f, paint):
    parts = [label(f, paint), paint(f["rule"], "bold"), f["title"]]
    if f["cwes"]:
        parts.append(paint("[" + ", ".join(f["cwes"]) + "]", "dim"))
    return "  ".join(parts)


def excerpt(src, loc, before, after, paint):
    rows = src.around(loc, before, after)
    width = len(str(rows[-1][0])) if rows else 0
    return [f"  {paint('>', 'mark') if n == loc['line'] else ' '} {paint(str(n).rjust(width), 'dim')} "
            f"{paint('│', 'dim')} {marked(text, loc, n, paint)}" for n, text in rows]


def path_steps(f, src, paint):
    out = []
    for pi, steps in enumerate(f["paths"], 1):
        out.append(paint(f"Path {pi} of {len(f['paths'])}, {len(steps)} steps:", "bold"))
        width = len(str(len(steps)))
        for si, loc in enumerate(steps, 1):
            role = "  source" if si == 1 else "  sink" if si == len(steps) else ""
            out.append(f"  {str(si).rjust(width)}  {paint(where(loc), 'loc')}  {loc['message']}{paint(role, 'dim')}")
            text = src.line(loc, loc["line"]) if loc["line"] else None
            if text is not None:
                out.append(f"  {' ' * width}  {paint('│', 'dim')} {marked(text, loc, loc['line'], paint).strip()}")
    return out


def path_summary(f, paint):
    steps, more = f["paths"][0], len(f["paths"]) - 1
    text = f"path: {where(steps[0])} → {where(steps[-1])}, {len(steps)} steps"
    if more:
        text += f" (+{plural(more, 'more path')})"
    return paint(text, "dim")


def detail(f, src, paint):
    """Everything about one finding: the fzf preview and the enter pager."""
    out = [heading(f, paint)]
    if f["description"]:
        out.append(paint(f["description"], "dim"))
    out += ["", f"{paint(where(f['where']), 'loc')}  {message(f, paint, True)}"]
    out += excerpt(src, f["where"], 4, 2, paint)
    if f["paths"]:
        out += [""] + path_steps(f, src, paint)
    info = ([f"precision {f['precision']}"] if f["precision"] else []) + [f"from {f['sarif']}"]
    out += ["", paint("   ".join(info), "dim")]
    return "\n".join(out)


def entry(f, src, paint, all_steps):
    """One finding in the printed report."""
    out = [heading(f, paint), f"  {paint(where(f['where']), 'loc')}  {message(f, paint, True)}"]
    out += excerpt(src, f["where"], 0, 0, paint)
    if f["paths"]:
        out += ["  " + line for line in path_steps(f, src, paint)] if all_steps else ["  " + path_summary(f, paint)]
    return "\n".join(out)


def summary(found, dupes, nfiles, filtered, paint, per_rule=True):
    counts = severity_counts(found)
    head = f"{plural(len(found), 'finding')} in {plural(nfiles, 'SARIF file')}"
    if counts:
        head += ": " + ", ".join(paint(f"{counts[s]} {s}", s) for s in ORDER if s in counts)
    notes = (["filtered"] if filtered else []) + ([f"{plural(dupes, 'duplicate')} skipped"] if dupes else [])
    if notes:
        head += paint(f"  ({', '.join(notes)})", "dim")
    lines = [head]
    if per_rule:
        groups = by_rule(found)
        width = max((len(str(len(g))) for _, g in groups), default=1)
        for rid, group in groups:
            lines.append(f"  {str(len(group)).rjust(width)}  {label(group[0], paint, pad=True)}  "
                         f"{paint(rid, 'bold')}  {group[0]['title']}")
    return "\n".join(lines)


# --- HTML report -------------------------------------------------------------

def esc(text):
    return html.escape(str(text), quote=True)


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")


def cwe_link(cwe):
    return f'<a href="https://cwe.mitre.org/data/definitions/{cwe.split("-", 1)[1]}.html">{esc(cwe)}</a>'


def badge(f):
    return f'<span class="badge sev-{f["severity"]}">{esc(label(f, PLAIN))}</span>'


def search_text(f):
    return " ".join([f["rule"], f["title"], where(f["where"]), message(f, PLAIN, False)] + f["cwes"]).lower()


def code_html(src, loc, before, after):
    rows = []
    for n, text in src.around(loc, before, after):
        a, b, c = split_span(text, loc, n)
        body = esc(a) + (f"<mark>{esc(b)}</mark>" if b else "") + esc(c)
        rows.append(f'<div class="l{" hit" if n == loc["line"] else ""}"><span class="n">{n}</span>{body}</div>')
    return f'<div class="code">{"".join(rows)}</div>' if rows else ""


def message_html(f):
    out, last = [], 0
    for match in LINK.finditer(f["message"]):
        out.append(esc(f["message"][last:match.start()]))
        loc = f["related"].get(match.group(2))
        out.append(f"<strong>{esc(match.group(1))}</strong>"
                   + (f" (<code>{esc(where(loc))}</code>)" if loc and loc["line"] else ""))
        last = match.end()
    out.append(esc(f["message"][last:]))
    return "".join(out)


def flows_html(f, src):
    out, total = [], len(f["paths"])
    for pi, steps in enumerate(f["paths"], 1):
        items = []
        for si, loc in enumerate(steps, 1):
            role = "source" if si == 1 else "sink" if si == len(steps) else ""
            tag = f' <span class="role {role}">{role}</span>' if role else ""
            items.append(f'<li><div class="step"><code>{esc(where(loc))}</code> '
                         f'<span class="msg">{esc(loc["message"])}</span>{tag}</div>'
                         f'{code_html(src, loc, 0, 0)}</li>')
        title = f"Data flow, path {pi} of {total}" if total > 1 else "Data flow"
        out.append(f'<details class="flow"{" open" if pi == 1 else ""}><summary>{title}: '
                   f'{plural(len(steps), "step")}, <code>{esc(where(steps[0]))}</code> → '
                   f'<code>{esc(where(steps[-1]))}</code></summary><ol class="steps">{"".join(items)}</ol></details>')
    return "".join(out)


MD_LINK = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def md_inline(text):
    """Inline Markdown to HTML. Everything is escaped first; only code spans,
    bold and http(s)/mailto links are turned back into markup."""
    def link(match):
        if re.match(r"(https?:|mailto:)", match.group(2), re.I):
            return f'<a href="{match.group(2)}">{match.group(1)}</a>'
        return match.group(1)
    out = []
    for i, part in enumerate(re.split(r"(`[^`]+`)", text)):
        if i % 2:
            out.append(f"<code>{esc(part[1:-1])}</code>")
        else:
            part = MD_LINK.sub(link, esc(part))
            out.append(re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", part))
    return "".join(out)


def md_table(rows):
    cells = [[c.strip() for c in row.strip().strip("|").split("|")] for row in rows]
    cells = [row for row in cells if not all(re.fullmatch(r":?-+:?", c) for c in row if c)]
    if not cells:
        return ""
    head = "".join(f"<th>{md_inline(c)}</th>" for c in cells[0])
    body = "".join("<tr>" + "".join(f"<td>{md_inline(c)}</td>" for c in row) + "</tr>" for row in cells[1:])
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def md_html(text):
    """Query help, CodeQL's small Markdown subset, as HTML. The leading title is
    dropped (the rule heading shows it) and headings sit below the rule's. Raw
    HTML in the help comes out as text, never as markup."""
    out, para, items, rows = [], [], [], []
    kind = None

    def flush():
        nonlocal para, items, rows, kind
        if para:
            out.append(f"<p>{md_inline(' '.join(para))}</p>")
        if items:
            out.append(f"<{kind}>" + "".join(f"<li>{md_inline(i)}</li>" for i in items) + f"</{kind}>")
        if rows:
            out.append(md_table(rows))
        para, items, rows, kind = [], [], [], None

    lines, i = text.splitlines(), 0
    while i < len(lines):
        line, stripped = lines[i], lines[i].strip()
        i += 1
        fence = re.match(r"(`{3,}|~{3,})", stripped)
        if fence:
            flush()
            code = []
            while i < len(lines) and not lines[i].strip().startswith(fence.group(1)):
                code.append(lines[i].expandtabs(4))
                i += 1
            i += 1
            out.append(f"<pre><code>{esc(chr(10).join(code))}</code></pre>")
            continue
        head = re.match(r"(#{1,6})\s+(.*?)\s*#*$", stripped)
        if head:
            flush()
            if len(head.group(1)) == 1 and not out:
                continue
            level = min(6, len(head.group(1)) + 2)
            out.append(f"<h{level}>{md_inline(head.group(2))}</h{level}>")
            continue
        item = re.match(r"([*+-]|\d+[.)])\s+(.*)", stripped)
        if item:
            this = "ol" if item.group(1)[0].isdigit() else "ul"
            if para or rows or (kind and kind != this):
                flush()
            kind = this
            items.append(item.group(2))
        elif stripped.startswith("|"):
            if para or items:
                flush()
            rows.append(stripped)
        elif not stripped:
            flush()
        elif items and line[:1] in (" ", "\t"):
            items[-1] += " " + stripped
        else:
            if items or rows:
                flush()
            para.append(stripped)
    flush()
    return "".join(out)


def finding_html(f, n, src, context):
    w = f["where"]
    facts = [f'<a href="#rule-{slug(f["rule"])}"><code>{esc(f["rule"])}</code></a>',
             f"<code>{esc(where(w))}</code>"] + [cwe_link(c) for c in f["cwes"]]
    return (f'<article class="finding sev-{f["severity"]}" id="f{n}" data-sev="{f["severity"]}" '
            f'data-search="{esc(search_text(f))}">'
            f'<h3><a class="fid" href="#f{n}">#{n}</a>{badge(f)}<span>{esc(f["title"])}</span></h3>'
            f'<div class="facts">{" · ".join(facts)}</div>'
            f'<p class="message">{message_html(f)}</p>'
            f'{code_html(src, w, context, context)}{flows_html(f, src)}'
            f'<div class="origin">from <code>{esc(f["sarif"])}</code></div></article>')


def rule_html(rid, group, rule_help):
    f = group[0]
    facts = [badge(f), plural(len(group), "finding")]
    facts += ([f"precision {esc(f['precision'])}"] if f["precision"] else []) + [cwe_link(c) for c in f["cwes"]]
    if rule_help:
        text, is_markdown = rule_help
        body = md_html(text) if is_markdown else f'<p class="pre">{esc(text)}</p>'
    else:
        body = f"<p>{esc(f['description'])}</p>" if f["description"] else ""
    return (f'<section class="rule" id="rule-{slug(rid)}"><h3><code>{esc(rid)}</code> {esc(f["title"])}</h3>'
            f'<div class="facts">{" · ".join(facts)}</div><div class="help">{body}</div></section>')


def report_html(found, info, src, meta):
    counts, groups = severity_counts(found), by_rule(found)
    number = {f["id"]: n for n, f in enumerate(found, 1)}
    chips = [f'<div class="chip"><b>{len(found)}</b><span>findings</span></div>'] + [
        f'<div class="chip sev-{s}"><b>{counts[s]}</b><span>{s}</span></div>' for s in ORDER if s in counts]
    rule_rows = "".join(
        f'<tr><td>{badge(g[0])}</td><td><a href="#rule-{slug(rid)}"><code>{esc(rid)}</code></a></td>'
        f'<td>{esc(g[0]["title"])}</td><td>{", ".join(cwe_link(c) for c in g[0]["cwes"])}</td>'
        f'<td class="num">{len(g)}</td></tr>' for rid, g in groups)
    index_rows = "".join(
        f'<tr data-sev="{f["severity"]}" data-search="{esc(search_text(f))}">'
        f'<td class="num"><a href="#f{number[f["id"]]}">{number[f["id"]]}</a></td><td>{badge(f)}</td>'
        f'<td><code>{esc(f["rule"])}</code></td><td><code>{esc(where(f["where"]))}</code></td>'
        f'<td>{esc(message(f, PLAIN, False))}</td></tr>' for f in found)
    toggles = "".join(f'<label class="sev-{s}"><input type="checkbox" value="{s}" checked> {s} ({counts[s]})</label>'
                      for s in ORDER if s in counts)
    meta_line = " · ".join([f"Generated {esc(meta['generated'])}", f"source <code>{esc(meta['root'])}</code>"]
                           + [esc(t) for t in info["tools"]])
    notes = [f'<p class="meta">SARIF: {", ".join(f"<code>{esc(s)}</code>" for s in meta["sarifs"])}</p>']
    if meta["filtered"]:
        notes.append(f'<p class="meta">Filtered: {esc(meta["filtered"])}</p>')
    if found:
        findings = (
            '<div class="controls"><input type="search" id="q" placeholder="Filter by rule, file, message or CWE">'
            f'<span id="sev">{toggles}</span>'
            '<button type="button" id="expand">Expand all</button><button type="button" id="collapse">Collapse all</button>'
            f'<span class="count"><b id="shown">{len(found)}</b> shown</span></div>'
            '<details class="index" open><summary>Index</summary><table><thead><tr><th>#</th><th>Severity</th>'
            f'<th>Rule</th><th>Location</th><th>Message</th></tr></thead><tbody>{index_rows}</tbody></table></details>'
            + "".join(finding_html(f, number[f["id"]], src, meta["context"]) for f in found))
        rules = "".join(rule_html(rid, g, info["help"].get(rid)) for rid, g in groups)
        if not any(rid in info["help"] for rid, _ in groups):
            rules = ('<p class="meta">This SARIF carries no query help, so only short descriptions are shown. '
                     '<code>codeql-scan</code> includes it; with <code>codeql database analyze</code>, add '
                     '<code>--sarif-include-query-help=always</code>.</p>') + rules
        rules_table = ('<table><thead><tr><th>Severity</th><th>Rule</th><th>Title</th><th>CWE</th>'
                       f'<th class="num">Findings</th></tr></thead><tbody>{rule_rows}</tbody></table>')
    else:
        findings, rules, rules_table = '<p>No findings.</p>', '<p>No findings, so no rules to describe.</p>', ""
    return "\n".join([
        "<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{esc(meta['title'])}</title>", f"<style>{CSS}</style>", "</head>", "<body>", "<main>",
        f'<header><h1>{esc(meta["title"])}</h1><p class="meta">{meta_line}</p>{"".join(notes)}</header>',
        f'<section id="summary"><h2>Summary</h2><div class="chips">{"".join(chips)}</div>{rules_table}</section>',
        f'<section id="findings"><h2>Findings</h2>{findings}</section>',
        f'<section id="rules"><h2>Rules</h2>{rules}</section>',
        '<footer>Written by codeql-findings (skw/codeql).</footer>',
        "</main>", f"<script>{JS}</script>", "</body>", "</html>", ""])


CSS = """
:root{color-scheme:light dark;--bg:#fff;--fg:#1f2328;--muted:#59636e;--border:#d1d9e0;--panel:#f6f8fa;
--hit:#fff8c5;--mark:#ffcecb;--mark-fg:#82071e;--link:#0969da;--critical:#8250df;--high:#cf222e;
--medium:#9a6700;--low:#0969da;--error:#bc4c00;--warning:#9a6700;--note:#59636e;--none:#59636e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--border:#3d444d;
--panel:#151b23;--hit:#2e2a14;--mark:#67060c;--mark-fg:#ffdcd7;--link:#4493f8;--critical:#ab7df8;
--high:#f85149;--medium:#d29922;--low:#4493f8;--error:#db6d28;--warning:#d29922;--note:#9198a1;--none:#9198a1}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1120px;margin:0 auto;padding:32px 20px 64px}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
code,.code{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace;font-size:12.5px}
h1{font-size:26px;margin:0 0 6px}
h2{font-size:20px;margin:40px 0 14px;padding-bottom:6px;border-bottom:1px solid var(--border)}
.meta{color:var(--muted);font-size:13px;margin:2px 0}
.sev-critical{--sev:var(--critical)}.sev-high{--sev:var(--high)}.sev-medium{--sev:var(--medium)}
.sev-low{--sev:var(--low)}.sev-error{--sev:var(--error)}.sev-warning{--sev:var(--warning)}
.sev-note{--sev:var(--note)}.sev-none{--sev:var(--none)}
.chips{display:flex;flex-wrap:wrap;gap:10px;margin:0 0 18px}
.chip{border:1px solid var(--border);border-top:3px solid var(--sev,var(--border));border-radius:8px;
padding:8px 16px;background:var(--panel);min-width:104px}
.chip b{display:block;font-size:24px;line-height:1.2;color:var(--sev,var(--fg))}
.chip span{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em}
.badge{display:inline-block;padding:0 8px;border-radius:999px;font:600 11px/1.8 ui-monospace,Menlo,Consolas,monospace;
color:#fff;background:var(--sev);white-space:nowrap;vertical-align:1px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}.num{text-align:right;font-variant-numeric:tabular-nums}
.controls{display:none;gap:10px 14px;align-items:center;flex-wrap:wrap;position:sticky;top:0;z-index:1;
background:var(--bg);padding:10px 0;margin-bottom:8px;border-bottom:1px solid var(--border)}
.js .controls{display:flex}
.controls input[type=search]{flex:1 1 260px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;
background:var(--panel);color:var(--fg);font:inherit}
.controls label{font-size:13px;white-space:nowrap;margin-right:10px;color:var(--sev)}
.controls button{font:inherit;font-size:13px;padding:4px 10px;border:1px solid var(--border);border-radius:6px;
background:var(--panel);color:var(--fg);cursor:pointer}
.count{color:var(--muted);font-size:13px;margin-left:auto}
details>summary{cursor:pointer}
.index{margin:8px 0 20px}.index>summary{font-weight:600;margin-bottom:6px}
.finding{border:1px solid var(--border);border-left:4px solid var(--sev);border-radius:8px;padding:14px 18px;margin:16px 0}
.finding h3{margin:0 0 4px;font-size:16px;display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.fid{color:var(--muted);font-weight:500}
.facts{color:var(--muted);font-size:13px}
.message{margin:10px 0}
.code{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:6px 0;overflow-x:auto;
line-height:1.55;margin:8px 0}
.code .l{white-space:pre;padding-right:14px;min-width:max-content}
.code .l.hit{background:var(--hit)}
.code .n{display:inline-block;width:4.2em;padding-right:14px;text-align:right;color:var(--muted);user-select:none}
mark{background:var(--mark);color:var(--mark-fg);border-radius:3px;padding:0 1px}
.flow{margin-top:12px}.flow>summary{font-weight:600;font-size:13px}
.steps{list-style:none;counter-reset:step;margin:10px 0 4px 10px;padding:0;border-left:2px solid var(--border)}
.steps li{counter-increment:step;position:relative;padding:0 0 10px 22px}
.steps li::before{content:counter(step);position:absolute;left:-11px;top:1px;width:20px;height:20px;border-radius:50%;
background:var(--panel);border:1px solid var(--border);font-size:11px;line-height:18px;text-align:center;color:var(--muted)}
.steps .code{margin:4px 0 0}.step{font-size:13px}.msg{color:var(--muted)}
.role{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:1px 6px;border-radius:4px;
border:1px solid currentColor;margin-left:6px}.role.source{color:var(--low)}.role.sink{color:var(--high)}
.origin{color:var(--muted);font-size:12px;margin-top:8px}
.rule{border-top:1px solid var(--border);padding:6px 0 10px}.rule:first-of-type{border-top:0}
.rule h3{font-size:16px;margin:14px 0 4px}
.help h3,.help h4,.help h5,.help h6{font-size:14px;margin:16px 0 6px}
.help pre{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:10px 12px;overflow-x:auto}
.help table{margin:8px 0}.pre{white-space:pre-wrap}
footer{color:var(--muted);font-size:12px;margin-top:48px}
@media print{.controls{display:none!important}.finding{break-inside:avoid-page}body{font-size:12px}
main{max-width:none;padding:0}a{color:inherit}}
"""

JS = """
(function () {
  document.documentElement.classList.add('js');
  var q = document.getElementById('q');
  if (!q) return;
  var boxes = [].slice.call(document.querySelectorAll('#sev input'));
  var items = [].slice.call(document.querySelectorAll('[data-sev]'));
  var shown = document.getElementById('shown');
  function apply() {
    var text = q.value.trim().toLowerCase(), on = {}, n = 0;
    boxes.forEach(function (b) { on[b.value] = b.checked; });
    items.forEach(function (el) {
      var ok = on[el.dataset.sev] !== false && (!text || el.dataset.search.indexOf(text) !== -1);
      el.hidden = !ok;
      if (ok && el.tagName === 'ARTICLE') n++;
    });
    shown.textContent = n;
  }
  function openAll(state) {
    document.querySelectorAll('details.flow, details.index').forEach(function (d) { d.open = state; });
  }
  q.addEventListener('input', apply);
  boxes.forEach(function (b) { b.addEventListener('change', apply); });
  document.getElementById('expand').addEventListener('click', function () { openAll(true); });
  document.getElementById('collapse').addEventListener('click', function () { openAll(false); });
  window.addEventListener('beforeprint', function () {
    document.querySelectorAll('details').forEach(function (d) { d.open = true; });
  });
})();
"""


# --- Markdown report ---------------------------------------------------------

def md_escape(text):
    return re.sub(r"([\\`*_\[\]<>|#])", r"\\\1", text)


def md_code_span(text):
    tick = "`" * (max((len(run) for run in re.findall(r"`+", text)), default=0) + 1)
    pad = " " if text[:1] == "`" or text[-1:] == "`" else ""
    return f"{tick}{pad}{text}{pad}{tick}"


def md_fence(body):
    return "`" * max(3, max((len(run) for run in re.findall(r"`+", body)), default=0) + 1)


def code_md(src, loc, before, after, indent=""):
    rows = src.around(loc, before, after)
    if not rows:
        return []
    width, out = len(str(rows[-1][0])), []
    for n, text in rows:
        a, b, c = split_span(text, loc, n)
        out.append(f"{'>' if n == loc['line'] else ' '} {str(n).rjust(width)} | {a}{b}{c}".rstrip())
        if b:
            # A caret line under the flagged span, since a code block can't colour it.
            out.append(f"  {' ' * width} | {' ' * len(a)}{'^' * len(b)}")
    fence = md_fence("\n".join(out))
    return [indent + line for line in [fence] + out + [fence]]


def message_md(f):
    out, last = [], 0
    for match in LINK.finditer(f["message"]):
        out.append(md_escape(f["message"][last:match.start()]))
        loc = f["related"].get(match.group(2))
        out.append(f"**{md_escape(match.group(1))}**" + (f" ({md_code_span(where(loc))})" if loc and loc["line"] else ""))
        last = match.end()
    out.append(md_escape(f["message"][last:]))
    return "".join(out)


def md_safe(line):
    """A help line with raw HTML shown as text and only http(s)/mailto links kept,
    outside code spans: some Markdown viewers render raw HTML and javascript: links."""
    parts = re.split(r"(`[^`]+`)", line)
    for i in range(0, len(parts), 2):
        part = parts[i].replace("<", "\\<")
        parts[i] = MD_LINK.sub(lambda m: m.group(0) if re.match(r"(https?:|mailto:)", m.group(2), re.I)
                               else m.group(1), part)
    return "".join(parts)


def md_demote(text, shift):
    """Query help with its title dropped, headings pushed under the rule's, and
    made safe outside code blocks."""
    out, fence, first = [], None, True
    for line in text.splitlines():
        stripped = line.strip()
        if fence:
            out.append(line)
            if stripped.startswith(fence):
                fence = None
            continue
        opening = re.match(r"(`{3,}|~{3,})", stripped)
        head = re.match(r"(#{1,6})(\s.*)", line)
        if opening:
            fence = opening.group(1)
        elif head:
            if first and len(head.group(1)) == 1:
                first = False
                continue
            line = "#" * min(6, len(head.group(1)) + shift) + md_safe(head.group(2))
        else:
            line = md_safe(line)
        if stripped:
            first = False
        out.append(line)
    return "\n".join(out).strip()


def report_markdown(found, info, src, meta):
    counts, groups = severity_counts(found), by_rule(found)
    out = [f"# {md_escape(meta['title'])}", "",
           " · ".join([f"Generated {meta['generated']}", f"source {md_code_span(meta['root'])}"]
                      + [md_escape(t) for t in info["tools"]]) + "  ",
           "SARIF: " + ", ".join(md_code_span(s) for s in meta["sarifs"])]
    if meta["filtered"]:
        out[-1] += "  "
        out.append(f"Filtered: {md_escape(meta['filtered'])}")
    out += ["", "## Summary", ""]
    if not found:
        return "\n".join(out + ["No findings.", ""])
    out += [f"**{plural(len(found), 'finding')}:** " + ", ".join(f"{counts[s]} {s}" for s in ORDER if s in counts), "",
            "| Severity | Rule | Title | CWE | Findings |", "|---|---|---|---|---:|"]
    out += [f"| {label(g[0], PLAIN)} | {md_code_span(rid)} | {md_escape(g[0]['title'])} | "
            f"{', '.join(g[0]['cwes'])} | {len(g)} |" for rid, g in groups]
    out += ["", "## Findings"]
    for n, f in enumerate(found, 1):
        out += ["", f"### {n}. {label(f, PLAIN)} · {md_escape(f['title'])}", "",
                " · ".join([md_code_span(f["rule"]), md_code_span(where(f["where"]))] + f["cwes"]), "",
                message_md(f), ""]
        out += code_md(src, f["where"], meta["context"], meta["context"])
        for pi, steps in enumerate(f["paths"], 1):
            title = f"Data flow, path {pi} of {len(f['paths'])}" if len(f["paths"]) > 1 else "Data flow"
            out += ["", f"**{title}** ({plural(len(steps), 'step')}):", ""]
            for si, loc in enumerate(steps, 1):
                role = " *(source)*" if si == 1 else " *(sink)*" if si == len(steps) else ""
                out.append(f"{si}. {md_code_span(where(loc))} {md_escape(loc['message'])}{role}")
                out += code_md(src, loc, 0, 0, indent=" " * len(f"{si}. "))
        out += ["", f"<sub>from {md_code_span(f['sarif'])}</sub>"]
    out += ["", "## Rules"]
    for rid, group in groups:
        f = group[0]
        facts = [label(f, PLAIN), plural(len(group), "finding")] + \
                ([f"precision {f['precision']}"] if f["precision"] else []) + f["cwes"]
        out += ["", f"### {md_code_span(rid)} {md_escape(f['title'])}", "", " · ".join(facts), ""]
        rule_help = info["help"].get(rid)
        if rule_help:
            text, is_markdown = rule_help
            out.append(md_demote(text, 2) if is_markdown else md_escape(text))
        elif f["description"]:
            out.append(md_escape(f["description"]))
    return "\n".join(out) + "\n"


# --- modes -------------------------------------------------------------------

def browse(found, head, args):
    """fzf over the findings; previews re-run this script with --show."""
    fd, cache = tempfile.mkstemp(prefix="codeql-findings-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(found, fh)
        paint, src = Paint(True), Sources(args.src)
        rule_w = min(max(len(f["rule"]) for f in found), 45)
        loc_w = min(max(len(where(f["where"])) for f in found), 40)
        rows = []
        for f in found:
            w = f["where"]
            path = src.path(w["uri"])
            text = "  ".join([label(f, paint, pad=True), paint(f["rule"].ljust(rule_w), "bold"),
                              paint(where(w).ljust(loc_w), "loc"), message(f, PLAIN, False)])
            # Hidden fields: 1 id (for --show), 2 file and 3 line (for the editor).
            rows.append(f"{f['id']}\t{os.path.abspath(path) if path else ''}\t{w['line'] or 1}\t{text}")
        show = shlex.join([sys.executable, os.path.abspath(__file__), "--cache", cache,
                           "--src", args.src, "--color", "always", "--show"])
        cmd = [shutil.which("fzf"), "--ansi", "--layout=reverse", "--no-sort", "--tiebreak=index",
               "--delimiter=\t", "--with-nth=4", "--prompt=findings> ",
               f"--header={head}\n{LEGEND}",
               f"--preview={show} {{1}}",
               # The <80 is the preview's own width: below ~134 columns it moves under the list.
               "--preview-window=right,60%,wrap,border-left,<80(down,65%,wrap,border-top)",
               f"--bind=enter:execute:{show} {{1}} | less -R",
               "--bind=ctrl-e:execute:${EDITOR:-nano} +{3} {2}",
               "--bind=ctrl-/:toggle-preview"]
        code = subprocess.run(cmd, input="\n".join(rows) + "\n", text=True).returncode
        return 0 if code in (0, 1, 130) else code
    finally:
        os.unlink(cache)


def host_path(path):
    """The host's spelling of a path under the working directory, which the
    codeql-findings alias passes in HOST_PWD (inside the container it is /work)."""
    host, here = os.environ.get("HOST_PWD"), os.getcwd()
    if host and (path == here or path.startswith(here + os.sep)):
        return host + path[len(here):]
    return path


def write_reports(found, info, sarifs, args):
    root = host_path(args.src)
    notes = ([f"severity {args.severity} and above"] if args.severity != "all" else []) + \
            (["rule id containing " + " or ".join(repr(r) for r in args.rule)] if args.rule else [])
    meta = {
        "title": args.title or f"CodeQL report: {os.path.basename(root.rstrip(os.sep)) or root}",
        "root": root,
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "sarifs": sarifs,
        "filtered": ", ".join(notes),
        "context": max(0, args.context),
    }
    src = Sources(args.src)
    for target, render in ((args.html, report_html), (args.markdown, report_markdown)):
        if not target:
            continue
        text = render(found, info, src, meta)
        if target == "-":
            sys.stdout.write(text)
            continue
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"codeql-findings: wrote {target} ({plural(len(found), 'finding')})", file=sys.stderr)


def default_sarifs():
    here = sorted(glob.glob("*.sarif"))
    if here:
        return here
    deeper = sorted(glob.glob("*/*.sarif") + glob.glob("*/*/*.sarif"))
    hint = "".join(f"\n  {p}" for p in deeper[:10])
    raise SystemExit("codeql-findings: no *.sarif in the current directory; name the files to read"
                     + (", e.g.:" + hint if hint else ""))


def main():
    ap = argparse.ArgumentParser(
        prog="codeql-findings",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
        epilog="examples:\n"
               "  codeql-findings                          *.sarif here, in fzf\n"
               "  codeql-findings -s high results.sarif    high and critical only\n"
               "  codeql-findings --list -p | less -R      text report with every data-flow step\n"
               "  codeql-findings --summary                counts per severity and per rule\n"
               "  codeql-findings --html report.html       full HTML report\n"
               "  codeql-findings --markdown report.md     the same as Markdown")
    ap.add_argument("sarif", nargs="*", help="SARIF files (default: *.sarif in the current directory)")
    ap.add_argument("-l", "--list", action="store_true", help="print a text report instead of opening fzf")
    ap.add_argument("--summary", action="store_true", help="only the counts per severity and per rule")
    ap.add_argument("--html", metavar="FILE", help="write a full HTML report to FILE ('-' for stdout)")
    ap.add_argument("--markdown", metavar="FILE", help="write a full Markdown report to FILE ('-' for stdout)")
    ap.add_argument("-s", "--severity", choices=["critical", "high", "medium", "low", "all"], default="all",
                    help="minimum security severity; anything but 'all' drops non-security results")
    ap.add_argument("-r", "--rule", action="append", metavar="TEXT",
                    help="only rules whose id contains TEXT (repeatable)")
    ap.add_argument("-p", "--paths", action="store_true",
                    help="in the text report, every data-flow step rather than source → sink")
    ap.add_argument("-C", "--context", type=int, default=3, metavar="N",
                    help="source lines either side of a finding in --html/--markdown (default: 3)")
    ap.add_argument("--title", help="report title (default: 'CodeQL report: <directory>')")
    ap.add_argument("--src", default=".", metavar="DIR",
                    help="source root the SARIF paths are relative to (default: .)")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    ap.add_argument("--show", metavar="ID", help=argparse.SUPPRESS)
    ap.add_argument("--cache", help=argparse.SUPPRESS)
    args = ap.parse_args()
    args.src = os.path.abspath(args.src)
    paint = Paint(args.color == "always" or (args.color == "auto" and sys.stdout.isatty()))

    if args.show:
        if args.cache:
            with open(args.cache, encoding="utf-8") as fh:
                found = json.load(fh)
        else:
            found = load(args.sarif or default_sarifs())[0]
        match = next((f for f in found if f["id"] == args.show), None)
        if match is None:
            raise SystemExit(f"codeql-findings: no finding {args.show}")
        print(detail(match, Sources(args.src), paint))
        return 0

    sarifs = args.sarif or default_sarifs()
    found, dupes, info = load(sarifs)
    found = [f for f in found if wanted(f, args)]
    filtered = args.severity != "all" or bool(args.rule)

    if args.html or args.markdown:
        write_reports(found, info, sarifs, args)
        return 0

    if not args.list and not args.summary and found and sys.stdin.isatty() and sys.stdout.isatty() \
            and shutil.which("fzf"):
        return browse(found, summary(found, dupes, len(sarifs), filtered, Paint(True), per_rule=False), args)

    print(summary(found, dupes, len(sarifs), filtered, paint))
    if not args.summary:
        src = Sources(args.src)
        for f in found:
            print()
            print(entry(f, src, paint, args.paths))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(130)
