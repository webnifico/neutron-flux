"""Command help generated directly from the public parser."""

from __future__ import annotations

import argparse

COMMAND_DESCRIPTIONS = {
    "plan": "Discover capabilities and preview full coverage and resource requirements without creating resources.",
    "run": "Run functional, performance and applicable migration tests; write HTML/JSON/JUnit reports and clean up.",
    "status": "Show the latest run checkpoint in the output directory.",
    "cleanup": "Discover all Flux-owned resources in the current project, including active runs and orphans. Preview and confirm unless --yes is supplied.",
    "report": "Rebuild HTML and JUnit reports from results.json without contacting OpenStack.",
    "compare": "Compare baseline and candidate results.json without contacting OpenStack.",
    "trend": "Summarize result files or directories without contacting OpenStack.",
}
_OPTION_GROUPS = (
    ("General", ("help", "version", "output_dir")),
    ("Instance creation", ("image", "flavor", "storage", "volume_type")),
    (
        "Network and compute scope",
        (
            "external_networks",
            "zones",
            "target_hosts",
            "target_aggregates",
            "target_host_pairs",
        ),
    ),
    (
        "Testing",
        (
            "repeat",
            "migration_mode",
            "live_attempts",
            "shared_aggregate",
            "performance_profile",
            "concurrent_vm_pairs",
            "concurrent_repeats",
            "concurrent_duration",
            "ping_target_ipv4",
            "ping_target_ipv6",
        ),
    ),
    ("Recovery and inspection", ("resume", "keep_resources")),
    ("Cleanup", ("dry_run", "yes")),
)


def format_action_help(parser, command, excluded):
    positional = {
        "report": " RESULTS.json",
        "compare": " BASELINE.json CANDIDATE.json",
        "trend": " RESULTS_OR_DIRECTORY...",
    }
    formatter = argparse.HelpFormatter(
        prog=f"{parser.prog} {command}", max_help_position=36, width=100
    )
    formatter.add_usage("%(prog)s" + positional.get(command, "") + " [OPTIONS]", [], [])
    formatter.add_text(COMMAND_DESCRIPTIONS[command])
    options = {
        item.dest: item
        for item in parser._actions
        if item.option_strings and item.dest not in excluded
    }
    for title, names in _OPTION_GROUPS:
        actions = [options.pop(name) for name in names if name in options]
        if actions:
            formatter.start_section(title)
            formatter.add_arguments(actions)
            formatter.end_section()
    if command in {"plan", "run"}:
        formatter.add_text(
            "CLI-only: no configuration files are loaded. Multiple selected compute AZs include both local and cross-AZ tests. Service AZs prefer the compute AZ where supported and available, otherwise service defaults apply. Root-volume sizing and the SSH account are automatic."
        )
    formatter.add_text("Full reference: support/docs/CLI-REFERENCE.md")
    return formatter.format_help()
