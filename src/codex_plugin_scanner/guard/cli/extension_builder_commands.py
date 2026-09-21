"""Offline authoring commands, dispatched before Guard state initialization."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import TextIO

from ..extension_builder.errors import BuilderError
from ..extension_builder.io import (
    canonical_json,
    digest,
    list_value,
    object_value,
    read_bytes,
    read_json,
    text_from_bytes,
)

_METADATA_FLAGS = (
    "slug",
    "name",
    "publisher",
    "publisher_name",
    "homepage",
    "upstream_version",
    "executable",
    "launcher",
    "package",
)
_MAX_GENERATED_PROJECTION_BYTES = 8 * 1024 * 1024


def configure_extension_builder_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    parser = subparsers.add_parser(
        "extensions", help="Generate and review extension contributions from offline metadata"
    )
    commands = parser.add_subparsers(dest="extension_builder_command", required=True)
    generate = commands.add_parser("generate", help="Compile an offline inventory into a new contribution kit")
    generate.add_argument(
        "--from", dest="source_adapter", required=True, choices=("cli", "help", "click", "oclif", "mcp", "snapshot")
    )
    generate.add_argument("--input", type=Path, required=True, help="Local exported inventory or discovery snapshot")
    generate.add_argument(
        "--output", type=Path, required=True, help="New kit directory; existing directories are not overwritten"
    )
    generate.add_argument("--review", type=Path, help="Explicit review bound to this discovery snapshot")
    for name in _METADATA_FLAGS:
        generate.add_argument("--" + name.replace("_", "-"))
    generate.add_argument(
        "--topic-separator", choices=("colon", "space"), help="oclif invocation topic separator; defaults to colon"
    )
    validate = commands.add_parser(
        "validate", help="Rebuild a kit and verify every byte without importing generated code"
    )
    validate.add_argument("kit", type=Path)
    diff = commands.add_parser("diff", help="Compare valid kits; exit 1 when their inventories or reviews differ")
    diff.add_argument("previous", type=Path)
    diff.add_argument("current", type=Path)
    apply = commands.add_parser("apply", help="Plan native source integration; writing requires --write")
    apply.add_argument("kit", type=Path)
    apply.add_argument("--repo", type=Path, required=True, help="HOL Guard source checkout")
    apply.add_argument("--write", action="store_true", help="Explicitly apply the inspected source changes")
    apply.add_argument("--expected-plan", help="Require the plan digest from a previous inspection")
    handoff = commands.add_parser(
        "handoff", help="Check command-extension inputs and generated projections before opening a pull request"
    )
    handoff.add_argument("--source", type=Path, required=True, help="Canonical command source JSON")
    handoff.add_argument("--fixture", type=Path, required=True, help="Portable command fixture JSON")
    handoff.add_argument(
        "--trust-map",
        type=Path,
        default=Path("contracts/extensions/trust-class-map.v1.json"),
        help="Reviewed trust-class map (default: contracts/extensions/trust-class-map.v1.json)",
    )
    handoff.add_argument(
        "--repo", type=Path, default=Path("."), help="HOL Guard checkout containing generated projections"
    )
    for command in (generate, validate, diff, apply, handoff):
        command.add_argument("--json", action="store_true", help="Emit a deterministic JSON result")


def _generate(args: argparse.Namespace) -> dict[str, object]:
    from ..extension_builder.discover import discover
    from ..extension_builder.io import read_json
    from ..extension_builder.kit import build_kit, write_kit
    from ..extension_builder.models import Metadata
    from ..extension_builder.review import default_review, load_review

    metadata: Metadata | None = None
    if args.source_adapter == "snapshot":
        if any(getattr(args, name) is not None for name in _METADATA_FLAGS):
            raise BuilderError("snapshot_override", "Snapshot replay does not accept identity overrides.")
    else:
        if not all(getattr(args, name) for name in ("slug", "publisher", "homepage")):
            raise BuilderError("missing_metadata", "Provide --slug, --publisher, and --homepage for source discovery.")
        kind = "mcp" if args.source_adapter == "mcp" else "cli"
        if kind == "cli" and not args.executable:
            raise BuilderError("missing_metadata", "CLI discovery requires an explicit --executable basename.")
        if kind == "mcp" and (not args.launcher or not args.package):
            raise BuilderError("missing_metadata", "MCP discovery requires --launcher and --package identity.")
        metadata = Metadata(
            kind=kind,
            slug=args.slug,
            name=args.name or args.slug,
            publisher_id=args.publisher,
            publisher_name=args.publisher_name or args.publisher,
            homepage=args.homepage,
            upstream_version=args.upstream_version or "unspecified",
            executable=args.executable or "",
            launcher=args.launcher or "",
            package=args.package or "",
        )
    discovery = discover(args.source_adapter, args.input, metadata, topic_separator=args.topic_separator)
    review = load_review(read_json(args.review), discovery) if args.review is not None else default_review(discovery)
    kit = build_kit(discovery, review)
    write_kit(kit, args.output)
    return {**kit.summary(), "generated": True}


def _object_field(value: dict[str, object], name: str, *, code: str) -> dict[str, object]:
    return object_value(value.get(name), code=code)


def _string_list(value: object, *, code: str) -> list[str]:
    items = list_value(value, maximum=4096)
    if any(not isinstance(item, str) for item in items):
        raise BuilderError(code, "Expected a list of extension IDs.")
    return [str(item) for item in items]


def _projection_contains_extension(path: Path, extension_id: str) -> bool:
    content = text_from_bytes(read_bytes(path, limit=_MAX_GENERATED_PROJECTION_BYTES))
    pattern = rf'"extension_id"\s*:\s*{re.escape(json.dumps(extension_id))}'
    return re.search(pattern, content) is not None


def _handoff(args: argparse.Namespace) -> dict[str, object]:
    source = object_value(read_json(args.source), code="source_shape")
    if source.get("schema") != "guard.command-extension-source.v1":
        raise BuilderError("source_schema", "Source must use guard.command-extension-source.v1.")
    extension = _object_field(source, "extension", code="source_shape")
    extension_id = extension.get("extension_id")
    if not isinstance(extension_id, str) or not extension_id.startswith("command."):
        raise BuilderError("source_identity", "Source must declare a command.* extension ID.")
    if args.source.name != f"{extension_id}.json":
        raise BuilderError("source_filename", "Source filename must match its extension ID.")

    fixture = object_value(read_json(args.fixture), code="fixture_shape")
    if fixture.get("schema") != "guard.command-extension-fixtures.v1":
        raise BuilderError("fixture_schema", "Fixture must use guard.command-extension-fixtures.v1.")
    build = _object_field(fixture, "build", code="fixture_shape")
    if build.get("schema") != "guard.command-extension-build.v1":
        raise BuilderError("fixture_build", "Fixture build must use guard.command-extension-build.v1.")
    if source not in list_value(build.get("sources"), maximum=4096):
        raise BuilderError("fixture_binding", "Fixture must bind the exact canonical source document.")
    slug = extension_id.removeprefix("command.")
    if args.fixture.name != f"command-source-{slug}.v1.json":
        raise BuilderError("fixture_filename", "Fixture filename must match the command extension ID.")

    trust_map = object_value(read_json(args.trust_map), code="trust_shape")
    if trust_map.get("schemaVersion") != "guard.extension-trust-class-map.v1":
        raise BuilderError("trust_schema", "Trust map must use guard.extension-trust-class-map.v1.")
    classes = _object_field(trust_map, "classes", code="trust_shape")
    external = _string_list(classes.get("external"), code="trust_shape")
    if extension_id not in external:
        reviewed_classes = {
            name
            for name in ("first-party", "trusted-library")
            if extension_id in _string_list(classes.get(name), code="trust_shape")
        }
        if reviewed_classes:
            raise BuilderError(
                "trust_class",
                "External contributions must remain in the reviewed external trust class.",
            )
        raise BuilderError("missing_external_trust", "Trust map must list the extension under external.")

    try:
        source_relative = args.source.resolve().relative_to(args.repo.resolve()).as_posix()
    except ValueError as exc:
        raise BuilderError("source_path", "Source must be inside the requested HOL Guard checkout.") from exc
    descriptor_path = args.repo / "contributions" / "extensions" / f"{extension_id}.json"
    if not descriptor_path.is_file():
        raise BuilderError(
            "missing_projection",
            "Generated descriptor is missing; run the preparation command before opening a pull request.",
        )
    descriptor = object_value(read_json(descriptor_path), code="generated_shape")
    native_source = _object_field(descriptor, "nativeSource", code="generated_shape")
    if native_source.get("path") != source_relative or native_source.get("digest") != digest(source):
        raise BuilderError("projection_binding", "Generated descriptor is not bound to the current canonical source.")
    program_path = args.repo / "contracts" / "extensions" / "native-command-program.v1.json"
    catalog_path = args.repo / "contracts" / "extensions" / "command-catalog.v1.json"
    if not program_path.is_file() or not catalog_path.is_file():
        raise BuilderError(
            "missing_projection",
            "Generated native program or catalog is missing; run the preparation command "
            "before opening a pull request.",
        )
    if not _projection_contains_extension(program_path, extension_id):
        raise BuilderError("missing_projection", "Generated native program does not contain the extension.")
    if not _projection_contains_extension(catalog_path, extension_id):
        raise BuilderError("missing_projection", "Generated catalog does not contain the extension.")
    return {
        "contributionId": extension_id,
        "readyForPullRequest": True,
        "targetCommandsExecuted": 0,
    }


def _operate(args: argparse.Namespace) -> dict[str, object]:
    from ..extension_builder.kit import diff_kits, load_kit
    from ..extension_builder.repository_write import apply_kit
    from ..extension_builder.validation import SHA_PATTERN, token

    command = args.extension_builder_command
    if command == "generate":
        return _generate(args)
    if command == "handoff":
        return _handoff(args)
    if command == "validate":
        return {**load_kit(args.kit).summary(), "validated": True}
    if command == "diff":
        return diff_kits(load_kit(args.previous), load_kit(args.current))
    if command == "apply":
        if args.expected_plan is not None:
            token(args.expected_plan, pattern=SHA_PATTERN, maximum=64)
        return apply_kit(load_kit(args.kit), args.repo, write=args.write, expected_plan=args.expected_plan)
    raise BuilderError("unknown_command", "Unsupported extension authoring command.")


def _emit(result: dict[str, object], command: str, output: TextIO) -> None:
    if command == "apply":
        print(
            "Applied source changes." if result["written"] else "Source integration plan. Nothing has been written.",
            file=output,
        )
        for item in result["files"] if isinstance(result["files"], list) else []:
            if isinstance(item, dict):
                print(f"{item['action']}: {item['path']}", file=output)
        print(f"Plan digest: {result['planDigest']}", file=output)
    elif command == "diff":
        print("Kits differ." if result["changed"] else "Kits are identical.", file=output)
        for name in ("addedOperations", "removedOperations", "changedOperations", "changedReviews"):
            print(f"{name}: {result[name]}", file=output)
    elif command == "handoff":
        print(f"Contribution handoff is ready for {result['contributionId']}.", file=output)
        print("Source, fixture, external trust mapping, and generated projections agree.", file=output)
        print("No target was executed and active protection was not changed.", file=output)
    else:
        verb = "Generated" if command == "generate" else "Validated"
        print(
            f"{verb} {result['contributionId']}: {result['discoveredOperations']} operations, "
            f"{result['reviewedOperations']} explicitly reviewed.",
            file=output,
        )
        print("No target was executed and active protection was not changed.", file=output)
        print("Inspect report.json and review.json before contributing.", file=output)


def run_extension_builder_command(args: argparse.Namespace, *, output_stream: TextIO | None = None) -> int:
    output = output_stream if output_stream is not None else sys.stdout
    try:
        result = _operate(args)
    except BuilderError as exc:
        if args.json:
            print(canonical_json(exc.to_dict()), end="", file=output)
        else:
            print(f"{exc.code}: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError:
        error = BuilderError(
            "filesystem_error", "An authoring filesystem operation failed; inspect the destination before retrying."
        )
        if args.json:
            print(canonical_json(error.to_dict()), end="", file=output)
        else:
            print(str(error), file=sys.stderr)
        return error.exit_code
    except KeyboardInterrupt:
        return 130
    if args.json:
        print(canonical_json(result), end="", file=output)
    else:
        _emit(result, args.extension_builder_command, output)
    return 1 if args.extension_builder_command == "diff" and result.get("changed") else 0
