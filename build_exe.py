#!/usr/bin/env python3
"""
Сборка exe-файлов проекта через PyInstaller.

Примеры:
    python build_exe.py
    python build_exe.py --target client
    python build_exe.py --target all --clean
    python build_exe.py --target client --onefile
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
BUILD_DIR = ROOT_DIR / "build"
DIST_DIR = ROOT_DIR / "dist"
IS_WINDOWS = sys.platform.startswith("win")
DATA_SEPARATOR = ";" if IS_WINDOWS else ":"


@dataclass(frozen=True)
class TargetConfig:
    key: str
    name: str
    entry_file: Path
    windowed: bool
    uac_admin: bool = False
    icon_file: Path | None = None
    add_data: list[tuple[Path, str]] = field(default_factory=list)
    hidden_imports: list[str] = field(default_factory=list)
    collect_submodules: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


TARGETS: dict[str, TargetConfig] = {
    "client": TargetConfig(
        key="client",
        name="DLP_Agent",
        entry_file=ROOT_DIR / "client" / "dlp_client_setup.py",
        windowed=True,
        uac_admin=True,
        collect_submodules=["shared"],
        notes=[
            "Клиент собирается как GUI-приложение без консоли.",
        ],
    ),
    "server": TargetConfig(
        key="server",
        name="DLP_Server",
        entry_file=ROOT_DIR / "server" / "server_main.py",
        windowed=False,
        add_data=[(ROOT_DIR / "config.json", "_internal")],
        hidden_imports=["mitmproxy.http"],
        collect_submodules=["server", "shared"],
        notes=[
            "Серверная часть запускает `mitmdump` как внешний процесс.",
            "Для полностью автономного server.exe может потребоваться отдельная доработка запуска mitmproxy внутри приложения.",
        ],
    ),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Собирает exe-файлы проекта через PyInstaller."
    )
    parser.add_argument(
        "--target",
        choices=["client", "server", "all"],
        default="all",
        help="Что собирать: клиент, сервер или оба приложения.",
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Удалить предыдущие папки build/dist перед сборкой.",
    )
    parser.add_argument(
        "--onefile",
        action="store_true",
        help="Собрать в один exe-файл. По умолчанию используется one-folder.",
    )
    parser.add_argument(
        "--dist-dir",
        default=str(DIST_DIR),
        help="Папка для готовых exe. По умолчанию: ./dist",
    )
    parser.add_argument(
        "--build-dir",
        default=str(BUILD_DIR),
        help="Папка для временных файлов PyInstaller. По умолчанию: ./build",
    )
    return parser.parse_args()


def ensure_pyinstaller() -> None:
    try:
        __import__("PyInstaller")
    except ImportError as exc:
        raise SystemExit(
            "PyInstaller не найден. Установите зависимости: pip install -r requirements.txt"
        ) from exc


def remove_path(path: Path) -> None:
    if not path.exists():
        return
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def build_pyinstaller_command(
    target: TargetConfig,
    build_root: Path,
    dist_root: Path,
    onefile: bool,
) -> list[str]:
    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--distpath",
        str(dist_root),
        "--workpath",
        str(build_root / "work"),
        "--specpath",
        str(build_root / "spec"),
        "--paths",
        str(ROOT_DIR),
        "--name",
        target.name,
    ]

    cmd.append("--onefile" if onefile else "--onedir")
    cmd.append("--windowed" if target.windowed else "--console")

    if target.uac_admin and IS_WINDOWS:
        cmd.append("--uac-admin")

    if target.icon_file and target.icon_file.exists():
        cmd.extend(["--icon", str(target.icon_file)])

    for src, dest in target.add_data:
        if src.exists():
            cmd.extend(["--add-data", f"{src}{DATA_SEPARATOR}{dest}"])

    for hidden_import in target.hidden_imports:
        cmd.extend(["--hidden-import", hidden_import])

    for module_name in target.collect_submodules:
        cmd.extend(["--collect-submodules", module_name])

    cmd.append(str(target.entry_file))
    return cmd


def ensure_server_runtime_files(dist_root: Path, onefile: bool) -> None:
    if onefile:
        return

    config_src = ROOT_DIR / "config.json"
    if not config_src.exists():
        return

    server_internal_dir = dist_root / TARGETS["server"].name / "_internal"
    server_internal_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(config_src, server_internal_dir / "config.json")


def print_command(cmd: list[str]) -> None:
    print("Команда сборки:")
    print(" ".join(f'"{part}"' if " " in part else part for part in cmd))


def build_target(
    target: TargetConfig,
    build_root: Path,
    dist_root: Path,
    onefile: bool,
) -> None:
    if not target.entry_file.exists():
        raise SystemExit(f"Не найден файл запуска: {target.entry_file}")

    print(f"\n=== Сборка: {target.key} ({target.name}) ===")
    for note in target.notes:
        print(f"[INFO] {note}")

    cmd = build_pyinstaller_command(target, build_root, dist_root, onefile)
    print_command(cmd)
    subprocess.run(cmd, cwd=ROOT_DIR, check=True)

    if target.key == "server":
        ensure_server_runtime_files(dist_root, onefile)

    if onefile:
        output_path = dist_root / f"{target.name}.exe"
    else:
        output_path = dist_root / target.name / f"{target.name}.exe"

    print(f"[OK] Готово: {output_path}")


def main() -> int:
    args = parse_args()
    ensure_pyinstaller()

    dist_root = Path(args.dist_dir).resolve()
    build_root = Path(args.build_dir).resolve()

    if args.clean:
        print("Удаляю предыдущие артефакты сборки...")
        remove_path(dist_root)
        remove_path(build_root)

    build_root.mkdir(parents=True, exist_ok=True)
    dist_root.mkdir(parents=True, exist_ok=True)

    selected_targets = (
        [TARGETS["client"], TARGETS["server"]]
        if args.target == "all"
        else [TARGETS[args.target]]
    )

    for target in selected_targets:
        build_target(target, build_root, dist_root, args.onefile)

    print("\nСборка завершена.")
    print(f"Результат: {dist_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
