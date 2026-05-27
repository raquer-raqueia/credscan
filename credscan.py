#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════╗
║          CREDSCAN - Threat Intelligence Credential Scanner         ║
║              SOC / Threat Intel Internal Tool                      ║
╚══════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import time
import argparse
import signal
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# ── Terminal colors ──────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"
    BG_RED  = "\033[41m"
    BG_GRN  = "\033[42m"
    BG_BLK  = "\033[40m"

# ── Target domains ────────────────────────────────────────────────────────────
TARGET_DOMAINS = [
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
    "@domain",
]

# ── Regex: extract email:password pairs (handles dirty lines) ─────────────────
# Matches:  user@domain.br:password  or  user@domain.br;password
# Ignores:  URLs, extra tokens, whitespace noise
EMAIL_RE = re.compile(
    r'(?<![.\w])'                       # não precedido por caractere de palavra
    r'([\w.+\-]{1,64}'                  # local-part do e-mail
    r'@[\w\-]+(?:\.[\w\-]+)+'           # domínio
    r')'
    r'[:\;]'                            # separador
    r'([^\s:;\|,\\/\"\'\`<>]{3,128})',  # senha (sem espaço e sem delimitadores)
    re.IGNORECASE
)

# ── Banner ────────────────────────────────────────────────────────────────────
BANNER = f"""
{C.CYAN}{C.BOLD}
  ██████╗██████╗ ███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██╔════╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║     ██████╔╝█████╗  ██║  ██║███████╗██║     ███████║██╔██╗ ██║
 ██║     ██╔══██╗██╔══╝  ██║  ██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚██████╗██║  ██║███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║
  ╚═════╝╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}
{C.DIM}  Threat Intelligence Credential Scanner  ·  SOC Internal Tool{C.RESET}
{C.YELLOW}  Domínios monitorados: {len(TARGET_DOMAINS)}  |  Uso ético e responsável{C.RESET}
"""

# ── Helpers ───────────────────────────────────────────────────────────────────

def fmt_size(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n_bytes < 1024:
            return f"{n_bytes:.1f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.1f} PB"


def fmt_elapsed(seconds: float) -> str:
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


def spinner_char(i: int) -> str:
    return "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"[i % 10]


def domain_of(email: str) -> str:
    """Returns the @domain part (lower-cased) of an e-mail address."""
    return "@" + email.split("@", 1)[1].lower()


def is_target(email: str) -> bool:
    return domain_of(email) in [d.lower() for d in TARGET_DOMAINS]


def load_blacklist(path: str) -> set:
    """
    Loads blacklist.txt.
    Accepts lines in format  email:password  (case-insensitive on e-mail).
    Returns a set of normalised 'email:password' strings.
    """
    bl: set = set()
    p = Path(path)
    if not p.exists():
        print(f"{C.YELLOW}[!] blacklist.txt não encontrado em '{path}'. "
              f"Continuando sem blacklist.{C.RESET}")
        return bl

    with open(p, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Normalise: lower-case the e-mail part only
            if ":" in line:
                parts = line.split(":", 1)
                key = parts[0].lower().strip() + ":" + parts[1].strip()
                bl.add(key)
    return bl


def normalise_key(email: str, password: str) -> str:
    return email.lower().strip() + ":" + password.strip()


def extract_pairs(line: str):
    """
    Extract all (email, password) pairs from a (potentially dirty) line.
    Returns list of (email, password) tuples.
    """
    results = []
    for m in EMAIL_RE.finditer(line):
        email, pwd = m.group(1), m.group(2)
        # Basic sanity: email must have at least one dot in domain
        if "." not in email.split("@", 1)[1]:
            continue
        # Skip obvious false positives (URLs as passwords)
        if pwd.startswith("http") or "/" in pwd:
            continue
        results.append((email, pwd))
    return results


# ── Core scan ─────────────────────────────────────────────────────────────────

def scan_directory(directory: str, blacklist: set, blacklist_path: str,
                   output_file: str | None = None):
    root = Path(directory)
    if not root.exists():
        print(f"{C.RED}[✗] Diretório não encontrado: {directory}{C.RESET}")
        sys.exit(1)

    # Collect all .txt files
    txt_files = sorted(root.rglob("*.txt"))
    if not txt_files:
        print(f"{C.YELLOW}[!] Nenhum arquivo .txt encontrado em '{directory}'.{C.RESET}")
        sys.exit(0)

    total_files = len(txt_files)
    total_size  = sum(f.stat().st_size for f in txt_files)

    print(f"\n{C.BOLD}{C.BLUE}[✔] Diretório localizado:{C.RESET} {C.WHITE}{directory}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}[✔] Arquivos .txt:{C.RESET}      {C.WHITE}{total_files:,}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}[✔] Tamanho total:{C.RESET}      {C.WHITE}{fmt_size(total_size)}{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}[✔] Blacklist:{C.RESET}          {C.WHITE}{len(blacklist):,} entradas{C.RESET}")
    print(f"\n{C.DIM}{'─'*70}{C.RESET}\n")
    print(f"{C.CYAN}[*] Iniciando varredura — pressione Ctrl+C para interromper e ver parcial\n{C.RESET}")

    # ── Counters & accumulators ───────────────────────────────────────────────
    stats = {
        "files_done":   0,
        "lines_read":   0,
        "bytes_read":   0,
        "raw_hits":     0,   # all matches (including blacklisted)
        "new_hits":     0,
        "bl_hits":      0,
    }

    new_results:  dict[str, list] = defaultdict(list)  # domain → [(email, pwd, file)]
    bl_results:   dict[str, list] = defaultdict(list)

    seen_keys: set = set()   # dedup within this run

    start_time = time.time()

    def _print_live(file_idx: int, fname: str):
        elapsed = time.time() - start_time
        pct = (file_idx / total_files) * 100
        bar_len = 30
        filled  = int(bar_len * file_idx // total_files)
        bar     = "█" * filled + "░" * (bar_len - filled)
        sp      = spinner_char(file_idx)

        sys.stdout.write(
            f"\r  {sp} {C.CYAN}[{bar}]{C.RESET} "
            f"{pct:5.1f}% │ "
            f"Arqs: {C.WHITE}{file_idx:>5}/{total_files}{C.RESET} │ "
            f"{C.GREEN}Novos: {stats['new_hits']}{C.RESET} │ "
            f"{C.RED}BL: {stats['bl_hits']}{C.RESET} │ "
            f"⏱ {fmt_elapsed(elapsed)}"
            f"  {C.DIM}{fname[-35:]:<35}{C.RESET}   "
        )
        sys.stdout.flush()

    # ── Interrupt handler ────────────────────────────────────────────────────
    interrupted = False
    def _handle_interrupt(sig, frame):
        nonlocal interrupted
        interrupted = True
        print(f"\n\n{C.YELLOW}[!] Interrompido pelo usuário. Exibindo resultados parciais...{C.RESET}")

    signal.signal(signal.SIGINT, _handle_interrupt)

    # ── Main loop ─────────────────────────────────────────────────────────────
    for file_idx, fpath in enumerate(txt_files, 1):
        if interrupted:
            break

        _print_live(file_idx, fpath.name)

        try:
            fsize = fpath.stat().st_size
            with open(fpath, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if interrupted:
                        break
                    stats["lines_read"] += 1
                    pairs = extract_pairs(line)
                    for email, pwd in pairs:
                        if not is_target(email):
                            continue
                        stats["raw_hits"] += 1
                        key = normalise_key(email, pwd)
                        if key in seen_keys:
                            continue
                        seen_keys.add(key)
                        dom = domain_of(email)
                        if key in blacklist:
                            stats["bl_hits"] += 1
                            bl_results[dom].append((email, pwd, fpath.name))
                        else:
                            stats["new_hits"] += 1
                            new_results[dom].append((email, pwd, fpath.name))
            stats["bytes_read"] += fsize
        except (OSError, PermissionError) as exc:
            pass   # silently skip unreadable files

        stats["files_done"] = file_idx

    elapsed = time.time() - start_time

    # ── Results ──────────────────────────────────────────────────────────────
    print(f"\n\n{C.BOLD}{C.DIM}{'═'*70}{C.RESET}")
    print(f"{C.BOLD}{C.WHITE}  RELATÓRIO FINAL — CREDSCAN{C.RESET}")
    print(f"{C.DIM}{'═'*70}{C.RESET}\n")

    # Summary table
    print(f"  {C.BOLD}Tempo de execução:{C.RESET}  {fmt_elapsed(elapsed)}")
    print(f"  {C.BOLD}Arquivos lidos:  {C.RESET}  {stats['files_done']:,} / {total_files:,}")
    print(f"  {C.BOLD}Dados lidos:     {C.RESET}  {fmt_size(stats['bytes_read'])}")
    print(f"  {C.BOLD}Linhas lidas:    {C.RESET}  {stats['lines_read']:,}")
    print(f"  {C.BOLD}Matches brutos:  {C.RESET}  {stats['raw_hits']:,}")
    print(f"  {C.BOLD}{'✔ Novos (não reportados):':25}{C.RESET}  {C.GREEN}{C.BOLD}{stats['new_hits']:,}{C.RESET}")
    print(f"  {C.BOLD}{'✘ Já reportados (blacklist):':25}{C.RESET}  {C.RED}{C.BOLD}{stats['bl_hits']:,}{C.RESET}")
    print()

    # ── NEW results (green) ───────────────────────────────────────────────────
    if new_results:
        print(f"{C.BOLD}{C.GREEN}{'─'*70}")
        print(f"  ✅  NOVOS ACHADOS — Não constam na blacklist")
        print(f"{'─'*70}{C.RESET}\n")
        for dom in sorted(new_results):
            entries = new_results[dom]
            print(f"  {C.BOLD}{C.CYAN}{dom}{C.RESET}  {C.DIM}({len(entries)} entrada(s)){C.RESET}")
            for email, pwd, fname in entries:
                print(f"    {C.GREEN}● {C.BOLD}{email}:{pwd}{C.RESET}  {C.DIM}← {fname}{C.RESET}")
            print()
    else:
        print(f"{C.YELLOW}  Nenhum achado NOVO encontrado nos domínios monitorados.{C.RESET}\n")

    # ── BLACKLISTED results (red) ─────────────────────────────────────────────
    if bl_results:
        print(f"{C.BOLD}{C.RED}{'─'*70}")
        print(f"  🔴  JÁ REPORTADOS — Constam na blacklist")
        print(f"{'─'*70}{C.RESET}\n")
        for dom in sorted(bl_results):
            entries = bl_results[dom]
            print(f"  {C.BOLD}{C.CYAN}{dom}{C.RESET}  {C.DIM}({len(entries)} entrada(s)){C.RESET}")
            for email, pwd, fname in entries:
                print(f"    {C.RED}● {email}:{pwd}{C.RESET}  {C.DIM}← {fname}{C.RESET}")
            print()

    print(f"{C.DIM}{'═'*70}{C.RESET}")

    # ── Export novos resultados ───────────────────────────────────────────────
    if stats["new_hits"] > 0:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = output_file or f"credscan_novos_{ts}.txt"
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(f"# CREDSCAN — Novos achados — {datetime.now().isoformat()}\n")
            fh.write(f"# Diretório: {directory}\n")
            fh.write(f"# Total novos: {stats['new_hits']}\n\n")
            for dom in sorted(new_results):
                fh.write(f"## {dom}\n")
                for email, pwd, fname in new_results[dom]:
                    fh.write(f"{email}:{pwd}\n")
                fh.write("\n")
        print(f"\n{C.GREEN}[✔] Novos achados exportados para:{C.RESET} {C.WHITE}{C.BOLD}{out_path}{C.RESET}")
        print(f"{C.DIM}    Adicione estes ao seu pipeline de reporte e depois à blacklist.{C.RESET}\n")


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CREDSCAN — Threat Intel Credential Scanner",
        add_help=True
    )
    parser.add_argument("-d", "--directory",  help="Diretório com os arquivos .txt")
    parser.add_argument("-b", "--blacklist",  default="blacklist.txt",
                        help="Caminho para blacklist.txt (padrão: ./blacklist.txt)")
    parser.add_argument("-o", "--output",     help="Arquivo de saída dos novos achados")
    args = parser.parse_args()

    print(BANNER)

    # ── Blacklist ─────────────────────────────────────────────────────────────
    blacklist = load_blacklist(args.blacklist)

    # ── Directory prompt ──────────────────────────────────────────────────────
    directory = args.directory
    if not directory:
        print(f"{C.BOLD}{C.WHITE}  Qual diretório devo consultar?{C.RESET}")
        print(f"  {C.DIM}(caminho absoluto ou relativo ao diretório atual){C.RESET}")
        directory = input(f"\n  {C.CYAN}▶ {C.RESET}").strip()
        if not directory:
            print(f"{C.RED}[✗] Nenhum diretório informado. Encerrando.{C.RESET}")
            sys.exit(1)

    scan_directory(directory, blacklist, args.blacklist, args.output)


if __name__ == "__main__":
    main()
