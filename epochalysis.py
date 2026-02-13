#!/usr/bin/env python3

import struct
import argparse
import sys
import json
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_RECORD_SIZE = 384  # común en sistemas x86_64


def epoch_to_utc(epoch: int) -> str:
    try:
        return datetime.fromtimestamp(epoch, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        return "Invalid timestamp"


def load_epoch_file(filepath: str) -> set:
    epochs = set()
    try:
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line.isdigit():
                    epochs.add(int(line))
    except Exception as e:
        sys.exit(f"[ERROR] No se pudo leer archivo de epochs: {e}")
    return epochs


def parse_wtmp(filepath: str, record_size: int) -> list:
    records = []

    with open(filepath, "rb") as f:
        index = 0
        while True:
            data = f.read(record_size)
            if len(data) < record_size:
                break

            try:
                ut_type = struct.unpack("<h", data[0:2])[0]
                ut_user = data[44:76].split(b'\x00')[0].decode(errors="ignore")
                ut_host = data[76:332].split(b'\x00')[0].decode(errors="ignore")
                tv_sec = struct.unpack("<i", data[340:344])[0]
            except struct.error:
                index += 1
                continue  # saltar registro corrupto

            # USER_PROCESS = 7
            if ut_type == 7:
                records.append({
                    "index": index,
                    "user": ut_user,
                    "host": ut_host,
                    "epoch": tv_sec,
                    "utc": epoch_to_utc(tv_sec)
                })

            index += 1

    return records


def main():
    parser = argparse.ArgumentParser(
        description="Forensic wtmp USER_PROCESS parser"
    )

    parser.add_argument("wtmp", help="Archivo wtmp a analizar")
    parser.add_argument("-u", "--user", help="Filtrar por usuario")
    parser.add_argument("-i", "--ip", help="Filtrar por IP remota")
    parser.add_argument("-e", "--epochs", help="Archivo con lista de EPOCHs")
    parser.add_argument("-s", "--size", type=int, default=DEFAULT_RECORD_SIZE,
                        help="Tamaño de registro utmp (default: 384)")
    parser.add_argument("--first", action="store_true",
                        help="Mostrar solo el primer USER_PROCESS cronológico")
    parser.add_argument("--json", action="store_true",
                        help="Salida en formato JSON")

    args = parser.parse_args()

    if not Path(args.wtmp).exists():
        sys.exit("[ERROR] Archivo wtmp no encontrado.")

    epoch_candidates = load_epoch_file(args.epochs) if args.epochs else None

    records = parse_wtmp(args.wtmp, args.size)

    # Aplicar filtros
    if args.user:
        records = [r for r in records if args.user in r["user"]]

    if args.ip:
        records = [r for r in records if args.ip in r["host"]]

    # Orden cronológico
    records.sort(key=lambda x: x["epoch"])

    # Marcar coincidencias con epochs externas
    if epoch_candidates:
        for r in records:
            r["epoch_match"] = r["epoch"] in epoch_candidates

    # Mostrar solo el primero si se solicita
    if args.first and records:
        records = [records[0]]

    # Salida
    if args.json:
        print(json.dumps(records, indent=4))
    else:
        for r in records:
            print("\n----------------------------------------")
            print(f"Registro : {r['index']}")
            print(f"Usuario  : {r['user']}")
            print(f"IP       : {r['host']}")
            print(f"Epoch    : {r['epoch']}")
            print(f"UTC      : {r['utc']}")
            if "epoch_match" in r and r["epoch_match"]:
                print("MATCH    : Sí")


if __name__ == "__main__":
    main()


