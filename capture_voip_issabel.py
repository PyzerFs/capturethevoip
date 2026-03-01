#!/usr/bin/env python3
import subprocess
import shutil
import sys
import pathlib
import datetime
import argparse


def check_tshark():
    """
    Verifica se o tshark (Wireshark CLI) está instalado no sistema.
    """
    if shutil.which("tshark") is None:
        print("ERRO: tshark não encontrado no sistema.")
        print("Instale com: sudo apt install tshark")
        sys.exit(1)


def get_timestamp():
    """
    Retorna data e hora formatadas para nome de arquivo.
    """
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def run_capture(interface, output_dir, show_stats):
    """
    Executa a captura de pacotes SIP e RTP usando tshark.
    """
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Filtro padrão Issabel/Asterisk
    capture_filter = "(udp port 5060 or udp portrange 10000-20000)"

    filename = f"issabel_capture_{get_timestamp()}_%F.pcapng"
    output_path = pathlib.Path(output_dir) / filename

    tshark_command = [
        "tshark",
        "-i", interface,
        "-f", capture_filter,
        "-w", str(output_path),
        "-a", "duration:300",
        "-b", "files:5",
        "-b", "filesize:50",
        "-p"
    ]

    print("[+] Iniciando captura...")
    print("[+] Interface:", interface)
    print("[+] Filtro:", capture_filter)
    print("[+] Salvando em:", output_dir)

    try:
        subprocess.call(tshark_command)
    except KeyboardInterrupt:
        print("\n[!] Captura interrompida pelo usuário.")

    if show_stats:
        show_statistics(output_dir)


def show_statistics(output_dir):
    """
    Exibe estatísticas básicas SIP e RTP do último arquivo capturado.
    """
    files = sorted(pathlib.Path(output_dir).glob("*.pcapng"))

    if not files:
        print("Nenhum arquivo encontrado para estatísticas.")
        return

    last_file = str(files[-1])

    print("\n[+] Estatísticas do arquivo:", last_file)

    print("\n--- Hierarquia de protocolos ---")
    subprocess.call(["tshark", "-r", last_file, "-q", "-z", "io,phs"])

    print("\n--- Métodos SIP ---")
    subprocess.call(["tshark", "-r", last_file, "-Y", "sip", "-T", "fields", "-e", "sip.Method"])

    print("\n--- Fluxos RTP ---")
    subprocess.call(["tshark", "-r", last_file, "-q", "-z", "rtp,streams"])


def main():
    """
    Função principal.
    """
    parser = argparse.ArgumentParser(description="Captura VoIP Issabel/Asterisk (SIP + RTP)")
    parser.add_argument("-i", "--iface", required=True, help="Interface de rede (ex: eth0)")
    parser.add_argument("-o", "--out", default="capturas", help="Diretório de saída")
    parser.add_argument("--stats", action="store_true", help="Exibir estatísticas ao final")

    args = parser.parse_args()

    check_tshark()
    run_capture(args.iface, args.out, args.stats)


if __name__ == "__main__":
    main()
    