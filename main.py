import sys
from transfer_p2p import cli_main
from gui_p2p import run_gui

def main():
    if len(sys.argv) == 1:
        run_gui()
    elif sys.argv[1].lower() == "gui":
        run_gui()
    else:
        cli_main()

if __name__ == "__main__":
    main()
