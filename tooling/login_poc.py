"""Login-only PoC dialog: normal Ubisoft API login, never opens Connect."""
import sys
from pathlib import Path
import tkinter as tk

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'poc'))
from ubisoft_gui import UbisoftApp


class LoginOnly(UbisoftApp):
    def _build_main(self):
        # The normal login handler has saved only the issued session/remember-me
        # tickets. Destroy password widgets and terminate instead of exposing the
        # legacy GUI's Connect-dependent launch action.
        self.root.destroy()


if __name__ == '__main__':
    root = tk.Tk()
    app = LoginOnly(root)
    root.title('PoC independent login — no Connect client')
    root.mainloop()
