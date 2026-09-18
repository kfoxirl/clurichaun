from __future__ import annotations

import multiprocessing

from .cli import main

if __name__ == "__main__":
    multiprocessing.freeze_support()  # Windows / frozen builds
    main()
