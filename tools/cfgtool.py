import angr
from angrutils import *
import sys

path = sys.argv[1]
proc = angr.Project(path, auto_load_libs = False)

cfg_fast = proc.analyses.CFGFast()
cfg_full = proc.analyses.CFGEmulated()

plot_cfg(cfg_full, "./process_cfg", asminst=True, remove_imports=True, remove_path_terminator=True)