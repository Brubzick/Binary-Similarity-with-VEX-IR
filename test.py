import angr
from get_strands import GetStrands 
from strand_normalization import StrandNorm

proj = angr.Project('./dfs', auto_load_libs = False)

cfg = proj.analyses.CFGFast(normalize=True)

node = list(cfg.nodes())[0]

strands = GetStrands(node)

indexDict = {'max':0}

for i in range(0, len(strands)):
    strands[i], indexDict = StrandNorm(strands[i], indexDict)


print(strands)
node.block.vex.pp()

