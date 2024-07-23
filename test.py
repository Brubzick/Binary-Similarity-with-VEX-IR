import angr
from get_strands import GetStrands 
from strand_normalization import StrandNorm
import hashlib

proj1 = angr.Project('./dfs', auto_load_libs = False)
proj2 = angr.Project('./dfs2', auto_load_libs = False)

cfg1 = proj1.analyses.CFGFast(normalize=True)
cfg2 = proj2.analyses.CFGFast(normalize=True)

hashedStrandSet1 = set()
hashedStrandSet2 = set()
indexDict1 = {'max':0}
indexDict2 = {'max':0}

for node in cfg1.nodes():
    if (not node.is_simprocedure):

        strands = GetStrands(node)
        # indexDict1 = {'max':0}

        for i in range(0, len(strands)):
            strands[i], indexDict1 = StrandNorm(strands[i], indexDict1)

        for strand in strands:
            md5 = hashlib.md5()
            for stmt_str in strand:
                md5.update(stmt_str.encode('utf-8'))
            hashed_strand = md5.hexdigest()
            hashedStrandSet1.add(hashed_strand)

for node in cfg2.nodes():
    
    if (not node.is_simprocedure):

        strands = GetStrands(node)
        # indexDict2 = {'max':0}

        for i in range(0, len(strands)):
            strands[i], indexDict2 = StrandNorm(strands[i], indexDict2)

        for strand in strands:
            md5 = hashlib.md5()
            for stmt_str in strand:
                md5.update(stmt_str.encode('utf-8'))
            hashed_strand = md5.hexdigest()
            hashedStrandSet2.add(hashed_strand)

simSet = hashedStrandSet1.intersection(hashedStrandSet2)

sim = len(simSet)

print(sim, len(hashedStrandSet1), len(hashedStrandSet2))


