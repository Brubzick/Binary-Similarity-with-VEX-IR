import angr
from get_strands import GetStrands 
from strand_normalization import TypeNorm
import hashlib

proj1 = angr.Project('./dfs', auto_load_libs = False)
proj2 = angr.Project('./bfs', auto_load_libs = False)

cfg1 = proj1.analyses.CFGFast(normalize=True)
cfg2 = proj2.analyses.CFGFast(normalize=True)

hashedStrandSet1 = set()
hashedStrandSet2 = set()

for node in cfg1.nodes():
    if (not node.is_simprocedure):

        strands = GetStrands(node)

        for i in range(0, len(strands)):
            for j in range(0, len(strands[i])):
                strands[i][j] = TypeNorm(strands[i][j])

        for strand in strands:
            md5 = hashlib.md5()
            for stmt_str in strand:
                md5.update(stmt_str.encode('utf-8'))
            hashed_strand = md5.hexdigest()
            hashedStrandSet1.add(hashed_strand)

for node in cfg2.nodes():
    
    if (not node.is_simprocedure):

        strands = GetStrands(node)

        for i in range(0, len(strands)):
            for j in range(0, len(strands[i])):
                strands[i][j] = TypeNorm(strands[i][j])

        for strand in strands:
            md5 = hashlib.md5()
            for stmt_str in strand:
                md5.update(stmt_str.encode('utf-8'))
            hashed_strand = md5.hexdigest()
            hashedStrandSet2.add(hashed_strand)

simSet = hashedStrandSet1.intersection(hashedStrandSet2)

sim = len(simSet)

print(sim, len(hashedStrandSet1), len(hashedStrandSet2))