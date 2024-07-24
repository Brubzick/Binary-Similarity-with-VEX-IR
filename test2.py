import angr
from get_strands import GetAllStrandsNorm
from hash import GetHashedStrands

proj1 = angr.Project('./dfs', auto_load_libs = False) # query gcc x86
proj2 = angr.Project('./dfs2', auto_load_libs = False) # target clang x86
proj3 = angr.Project('./dfs3', auto_load_libs = False) # target clang arm

cfg1 = proj1.analyses.CFGFast(normalize=True)
cfg2 = proj2.analyses.CFGFast(normalize=True)
cfg3 = proj3.analyses.CFGFast(normalize=True)

strands1 = GetAllStrandsNorm(cfg1)
strands2 = GetAllStrandsNorm(cfg2)
strands3 = GetAllStrandsNorm(cfg3)

hashedStrandList1 = GetHashedStrands(strands1)
hashedStrandList2 = GetHashedStrands(strands2)
hashedStrandList3 = GetHashedStrands(strands3)

simSet1 = set(hashedStrandList1).intersection(set(hashedStrandList2))
simSet2 = set(hashedStrandList1).intersection(set(hashedStrandList3))

simScore1 = 0
simScore2 = 0

for hashedStrand in simSet1:
    simScore1 += 2/(hashedStrandList2.count(hashedStrand) + hashedStrandList3.count(hashedStrand))

for hashedStrand in simSet2:
    simScore2 += 2/(hashedStrandList2.count(hashedStrand) + hashedStrandList3.count(hashedStrand))

print(simScore1)
print(simScore2)

# for node in cfg1.nodes():
#     if (not node.is_simprocedure):

#         strands = GetStrands(node)

#         for i in range(0, len(strands)):
#             for j in range(0, len(strands[i])):
#                 strands[i][j] = TypeNorm(strands[i][j])

#         for strand in strands:
#             md5 = hashlib.md5()
#             for stmt_str in strand:
#                 md5.update(stmt_str.encode('utf-8'))
#             hashed_strand = md5.hexdigest()
#             hashedStrandSet1.add(hashed_strand)

# for node in cfg2.nodes():
    
#     if (not node.is_simprocedure):

#         strands = GetStrands(node)

#         for i in range(0, len(strands)):
#             for j in range(0, len(strands[i])):
#                 strands[i][j] = TypeNorm(strands[i][j])

#         for strand in strands:
#             md5 = hashlib.md5()
#             for stmt_str in strand:
#                 md5.update(stmt_str.encode('utf-8'))
#             hashed_strand = md5.hexdigest()
#             hashedStrandSet2.add(hashed_strand)

# simSet = hashedStrandSet1.intersection(hashedStrandSet2)

# sim = len(simSet)

# print(sim, len(hashedStrandSet1), len(hashedStrandSet2))