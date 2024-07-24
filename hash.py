import hashlib

def GetHashedStrands(strands):
    hashedStrandList = []
    for strand in strands:
        md5 = hashlib.md5()
        for stmt_str in strand:
            md5.update(stmt_str.encode('utf-8'))
        hashedStrand =  md5.hexdigest()
        hashedStrandList.append(hashedStrand)

    return hashedStrandList