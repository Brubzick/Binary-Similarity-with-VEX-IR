
def GetName(stmt_str):

    stmt_str = stmt_str.replace(',', ' ')
    stmt_str = stmt_str.replace('(', ' ')
    stmt_str = stmt_str.replace(')', ' ')

    variables = []
    stmt_str_list = stmt_str.split()

    for i in range(0, len(stmt_str_list)):
        if stmt_str_list[i][0] == 't':
            variables.append(stmt_str_list[i])
    
    return variables


def StrandNorm(strand, indexDict):

    for i in range(0, len(strand)):
        variables = GetName(strand[i])
        
        for name in variables:
            if (name not in indexDict):
                indexDict[name] = 't'+str(indexDict['max'])
                indexDict['max'] = indexDict['max'] + 1

            strand[i] = strand[i].replace(name, indexDict[name])
        
    return (strand, indexDict)
        


