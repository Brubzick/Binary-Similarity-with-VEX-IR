
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
        variables = GetName(str(strand[i]))
        
        for name in variables:
            if (name not in indexDict):
                indexDict[name] = 't'+str(indexDict['max'])
                indexDict['max'] = indexDict['max'] + 1

            strand[i] = str(strand[i]).replace(name, indexDict[name])
        
    return (strand, indexDict)
        

def TypeNorm(stmt):
    stmt_str = str(stmt)
    tag = stmt.tag
    norm = tag

    match tag:
        case 'Ist_Put':
            stmt_str_list = stmt_str.split()
            for i in range(0, len(stmt_str_list)):
                if stmt_str_list[i] == '=':
                    tmp = stmt_str_list[i+1]
                    break
            if tmp[0:2] == '0x':
                norm = 'Put.cons'
            else:
                norm = 'Put'  

        case 'Ist_PutI':
            stmt_str_list = stmt_str.split()
            for i in range(0, len(stmt_str_list)):
                if stmt_str_list[i] == '=':
                    tmp = stmt_str_list[i+1]
                    break
            if tmp[0:2] == '0x':
                norm = 'PutI.cons'
            else:
                norm = 'PutI'  

        case 'Ist_WrTmp':
            stmt_str_list = stmt_str.split()
            for i in range(0, len(stmt_str_list)):
                if stmt_str_list[i] == '=':
                    tmp = stmt_str_list[i+1]
                    break
            
            if tmp[0] == 't':
                norm = 'Copy'
            elif tmp[0:2] == '0x':
                norm = 'Constant'
            else:
                for i in range(0, len(tmp)):
                    if tmp[i] == '(':
                        tmp = tmp[:i]
                        break
                norm = tmp

        case 'Ist_Store':
            stmt_str_list = stmt_str.split()
            for i in range(0, len(stmt_str_list)):
                if stmt_str_list[i] == '=':
                    tmp = stmt_str_list[i+1]
                    break
            if tmp[0:2] == '0x':
                norm = 'STle.cons'
            else:
                norm = 'STle' 

        case 'Ist_Dirty':
            if (',' in stmt_str):
                norm = 'Dirty.cons'
            else:
                norm = 'Dirty'
    
    return norm


