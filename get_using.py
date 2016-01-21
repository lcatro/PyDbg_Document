'''
read_file_object=open('pydbg.py','rb')
write_file_object=open('output_using.txt','w')
get_function_discr=False

for read_line in read_file_object :
    if '    def'==read_line[:7] :
        write_file_object.write('\r\n'+read_line[4:])
    elif read_line.find('\'\'\'')!=-1 :
        if not get_function_discr :
            get_function_discr=True
            continue
        else :
            get_function_discr=False
            continue
            
    if get_function_discr and len(read_line.strip())!=0 :
        write_file_object.write(read_line.strip()+'\r\n')
'''

read_file_object=open('output_using.txt','rb')
write_file_object=open('output_using.md','w')

for read_line in read_file_object :
    read_line=read_line.strip()
    if 'def'==read_line[:3] :
        write_file_object.write('###'+read_line+'\r\n')
    elif len(read_line)==0 :
        write_file_object.write('---\r\n')
    elif '@see'==read_line[:4] :
        continue
    elif '@raise'==read_line[:6] :
        write_file_object.write('**Raise Exception:'+read_line[7:]+'**\r\n')
    elif '@type'==read_line[:5] :
        write_file_object.write('`'+read_line[7:]+'`:\r\n')
    elif '@param'==read_line[:6] :
        write_file_object.write('&nbsp;&nbsp;&nbsp;&nbsp;'+read_line[7:]+'\r\n')
    elif '@rtype'==read_line[:6] :
        write_file_object.write('`return: '+read_line[9:]+'`\r\n')
    elif '@return'==read_line[:7] :
        write_file_object.write('&nbsp;&nbsp;&nbsp;&nbsp;'+read_line[9:]+'\r\n')
    else :
        write_file_object.write('**'+read_line+'**\r\n')
