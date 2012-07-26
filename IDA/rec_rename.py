## This script helps with renaming functions
## See the following link for more info
## Created by alexander.hanel@gmail.com
## Ref: http://hooked-on-mnemonics.blogspot.de/2012/07/renaming-subroutine-blocks-and.html

from idaapi import * 
import idautils
import idc
import sys
imports_list = []

# The following two functions are used to get the import API names.
# ret_list_of_imports() returns the api names in a list
def imp_cb(ea, name, ord):
    global imports_list 
    if not name:
        pass 
    else:
        imports_list.append(name)
    return True

def ret_list_of_imports():
    global imports_list 
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0,nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            pass 
        idaapi.enum_import_names(i, imp_cb)

    return imports_list


def graph_down(ea, graph = {}, path = set([])):
    # This function was borrowed from Carlos G. Prado. Check out his Milf-Plugin for IDA on Google Code. 
    graph[ea] = list()    # Create a new entry on the graph dictionary {node: [child1, child2, ...], ...}
    path.add(ea)        # This is a set, therefore the add() method

    # Iterate through all function instructions and take only call instructions
    for x in [x for x in FuncItems(ea) if is_call_insn(x)]:        # Take the call elements
            for xref in XrefsFrom(x, XREF_FAR):                                   
                    if not xref.iscode:
                            continue
                                    
                    if xref.to not in path:        # Eliminates recursions
                            graph[ea].append(xref.to)
                            graph_down(xref.to, graph, path)
    return path

def main():
    # Get function name as input.
    func_name = LocByName(AskStr("sub_0xxxxx", "Enter Function Name"))

    if func_name == 0xffffffff:
        Warning("[ERROR] Bad Function Name [ERROR]")
        return

    tag = AskStr("string", "Function Tag")  
    if tag == None:
        Warning("[ERROR] Tag cannot be None [ERROR]")
        return

    list_imports = ret_list_of_imports()
    # graph down needs the address of the function passed. 
    nodes_xref_down = graph_down(func_name,graph = {}, path = set([]))
    # graph_down returns the int address needs to be converted 
    tmp  = []
    tmp1 = ''
    for func in nodes_xref_down:
        tmp1 = GetFunctionName(func)
        if tmp1 != '':
            tmp.append(tmp1)
    nodes_xref_down = tmp

    # Remove the APIs from the xref list 
    for xx in set(list_imports).intersection(set(nodes_xref_down)):
        nodes_xref_down.remove(xx)

    for rename in nodes_xref_down:
        func_addr =  LocByName(rename)
        if tag not in rename:
            MakeNameEx(func_addr, str(tag) + str('_') + rename, SN_NOWARN) 
 
 =============================================================================
 
 sub_blocks.py - subroutine-blocks finder - Download
 
 if __name__ == "__main__":
    main()
## This script will find subroutine-blocks using IDA
## See the following link for more info
## Created by alexander.hanel@gmail.com

from idaapi import * 
import idautils
import idc
import operator
import sys
imports_list = []

sys.setrecursionlimit(2000)

# Get every function name. Returns the function names in a list. This is basically
# the output from the "Function name" Tab/Window 
def get_func_names():
    func_name_list = []
    for x in idautils.Functions(): func_name_list.append(GetFunctionName(x))
    return func_name_list

# The following two functions are used to get the import API names.
# ret_list_of_imports() returns the api names in a list
def imp_cb(ea, name, ord):
    global imports_list 
    if not name:
        pass 
    else:
        imports_list.append(name)
    return True

# 2nd function as described above
def ret_list_of_imports():
    global imports_list 
    nimps = idaapi.get_import_module_qty()
    for i in xrange(0,nimps):
        name = idaapi.get_import_module_name(i)
        if not name:
            pass 
        idaapi.enum_import_names(i, imp_cb)

    return imports_list

# Returns a set of of calls that are found xrefed from
def graph_down(ea, graph = {}, path = set([])):
    # This function was borrowed from Carlos G. Prado. Check out his Milf-Plugin for IDA on Google Code. 
    graph[ea] = list()    # Create a new entry on the graph dictionary {node: [child1, child2, ...], ...}
    path.add(ea)        # This is a set, therefore the add() method

    # Iterate through all function instructions and take only call instructions
    for x in [x for x in FuncItems(ea) if is_call_insn(x)]:        # Take the call elements
            for xref in XrefsFrom(x, XREF_FAR):                                   
                    if not xref.iscode:
                            continue
                                    
                    if xref.to not in path:        # Eliminates recursions
                            graph[ea].append(xref.to)
                            graph_down(xref.to, graph, path)
    return path

def get_nodes(func_name, list_imports):
    threshold = set([])
    # Create list of each node in the xref from
    nodes_xref_down = graph_down(LocByName(func_name),graph = {}, path = set([]))
    # graph_down returns the int address needs to be converted 
    tmp  = []
    tmp1 = ''
    for func in nodes_xref_down:
        tmp1 = GetFunctionName(func)
        if tmp1 != '':
            tmp.append(tmp1)
    nodes_xref_down = tmp
    # Do not want the parent function xrefs to, just the child functions
    nodes_xref_down.remove(func_name)

    # Remove the APIs from the xref list 
    for xx in set(list_imports).intersection(set(nodes_xref_down)):
        nodes_xref_down.remove(xx)

    for nodes in nodes_xref_down:
        # Get all code xrefs to 
        ref_addr = CodeRefsTo(LocByName(nodes),0)

        # For each code xrefs to is not in nodes 
        for func_ref in ref_addr:
            # if func is not in all nodes 
            if GetFunctionName(func_ref) not in nodes_xref_down and GetFunctionName(func_ref) != func_name:
                threshold.add(GetFunctionName(func_ref))
                if len(threshold) == 3:
                    return
    ret = []   
    if len(threshold) < 3 and len(threshold) != 0:
        ret.append(func_name)
        ret.append(len(nodes_xref_down))
        for each in threshold:
            if each == '':
                ret.append('Unknown Function Address')
            else:
                ret.append(each)
    return ret

def sortByColumn(bigList, *args):
    bigList.sort(key=operator.itemgetter(*args))
    # Uncomment and comment above if sort from high to low, rather high to low
    #bigList.sort(key=operator.itemgetter(*args), reverse = True) # sorts the list in place

def main():
    data_o = []
    k = ''
    # List of all import APIs
    list_imports = ret_list_of_imports()
    # List of all function names
    list_func_names = get_func_names()

    # Some API names will be labeled functions by IDA. The below for loop
    # deletes all intersections that reside in both lists. 
    for intersection_function_name in set(list_imports).intersection(set(list_func_names)):
         list_func_names.remove(intersection_function_name)

    # For each func_name in set
    for func_name in list_func_names:
        k = get_nodes(func_name,list_imports)
        if k != None and k != []:
            data_o.append(k)
            
    # Sort by number of child nodes
    sortByColumn(data_o,1)

    for results in data_o:
        print 'Subroutine-Block: %s' % results[0]
        print '\tChild Nodes: %s' % results[1]
        if len(results) >= 3:
            print '\tThreshold Function: %s' %  results[2]
                
        if len(results) == 4:
            print '\tThreshold Function: %s' %  results[3]

    print 'Completed'


if __name__ == "__main__":
    main()