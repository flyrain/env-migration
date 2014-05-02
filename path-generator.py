f = open("objects")

lines = f.readlines()

nodes = []

for i in reversed(range(0, len(lines))):
    line_array = lines[i].split()
    index = int(line_array[3])
    address = int(line_array[0], 16)
    size = int(line_array[1], 16)
    #print index, hex(address), hex(size)
    nodes.append([address, size])
    if index == 0:
        break

#for node in reversed(nodes):
#    print hex(node[0]), hex(node[1])


f_edges = open("mem_graph.dot")

edge_lines = f_edges.readlines()

for line in edge_lines:
    if not line.__contains__("box"):
        continue

    line_array = line.split()
    global_addr = line_array[0].split('"')[1]
    global_addr = int(global_addr, 16)

    print "%x" % global_addr

for line in edge_lines:
    #"823c2180" -> "8220c640" [label=896]
    if not line.__contains__("->"):
        continue

    line_array = line.split()
    #print line_array
    source = line_array[0].split('"')[1]
    target = line_array[2].split('"')[1]
    offset = line_array[3].split('=')[1].split(']')[0]
    source = int(source, 16)
    target = int(target, 16)
    offset = int(offset)

    target_size = 0
    for node in reversed(nodes):
        if node[0] == target:
            target_size = node[1]

    #print hex(source), hex(target), hex(offset), hex(target_size)
    print "%x+%x->%x:%x" % (source, offset, target, target_size)